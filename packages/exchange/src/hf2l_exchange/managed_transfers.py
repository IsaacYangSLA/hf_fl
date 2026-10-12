"""Public managed descriptors, with raw signed transfers retained for trusted gateways.

This adapter never invokes origin URL signing for managed grant or download
responses. The trusted gateway keeps its separate raw TransferService instance.
"""
from .domain import ExchangeError
from .models import database_time
from .storage import StorageFailure, part_size_for

MANAGED_PROTOCOL = "hf2l-managed-v1"


class ManagedTransferService:
    def __init__(self, transfers):
        self.raw = transfers
        self.service = transfers.service

    def __getattr__(self, name):
        return getattr(self.raw, name)

    @staticmethod
    def _operation(space_id, record_id, attachment_id, method, number=None):
        operation = {"space_id": space_id, "record_id": record_id,
                     "attachment_id": attachment_id, "method": method}
        if number is not None:
            operation["part_number"] = number
        return {"protocol": MANAGED_PROTOCOL, "operation": operation, "headers": {}}

    def initiate(self, space_id, record_id, attachment_id, principal):
        response = self.raw.initiate(space_id, record_id, attachment_id, principal)
        if self.service.is_managed_space(space_id):
            response = {**response, "protocol": MANAGED_PROTOCOL}
        return response

    def complete(self, space_id, record_id, attachment_id, principal):
        response = self.raw.complete(space_id, record_id, attachment_id, principal)
        if self.service.is_managed_space(space_id):
            response = {**response, "protocol": MANAGED_PROTOCOL}
        return response

    def grants(self, space_id, record_id, attachment_id, principal, numbers):
        if not self.service.is_managed_space(space_id):
            return self.raw.grants(space_id, record_id, attachment_id, principal, numbers)
        if (not numbers or len(numbers) > 100 or
                any(type(number) is not int for number in numbers) or len(set(numbers)) != len(numbers)):
            raise ExchangeError(422, "invalid_part_numbers")
        with self.service.transaction(space_id, principal, write=False) as (session, _, member):
            record, blob = self.raw._attachment(session, space_id, record_id, attachment_id, member, principal, True)
            attempt = self.raw._active(session, blob)
            if (record.state != "draft" or record.expires_at <= database_time(session) or
                    not attempt or attempt.state != "uploading"):
                raise ExchangeError(409, "upload_not_ready")
            try:
                sizes = [part_size_for(number, blob.size, blob.part_size) for number in numbers]
            except StorageFailure as exc:
                raise ExchangeError(422, "invalid_part_numbers") from exc
        return {"grants": [{**self._operation(space_id, record_id, attachment_id, "PUT", number),
                             "number": number, "size": size} for number, size in zip(numbers, sizes)]}

    def download(self, space_id, record_id, attachment_id, principal):
        if not self.service.is_managed_space(space_id):
            return self.raw.download(space_id, record_id, attachment_id, principal)
        with self.service.transaction(space_id, principal, write=False) as (session, _, member):
            record, blob = self.raw._attachment(session, space_id, record_id, attachment_id, member, principal)
            if record.state != "published" or blob.state != "verified":
                raise ExchangeError(409, "attachment_not_available")
            size, digest = blob.verified_size, blob.verified_sha256
        return {**self._operation(space_id, record_id, attachment_id, "GET"),
                "size": size, "sha256": digest}
