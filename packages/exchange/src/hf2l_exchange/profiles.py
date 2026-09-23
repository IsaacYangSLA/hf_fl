"""Trusted optional application constraints; no database or ML dependencies.

Application commands invoke these constraints *in addition to* core authorization,
immutability, and fencing. Profiles cannot weaken core checks. The registry is
static: space metadata cannot cause modules or user-supplied code to be loaded.
"""
from dataclasses import dataclass
from .domain import Error


def _metadata(record):
    return record.get("metadata", record.get("metadata_json", {}))


def _bindings(record):
    return record.get("creator_bindings", record.get("attribution", {}))


@dataclass(frozen=True)
class Profile:
    name: str

    def policy_defaults(self, kind):
        return {"publish_roles": ["contributor", "publisher"], "visibility": "shared"}

    def validate_policy(self, kind, roles, visibility):
        return None

    def validate_bindings(self, bindings, other_bindings):
        return None

    def record_base_id(self, kind, metadata):
        return None

    def validate_publish(self, kind, metadata, record_bindings, current_bindings):
        return None

    def selection_spec(self, reference_name, base_id):
        return None

    def input_eligible(self, record, member):
        return True

    def validate_input_current(self, record, member):
        return None

    def completion_inputs(self, result, frozen, reference_name="main"):
        return list(frozen)

    def validate_type(self, kind, schema):
        return None

    def validate_record(self, kind, metadata, creator_bindings):
        return None

    def validate_reference(self, name, record, inputs=(), base_record_id=None):
        return None

    def select_inputs(self, records, base_record_id):
        return list(records)


@dataclass(frozen=True)
class FedAvgProfile(Profile):
    minimum_participants: int = 2

    def policy_defaults(self, kind):
        if kind == "training.update":
            return {"publish_roles": ["contributor"], "visibility": "private"}
        if kind == "model.global":
            return {"publish_roles": ["publisher"], "visibility": "shared"}
        return super().policy_defaults(kind)

    def validate_policy(self, kind, roles, visibility):
        if kind == "model.global" and (set(roles) != {"publisher"} or visibility != "shared"):
            raise Error(422, "profile_policy_conflict")
        if kind == "training.update" and set(roles) != {"contributor"}:
            raise Error(422, "profile_policy_conflict")

    def validate_bindings(self, bindings, other_bindings):
        participant = bindings.get("participant")
        if participant is None:
            return
        if not isinstance(participant, str) or not participant or len(participant) > 128:
            raise Error(422, "invalid_participant")
        if any(other.get("participant") == participant for other in other_bindings):
            raise Error(409, "participant_already_bound")

    def record_base_id(self, kind, metadata):
        return metadata.get("base_record_id") if kind in {"training.update", "model.global"} else None

    def validate_publish(self, kind, metadata, record_bindings, current_bindings):
        self.validate_record(kind, metadata, record_bindings)
        if kind == "training.update" and record_bindings != current_bindings:
            raise Error(409, "participant_binding_changed")

    def selection_spec(self, reference_name, base_id):
        if reference_name == "main":
            return {"kind": "training.update", "base_id": base_id, "minimum": self.minimum_participants,
                    "minimum_error": "insufficient_participants"}
        return None

    def input_eligible(self, record, member):
        if record.get("kind") != "training.update":
            return True
        return (member is not None and "contributor" in member.get("roles", [])
                and member.get("bindings", {}) == _bindings(record))

    def validate_input_current(self, record, member):
        if not self.input_eligible(record, member):
            raise Error(409, "input_participant_revoked")

    def completion_inputs(self, result, frozen, reference_name="main"):
        if reference_name != "main":
            return list(frozen)
        declared = _metadata(result).get("inputs", [])
        if not isinstance(declared, list) or any(not isinstance(item, str) for item in declared):
            raise Error(409, "invalid_result_inputs")
        if len(declared) != len(set(declared)):
            raise Error(409, "invalid_result_inputs")
        by_id = {record["id"]: record for record in frozen}
        if not set(declared).issubset(by_id):
            raise Error(409, "result_provenance_mismatch")
        used = [by_id[rid] for rid in declared]
        participants = {_bindings(record).get("participant") for record in used}
        if len(used) < self.minimum_participants or len(participants) != len(used) or None in participants:
            raise Error(409, "insufficient_participants")
        return used

    def validate_type(self, kind, schema):
        if kind not in {"training.update", "model.global"}:
            return
        # Composed root schemas can constrain compulsory profile fields indirectly.
        # A deliberately small shape makes compatibility inspectable; constraints
        # for application-specific properties still use ordinary JSON Schema.
        annotations = {"title", "description", "$comment", "examples", "default"}
        if set(schema) - ({"$schema", "type", "properties", "required", "additionalProperties"} | annotations):
            raise Error(422, "profile_schema_conflict")
        if not isinstance(schema.get("additionalProperties", True), bool):
            raise Error(422, "profile_schema_conflict")
        expected = ({"base_record_id": "string", "sample_count": "integer"}
                    if kind == "training.update" else {"inputs": "array", "base_record_id": "string"})
        properties = schema.get("properties", {})
        for field, expected_type in expected.items():
            if field in properties:
                spec = properties[field]
                if not isinstance(spec, dict) or spec.get("type") != expected_type or set(spec) - ({"type"} | annotations):
                    raise Error(422, "profile_schema_conflict", field)
            elif schema.get("additionalProperties") is False:
                raise Error(422, "profile_schema_conflict", field)

    def validate_record(self, kind, metadata, creator_bindings):
        if kind == "training.update":
            participant = creator_bindings.get("participant")
            if not isinstance(participant, str) or not participant or len(participant) > 128:
                raise Error(422, "participant_binding_required")
            if not isinstance(metadata.get("base_record_id"), str) or not metadata["base_record_id"]:
                raise Error(422, "round_base_required")
            count = metadata.get("sample_count")
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                raise Error(422, "invalid_sample_count")
            if "participant" in metadata:
                raise Error(422, "participant_is_server_attributed")
        elif kind == "model.global":
            inputs = metadata.get("inputs", [])
            if not isinstance(inputs, list) or any(not isinstance(value, str) or not value for value in inputs):
                raise Error(422, "invalid_result_inputs")
            if len(inputs) != len(set(inputs)):
                raise Error(422, "invalid_result_inputs")
            if metadata.get("base_record_id") is not None and not isinstance(metadata["base_record_id"], str):
                raise Error(422, "invalid_round_base")

    def validate_reference(self, name, record, inputs=(), base_record_id=None):
        if name != "main":
            return
        if record.get("kind") != "model.global":
            raise Error(422, "profile_reference_kind")
        metadata = _metadata(record)
        if base_record_id is None:
            if metadata.get("base_record_id") is not None or metadata.get("inputs", []):
                raise Error(409, "initial_model_has_provenance")
            return
        if not inputs:
            raise Error(409, "coordination_required")
        if len(inputs) < self.minimum_participants:
            raise Error(409, "insufficient_participants")
        participants = set()
        for item in inputs:
            participant = _bindings(item).get("participant")
            if (item.get("kind") != "training.update" or _metadata(item).get("base_record_id") != base_record_id
                    or not isinstance(participant, str) or not participant or participant in participants):
                raise Error(409, "invalid_round_inputs")
            participants.add(participant)
        expected = {item["id"] for item in inputs}
        if metadata.get("base_record_id") != base_record_id or set(metadata.get("inputs", [])) != expected:
            raise Error(409, "result_provenance_mismatch")

    def select_inputs(self, records, base_record_id):
        selected = {}
        for record in records:
            if record.get("state", "published") != "published" or record.get("kind") != "training.update":
                continue
            if _metadata(record).get("base_record_id") != base_record_id:
                continue
            participant = _bindings(record).get("participant")
            if not isinstance(participant, str) or not participant:
                continue
            previous = selected.get(participant)
            key = (record.get("published_at") or 0, record["id"])
            if previous is None or key > ((previous.get("published_at") or 0), previous["id"]):
                selected[participant] = record
        return [selected[name] for name in sorted(selected)]


_PROFILES = {"generic.v1": Profile("generic.v1"), "fedavg.v1": FedAvgProfile("fedavg.v1")}


def get_profile(name):
    try:
        return _PROFILES[name]
    except (KeyError, TypeError):
        raise Error(422, "unknown_profile") from None


def profile_names():
    return tuple(_PROFILES)
