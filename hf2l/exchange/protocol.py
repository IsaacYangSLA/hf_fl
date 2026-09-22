"""Wire-level constants shared by the service, the SDK and the FedAvg adapter; standard library only."""
import json

from hf2l.hub_helpers import ROUND_FILE, SUBMISSION_FILE

# Serialized size limit of one record's metadata, enforced by the service and pre-checked by the SDK.
METADATA_LIMIT_BYTES = 65536
# Metadata key under which the adapter stores small HF2L manifests instead of uploading them as attachments.
INLINE_FILES_KEY = "hf2l_files"
# Manifest names that are always materialised from metadata; no attachment may take or shadow them.
INLINE_MANIFEST_NAMES = (ROUND_FILE, SUBMISSION_FILE)


def metadata_size(value):
    """Serialized size the service measures; NaN and infinity are rejected like any other invalid JSON."""
    return len(json.dumps(value, allow_nan=False).encode())


def names_collide(first, second):
    """Whether two relative names denote one file on a case-insensitive filesystem or nest as file and directory."""
    first, second = first.casefold(), second.casefold()
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")
