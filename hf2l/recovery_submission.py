"""Read-only reconciliation of a completed participant's saved publication."""
from dataclasses import asdict
from pathlib import Path

from hf2l.client_steps import upload_client_update


def reconcile_saved_submission(store, work_dir, participant, metadata):
    """Find the exact previously accepted result, or return None when unpublished."""
    if not callable(getattr(store, "reconcile_submission", None)):
        raise ValueError("The configured store cannot reconcile saved submissions")
    work_dir = Path(work_dir)
    trained_dir = work_dir / "trained_model"
    if trained_dir.is_symlink():
        raise ValueError("Saved training output must not be a symlink")
    result, _ = upload_client_update(
        store, work_dir, trained_dir, participant,
        metadata["num_examples"], metadata["training"], _reconcile_only=True,
    )
    return asdict(result) if result is not None else None
