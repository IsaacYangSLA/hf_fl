"""HF²L: Hugging Face Federated Learning."""

from importlib.metadata import PackageNotFoundError, version
import sys


if sys.version_info < (3, 14, 0, "final", 0) or sys.version_info >= (3, 16):
    raise RuntimeError(
        "HF²L requires Python 3.14 or 3.15. "
        f"Running Python {sys.version.split()[0]}. "
        "Create and use a virtual environment with a supported Python version."
    )


try:
    __version__ = version("hf2l")
except PackageNotFoundError:
    __version__ = "0+unknown"
