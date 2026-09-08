"""HF²L: Hugging Face Federated Learning."""

from importlib.metadata import PackageNotFoundError, version


try:
    __version__ = version("hf2l")
except PackageNotFoundError:
    __version__ = "0+unknown"
