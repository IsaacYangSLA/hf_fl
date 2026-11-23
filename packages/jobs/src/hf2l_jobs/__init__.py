"""Sandboxed Python training/build adapters; server services are implemented in Go."""

import sys


if sys.version_info < (3, 14, 0, "final", 0) or sys.version_info >= (3, 16):
    raise RuntimeError(
        "The HF²L job runtime requires Python 3.14 or 3.15. "
        f"Running Python {sys.version.split()[0]}. "
        "Create and use a virtual environment with a supported Python version."
    )


__version__ = "0.1.0.dev0"
