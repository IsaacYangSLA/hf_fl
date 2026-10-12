"""Separate trusted plugin diagnostics from command and library results."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout
import sys


@contextmanager
def plugin_stdout_to_stderr() -> Iterator[None]:
    """Redirect Python plugin stdout and restore it even when the plugin raises.

    This changes the process-wide stream, so callers must not run unrelated
    stdout-producing work concurrently within this context.
    """
    with redirect_stdout(sys.stderr):
        yield
