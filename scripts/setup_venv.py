#!/usr/bin/env python3
"""Create a checked HF²L virtual environment without replacing existing files."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import venv


_MINIMUM = (3, 14, 0, "final", 0)
_UPPER_BOUND = (3, 16)
_PROBE = """
import json
from pathlib import Path
import sys
import sysconfig

prefix = Path(sys.prefix).resolve()
pip_main = Path(sysconfig.get_path("purelib")) / "pip" / "__main__.py"
print(json.dumps({
    "version": list(sys.version_info),
    "prefix": str(prefix),
    "base_prefix": str(Path(sys.base_prefix).resolve()),
    "has_pip": pip_main.is_file() and pip_main.resolve().is_relative_to(prefix),
}))
"""


def _supported(version):
    return _MINIMUM <= tuple(version) < _UPPER_BOUND


def _existing_error(directory, reason):
    return ValueError(
        f"{directory}: {reason}. Deactivate any active environment, then move this "
        "directory aside as a backup and run setup again, or choose a fresh path."
    )


def _check_environment(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise _existing_error(directory, "expected an environment directory, not a file or symbolic link")
    config = directory / "pyvenv.cfg"
    python = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if config.is_symlink() or not config.is_file() or not python.is_file():
        raise _existing_error(directory, "missing a usable virtual environment")
    try:
        result = subprocess.run(
            [str(python), "-I", "-B", "-S", "-c", _PROBE],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        info = json.loads(result.stdout)
        version = tuple(info["version"])
        if len(version) != 5:
            raise ValueError("Unexpected interpreter version")
        supported = _supported(version)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        raise _existing_error(directory, "could not verify the environment's Python") from exc

    actual = ".".join(str(part) for part in version[:3])
    if not supported:
        raise _existing_error(directory, f"Python {actual} is unsupported (requires Python 3.14 or 3.15)")
    if version[:2] != sys.version_info[:2]:
        requested = f"{sys.version_info.major}.{sys.version_info.minor}"
        raise _existing_error(directory, f"Python {actual} does not match the requested Python {requested}")
    if info["prefix"] != str(directory.resolve()) or info["prefix"] == info["base_prefix"]:
        raise _existing_error(directory, "the interpreter does not identify this directory as its environment")
    if not info["has_pip"]:
        raise _existing_error(directory, "the environment does not contain pip")
    return python


def setup(directory):
    """Return the path of a checked Python executable in a new or existing environment."""
    if not _supported(sys.version_info):
        raise ValueError(
            f"HF²L setup requires Python 3.14 or 3.15 (running {sys.version.split()[0]}). "
            "Run this script with python3.14 or python3.15."
        )
    directory = Path(directory).absolute()
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        return _check_environment(directory)

    try:
        venv.create(directory, with_pip=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _existing_error(
            directory, "environment setup failed; check that this Python provides venv and pip"
        ) from exc
    return _check_environment(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Environment directory, for example .venv")
    args = parser.parse_args(argv)
    try:
        python = setup(args.directory)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Setup failed: {exc}\n")
    print(f"Ready: {python}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
