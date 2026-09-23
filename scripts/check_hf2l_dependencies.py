"""Check HF2L source boundaries and its deliberately minimal installed runtime.

The ``core`` mode must run in a clean environment installed from the HF2L wheel
without extras. It verifies absence of optional stacks, checkpoint discovery,
NumPy aggregation, local storage and every core command's help entry point.
"""
from __future__ import annotations

import argparse
import ast
import importlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


OPTIONAL_MODULES = {
    "torch", "huggingface_hub", "httpx", "hf2l_exchange", "fastapi",
    "sqlalchemy", "boto3", "jwt", "jsonschema",
}
FRAMEWORK_MODULES = OPTIONAL_MODULES | {"numpy", "safetensors"}


def check_source(root: Path) -> list[str]:
    """Protocol, filesystem primitives and discovery must remain stdlib only."""
    package = root / "hf2l"
    paths = [*sorted((package / "core").rglob("*.py")),
             *sorted((package / "common").rglob("*.py")),
             package / "checkpoint/layout.py", package / "checkpoint/safetensors.py"]
    problems = []
    for path in paths:
        if not path.is_file():
            problems.append(f"Missing framework-neutral source: {path}")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            imports = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                       else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            for name in imports:
                if name.split(".", 1)[0] in FRAMEWORK_MODULES:
                    problems.append(f"{path.relative_to(root)}:{node.lineno}: prohibited import {name}")
                if name.startswith(("hf2l.backends", "hf2l.exchange", "hf2l.round", "hf2l.cli")):
                    problems.append(f"{path.relative_to(root)}:{node.lineno}: reversed dependency {name}")
    return problems


def _installed_requirements() -> list[str]:
    dependencies = []
    for requirement in importlib.metadata.requires("hf2l") or []:
        if ";" not in requirement:
            match = re.match(r"[A-Za-z0-9_.-]+", requirement)
            if match:
                dependencies.append(match.group(0).lower().replace("_", "-"))
    return sorted(dependencies)


def _command_help() -> None:
    entrypoints = [entry for entry in importlib.metadata.distribution("hf2l").entry_points
                   if entry.group == "console_scripts" and entry.name != "hf2l-exchange-service"]
    if not any(entry.name == "hf2l" for entry in entrypoints):
        raise AssertionError("Unified hf2l console entry point is missing")
    # Spawn each actual installed entry point independently: import caching cannot
    # conceal an eager optional dependency in another command's startup path.
    for entry in entrypoints:
        source = (
            "import importlib.metadata, sys; "
            f"sys.argv = [{entry.name!r}, '--help']; "
            "entries = importlib.metadata.distribution('hf2l').entry_points; "
            f"raise SystemExit(next(e for e in entries if e.group == 'console_scripts' and e.name == {entry.name!r}).load()())"
        )
        result = subprocess.run([sys.executable, "-I", "-c", source], capture_output=True, text=True, timeout=30)
        if result.returncode != 0 or "usage:" not in result.stdout:
            raise AssertionError(f"{entry.name} --help failed:\n{result.stdout}{result.stderr}")


def _checkpoint_smoke() -> None:
    import numpy as np
    from safetensors.numpy import save_file, load_file
    from hf2l.checkpoint.safetensors import discover
    from hf2l.checkpoint_utils import aggregate_checkpoints
    from hf2l.backends.factory import make_store

    with tempfile.TemporaryDirectory(prefix="hf2l-core-check-") as temporary:
        root = Path(temporary)
        layouts = []
        for name, value in (("base", 0.0), ("alice", 1.0), ("bob", 3.0)):
            folder = root / name
            folder.mkdir()
            (folder / "config.json").write_text(json.dumps({"model_type": "numpy-smoke"}), encoding="utf-8")
            save_file({"weight": np.array([value], dtype=np.float32)}, str(folder / "model.safetensors"))
            layouts.append(discover(folder))
        result = aggregate_checkpoints(layouts[0], layouts[1:], [0.25, 0.75], root / "result",
                                       array_backend="numpy", accumulator_dtype="float64")
        np.testing.assert_array_equal(load_file(str(result.root / "model.safetensors"))["weight"],
                                      np.array([2.5], dtype=np.float32))
        with make_store("local", endpoint=str(root / "store"), principal="owner") as store:
            revision = store.initialize_repository("minimal-core", result.root, private=False).revision
            store.download_snapshot("minimal-core", revision, root / "download")
            downloaded = discover(root / "download")
            if downloaded.tensors != result.tensors:
                raise AssertionError("Local store changed checkpoint tensor metadata")


def check_installation() -> list[str]:
    problems = []
    dependencies = _installed_requirements()
    if dependencies != ["numpy", "safetensors"]:
        problems.append(f"Core dependencies must be [numpy, safetensors], got {dependencies}")
    for module in sorted(OPTIONAL_MODULES):
        if importlib.util.find_spec(module) is not None:
            problems.append(f"Minimal core environment unexpectedly contains {module}")
    if problems:
        return problems
    for module in ("hf2l", "hf2l.core.ports", "hf2l.core.protocol", "hf2l.common.fs",
                   "hf2l.checkpoint.safetensors", "hf2l.backends.factory", "hf2l.backends.local",
                   "hf2l.round.config", "hf2l.cli"):
        importlib.import_module(module)
    _checkpoint_smoke()
    _command_help()
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("source", "core"), default="source")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    problems = check_source(args.root)
    if args.mode == "core":
        problems.extend(check_installation())
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"HF2L {args.mode} dependency boundaries passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
