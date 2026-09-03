#!/usr/bin/env python3
"""Load explicitly trusted, local model/training plugins."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable


PLUGIN_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def parse_plugin_args(values: list[str] | None) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for value in values or []:
        if "=" not in value:
            raise ValueError(f"Plugin argument must be KEY=VALUE: {value!r}")
        key, raw = value.split("=", 1)
        if not PLUGIN_KEY.fullmatch(key):
            raise ValueError(f"Invalid plugin argument name: {key!r}")
        if key in options:
            raise ValueError(f"Duplicate plugin argument: {key}")
        try:
            options[key] = json.loads(raw)
        except json.JSONDecodeError:
            options[key] = raw
    return options


def load_local_plugin(path: Path) -> ModuleType:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"Plugin file does not exist: {resolved}")
    module_name = f"hf_fedavg_plugin_{abs(hash(resolved))}"
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load plugin: {resolved}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    plugin_directory = str(resolved.parent)
    if plugin_directory not in sys.path:
        sys.path.insert(0, plugin_directory)
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


def require_callable(plugin: ModuleType, name: str) -> Callable[..., Any]:
    value = getattr(plugin, name, None)
    if not callable(value):
        raise ValueError(f"Plugin must define callable {name}(...)")
    return value
