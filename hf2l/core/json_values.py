"""Equality for JSON values without Python's boolean/number coercion."""

from __future__ import annotations

import math
from typing import Any


def _validate_json(value: Any, containers: set[int]) -> None:
    value_type = type(value)
    if value is None or value_type in (str, bool, int):
        return
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return
    if value_type not in (dict, list):
        raise ValueError(f"Value of type {value_type.__name__} is not JSON compatible")
    if id(value) in containers:
        raise ValueError("JSON values must not contain circular references")
    containers.add(id(value))
    try:
        if value_type is dict:
            if any(type(key) is not str for key in value):
                raise ValueError("JSON object keys must be strings")
            children = value.values()
        else:
            children = value
        for child in children:
            _validate_json(child, containers)
    finally:
        containers.remove(id(value))


def _equal(left: Any, right: Any) -> bool:
    left_type, right_type = type(left), type(right)
    if left_type in (int, float) and right_type in (int, float):
        return left == right
    if left_type is not right_type:
        return False
    if left_type is dict:
        return left.keys() == right.keys() and all(
            _equal(left[key], right[key]) for key in left
        )
    if left_type is list:
        return len(left) == len(right) and all(
            _equal(first, second) for first, second in zip(left, right)
        )
    return left == right


def json_values_equal(left: Any, right: Any) -> bool:
    """Compare JSON values recursively, keeping booleans distinct from numbers.

    Object key order is ignored; array order is preserved. Integers and finite
    floats compare by their numeric value, so ``1`` and ``1.0`` match. Both
    operands must contain only standard JSON scalar types, dictionaries with
    string keys, and lists. Invalid values raise ``ValueError``, even when they
    occur in a branch that would otherwise make the operands unequal.

    Document size, numeric range, Unicode, and depth limits belong to the wire
    protocol's validation and are not imposed by this equality helper.
    """
    try:
        _validate_json(left, set())
        _validate_json(right, set())
        return _equal(left, right)
    except RecursionError as exc:
        raise ValueError("JSON values exceed the supported recursion depth") from exc
