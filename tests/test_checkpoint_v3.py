"""Immutable WP0 numeric oracles and framework-neutral checkpoint contracts."""
from __future__ import annotations

import hashlib
import json
import platform
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import numpy as np
from safetensors.numpy import load_file, save_file

from hf2l.checkpoint.aggregate import aggregate_shards, average, validate_coefficients
from hf2l.checkpoint.format import FORMATS, FormatSpec, discover, get_ops
from hf2l.checkpoint.layout import CheckpointLayout, CompatibilityPolicy, TensorSpec
from hf2l.checkpoint.safetensors import MAX_HEADER_BYTES, read_header
from hf2l.checkpoint.safetensors_numpy import Ops as NumpyOps

GOLDENS = Path(__file__).parent / "goldens"


class HeaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "config.json").write_text('{"width": 1}', encoding="utf-8")

    def raw(self, header, data=b"\x00\x00\x80\x3f"):
        value = header if isinstance(header, bytes) else json.dumps(header).encode()
        (self.root / "model.safetensors").write_bytes(struct.pack("<Q", len(value)) + value + data)

    def test_valid_scalar_empty_and_header_only_discovery(self):
        save_file({"scalar": np.array(1, np.float32), "empty": np.array([], np.float32)}, self.root / "model.safetensors")
        layout = discover(self.root)
        self.assertEqual((), layout.tensors["scalar"].shape)
        self.assertEqual((0,), layout.tensors["empty"].shape)
        code = '''
import importlib.abc, sys
from pathlib import Path
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, *args):
        if fullname.split('.')[0] in {'torch', 'numpy', 'safetensors', 'huggingface_hub', 'fastapi', 'pydantic'}:
            raise ImportError('blocked ' + fullname)
sys.meta_path.insert(0, Block())
from hf2l.checkpoint.format import discover
from hf2l.checkpoint_utils import discover_checkpoint
assert discover(Path(sys.argv[1])).tensors == discover_checkpoint(Path(sys.argv[1])).tensors
'''
        subprocess.run([sys.executable, "-c", code, str(self.root)], check=True, capture_output=True, text=True)

    def test_corrupt_headers_offsets_and_truncation_rejected(self):
        valid = {"x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
        cases = [
            ({"x": {"dtype": "F32", "shape": [1], "data_offsets": [1, 5]}}, b"12345"),
            ({"x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 3]}}, b"123"),
            ({"x": {"dtype": "F32", "shape": [True], "data_offsets": [0, 4]}}, b"1234"),
            ({"x": {"dtype": "F32", "shape": [-1], "data_offsets": [0, 4]}}, b"1234"),
            ({"x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
              "y": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}, b"1234"),
            ({"x": {"dtype": "unknown", "shape": [1], "data_offsets": [0, 4]}}, b"1234"),
            ({**valid, "__metadata__": {"bad": 42}}, b"1234"),
            (valid, b"123"), (valid, b"12345"),
            (b'{"x":{},"x":{}}', b""), (b"[]", b""), (b'{"x": NaN}', b""),
        ]
        for header, payload in cases:
            with self.subTest(header=header, payload=payload):
                self.raw(header, payload)
                with self.assertRaises(ValueError):
                    discover(self.root)
        for value in (b"short", struct.pack("<Q", MAX_HEADER_BYTES + 1), struct.pack("<Q", 100) + b"{}"):
            (self.root / "model.safetensors").write_bytes(value)
            with self.assertRaises(ValueError):
                discover(self.root)

    def test_all_header_strings_and_numbers_conform_to_reader_json(self):
        spec = {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}
        invalid = [
            {"x": spec, "__metadata__": {"format": "\ud800"}},
            {"x": spec, "__metadata__": {"\udfff": "value"}},
            {"\ud800": spec},
            {"x": {**spec, "extra": {"nested": ["\ud800"]}}},
            {"x": {**spec, "extra": 10**400}},
            b'{"x":{"dtype":"F32","shape":[1],"data_offsets":[0,4],"extra":1e999}}',
        ]
        nested = 1
        for _ in range(126):
            nested = [nested]
        invalid.append({"x": {**spec, "extra": nested}})
        for header in invalid:
            with self.subTest(header=header):
                self.raw(header)
                with self.assertRaisesRegex(ValueError, "Invalid SafeTensors JSON header"):
                    discover(self.root)
        # A properly paired escaped surrogate is one valid Unicode scalar.
        self.raw({"x": spec, "__metadata__": {"format": "\U0001f600"}})
        self.assertIn("x", discover(self.root).tensors)

    def test_empty_axes_cannot_hide_buffer_size_overflow(self):
        for shape in ([2**62, 8, 0], [0, 2**62, 8], [0, 2**62]):
            with self.subTest(shape=shape):
                self.raw({"x": {"dtype": "F32", "shape": shape, "data_offsets": [0, 0]}}, b"")
                with self.assertRaisesRegex(ValueError, "overflows supported buffer size"):
                    discover(self.root)
        # Ordinary empty tensors remain valid independently of axis order.
        for shape in ([0, 8], [8, 0], [2, 0, 8]):
            self.raw({"x": {"dtype": "F32", "shape": shape, "data_offsets": [0, 0]}}, b"")
            self.assertEqual(tuple(shape), discover(self.root).tensors["x"].shape)

    def test_index_paths_keys_and_symlinks(self):
        save_file({"x": np.array([1], np.float32)}, self.root / "part.safetensors")
        index = self.root / "model.safetensors.index.json"
        for name in ("../part.safetensors", "/part.safetensors", "a\\part.safetensors", "./part.safetensors", "C:part.safetensors", "bad\n.safetensors"):
            index.write_text(json.dumps({"weight_map": {"x": name}}))
            with self.assertRaises(ValueError):
                discover(self.root)
        index.write_text(json.dumps({"weight_map": {"other": "part.safetensors"}}))
        with self.assertRaisesRegex(ValueError, "Index/tensor keys differ"):
            discover(self.root)
        index.write_text(json.dumps({"weight_map": {"x": "missing.safetensors"}}))
        with self.assertRaisesRegex(ValueError, "missing"):
            discover(self.root)
        index.write_text(json.dumps({"weight_map": {"x": "link.safetensors"}}))
        (self.root / "link.safetensors").symlink_to(self.root / "part.safetensors")
        with self.assertRaisesRegex(ValueError, "symlink"):
            discover(self.root)
        index.write_text(json.dumps({"weight_map": {"x": "part.safetensors"}}))
        self.assertEqual(("part.safetensors",), discover(self.root).weight_files)

    def test_duplicate_tensor_across_shards_rejected(self):
        for name in ("a.safetensors", "b.safetensors"):
            save_file({"x": np.array([1], np.float32)}, self.root / name)
        (self.root / "model.safetensors.index.json").write_text(json.dumps({"weight_map": {"x": "a.safetensors", "y": "b.safetensors"}}))
        with self.assertRaisesRegex(ValueError, "more than one"):
            discover(self.root)

    def test_format_registration_and_compatibility_policy(self):
        layout = CheckpointLayout(self.root, {"width": 1, "description": "a"}, ("weights.custom",), None,
                                  {"x": TensorSpec("weights.custom", (1,), "F32")}, "custom")
        FORMATS["custom"] = FormatSpec(lambda path: path == self.root, lambda path: layout, ())
        try:
            self.assertEqual(layout, discover(self.root))
            self.assertEqual(layout, discover(self.root, format_name="custom"))
        finally:
            del FORMATS["custom"]
        other = replace(layout, config={"width": 1, "description": "b"})
        with self.assertRaisesRegex(ValueError, "configuration"):
            CompatibilityPolicy().check(layout, other)
        CompatibilityPolicy(("width",)).check(layout, other)
        with self.assertRaisesRegex(ValueError, "format"):
            CompatibilityPolicy(("width",)).check(layout, replace(other, format="different"))


class GoldenTests(unittest.TestCase):
    def test_torch_matches_frozen_goldens(self):
        try:
            import torch
        except ImportError:
            self.skipTest("Torch extra not installed")
        from hf2l.checkpoint_utils import aggregate_checkpoints
        for fixture in sorted(GOLDENS.iterdir()):
            with self.subTest(fixture=fixture.name), tempfile.TemporaryDirectory() as temp:
                meta = json.loads((fixture / "meta.json").read_text())
                layouts = [discover(fixture / "clients" / str(i)) for i in range(3)]
                output = aggregate_checkpoints(layouts[0], layouts, meta["coefficients"], Path(temp) / "output")
                matches_cpu = (meta["cpu_capability"] == torch.backends.cpu.get_cpu_capability()
                               and meta["platform_machine"] == platform.machine())
                for filename in output.weight_files:
                    actual = load_file(output.root / filename)
                    expected = load_file(fixture / "expected" / filename)
                    for name, value in actual.items():
                        if matches_cpu or not np.issubdtype(value.dtype, np.floating):
                            self.assertEqual(meta["tensor_sha256"][name], hashlib.sha256(value.tobytes()).hexdigest())
                        else:
                            operands = [load_file(layout.root / filename)[name] for layout in layouts]
                            acc = np.float64 if value.dtype == np.float64 else np.float32
                            bound = 2 * np.finfo(acc).eps * sum(abs(c) for c in meta["coefficients"]) * max(float(np.abs(x).max()) for x in operands)
                            ulp = np.abs(np.spacing(expected[name])).astype(np.float64)
                            self.assertTrue(np.all(np.abs(value.astype(np.float64)-expected[name].astype(np.float64)) <= np.maximum(ulp, bound)))

    def test_numpy_within_operand_scaled_bound_and_reference(self):
        np_ops = NumpyOps()
        try:
            from hf2l.checkpoint.safetensors_torch import Ops as TorchOps
            torch_ops = TorchOps()
        except ImportError:
            torch_ops = None
        for fixture in sorted(GOLDENS.iterdir()):
            meta = json.loads((fixture / "meta.json").read_text())
            coeffs = meta["coefficients"]
            layouts = [discover(fixture / "clients" / str(i)) for i in range(3)]
            with tempfile.TemporaryDirectory() as temp:
                output = aggregate_shards(layouts[0], layouts, coeffs, Path(temp) / "output")
                for filename in output.weight_files:
                    inputs = [load_file(layout.root / filename) for layout in layouts]
                    actual = load_file(output.root / filename)
                    expected = load_file(fixture / "expected" / filename)
                    for name, result in actual.items():
                        with self.subTest(fixture=fixture.name, name=name):
                            operands = [mapping[name] for mapping in inputs]
                            if not np.issubdtype(result.dtype, np.floating):
                                np.testing.assert_array_equal(result, expected[name])
                                continue
                            dtype = np.float64 if result.dtype == np.float64 else np.float32
                            bound = 2 * np.finfo(dtype).eps * sum(abs(c) for c in coeffs) * max(float(np.abs(x).max()) for x in operands)
                            acc = average(operands[0], operands, coeffs, ops=np_ops, name=name, cast_back=False)
                            truth = sum(c * x.astype(np.float64) for c, x in zip(coeffs, operands, strict=True))
                            self.assertTrue(np.all(np.abs(acc.astype(np.float64) - truth) <= bound))
                            if torch_ops is not None:
                                import torch
                                tensors = [torch.from_numpy(x.copy()) for x in operands]
                                tacc = average(tensors[0], tensors, coeffs, ops=torch_ops, name=name, cast_back=False).numpy()
                                self.assertTrue(np.all(np.abs(acc.astype(np.float64) - tacc.astype(np.float64)) <= bound))
                                self.assertTrue(np.all(np.abs(tacc.astype(np.float64) - truth) <= bound))
                            ulp = np.abs(np.spacing(expected[name])).astype(np.float64)
                            self.assertTrue(np.all(np.abs(result.astype(np.float64)-expected[name].astype(np.float64)) <= np.maximum(ulp, bound)))

    def test_shards_stream_and_close_on_success_and_failure(self):
        class RecordingOps(NumpyOps):
            def __init__(self):
                self.active = 0
                self.high_water = 0
                self.opened = []
                self.fail = False
            @contextmanager
            def open_shard(self, path):
                with super().open_shard(path) as shard:
                    self.opened.append(path)
                    self.active += 1
                    self.high_water = max(self.high_water, self.active)
                    try:
                        yield shard
                    finally:
                        self.active -= 1
            def write_shard(self, *args):
                if self.fail:
                    raise RuntimeError("injected write failure")
                return super().write_shard(*args)
        fixture = GOLDENS / "sharded"
        layouts = [discover(fixture / "clients" / str(i)) for i in range(3)]
        base = discover(fixture / "expected")
        ops = RecordingOps()
        with tempfile.TemporaryDirectory() as temp:
            aggregate_shards(base, layouts, [.2, .3, .5], Path(temp) / "good", ops=ops)
            self.assertEqual(0, ops.active)
            self.assertEqual(4, ops.high_water)
            self.assertEqual(8, len(ops.opened))
            self.assertEqual(8, len(set(ops.opened)))
            ops.fail = True
            with self.assertRaisesRegex(RuntimeError, "injected"):
                aggregate_shards(base, layouts, [.2, .3, .5], Path(temp) / "bad", ops=ops)
            self.assertEqual(0, ops.active)


class AveragingTests(unittest.TestCase):
    def test_nonfloat_policy_checks_base_not_just_clients(self):
        with self.assertRaisesRegex(ValueError, "Non-floating"):
            average(np.array([1]), [np.array([2]), np.array([2])], [.5, .5], name="count", ops=NumpyOps())

    def test_nonfinite_inputs_rejected_even_zero_weight_and_overflow(self):
        ops = NumpyOps()
        for invalid in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "Input tensor"):
                average(np.array([1.], np.float32), [np.array([invalid], np.float32), np.array([1.], np.float32)],
                        [0., 1.], name="x", ops=ops)
        with self.assertRaisesRegex(ValueError, "Aggregated tensor"):
            # Tiny sum tolerance still permits coefficients that overflow max F32.
            maximum = np.array([np.finfo(np.float32).max], np.float32)
            class OverflowOps(NumpyOps):
                def add_scaled(self, accumulator, array, coefficient):
                    accumulator[:] = np.inf
            average(maximum, [maximum], [1.], name="x", ops=OverflowOps())

    def test_float64_promotes_and_coefficients_are_validated(self):
        x = np.array([1 + 2**-40], np.float64)
        result = average(x, [x], [1.], name="x", ops=NumpyOps())
        np.testing.assert_array_equal(x, result)
        for coefficients, count in (([], 0), ([1], 2), ([float("nan")], 1), ([-1, 2], 2), ([.2], 1)):
            with self.subTest(coefficients=coefficients), self.assertRaises(ValueError):
                validate_coefficients(coefficients, count)

    def test_bfloat16_backend_error_is_actionable(self):
        layout = CheckpointLayout(Path("."), {}, ("model.safetensors",), None,
                                  {"x": TensorSpec("model.safetensors", (1,), "BF16")})
        with self.assertRaisesRegex(ValueError, r"BF16.*hf2l\[torch\]"):
            get_ops(layout, prefer="numpy")
        try:
            import torch
        except ImportError:
            return
        from hf2l.checkpoint.safetensors_torch import Ops
        value = torch.tensor([2., 4.], dtype=torch.bfloat16)
        result = average(value, [value], [1.], name="bf16", ops=Ops())
        self.assertTrue(torch.equal(value, result))

    def test_generic_copy_exclusions_and_output_safety(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "base"
            root.mkdir()
            (root / "config.json").write_text("{}")
            (root / "notes.json").write_text('{"hello": "world"}')
            (root / "private").mkdir()
            (root / "private" / "state").write_text("secret")
            save_file({"x": np.array([1], np.float32)}, root / "model.safetensors")
            layout = discover(root)
            output = aggregate_shards(layout, [layout], [1.], Path(temp) / "output", exclude=("private",))
            self.assertTrue((output.root / "notes.json").is_file())
            self.assertFalse((output.root / "private").exists())
            with self.assertRaisesRegex(ValueError, "outside"):
                aggregate_shards(layout, [layout], [1.], root / "nested")


if __name__ == "__main__":
    unittest.main()
