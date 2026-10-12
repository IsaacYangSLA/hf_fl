"""JSON equality must not accept boolean algorithm parameters as numbers."""

from __future__ import annotations

import unittest

from hf2l.core.json_values import json_values_equal


class JsonValuesEqualTests(unittest.TestCase):
    def test_boolean_parameters_differ_from_numbers_at_every_depth(self):
        for first, second in [(True, 1), (True, 1.0), (False, 0), (False, 0.0)]:
            for wrap in [lambda item: item,
                         lambda item: {"enabled": item},
                         lambda item: {"nested": [{"enabled": item}]}]:
                with self.subTest(first=first, second=second, wrap=wrap):
                    self.assertFalse(json_values_equal(wrap(first), wrap(second)))
                    self.assertFalse(json_values_equal(wrap(second), wrap(first)))

    def test_json_scalar_values_compare_by_type_and_value(self):
        for value in [None, True, False, "value", "", 3, 1.25]:
            with self.subTest(value=value):
                self.assertTrue(json_values_equal(value, value))
        for first, second in [(None, False), (True, False), ("1", 1),
                              ("true", True), ("first", "second"), (1, 2), (1, 1.1)]:
            with self.subTest(first=first, second=second):
                self.assertFalse(json_values_equal(first, second))

    def test_integer_float_parameters_share_json_number_semantics(self):
        self.assertTrue(json_values_equal(1, 1.0))
        self.assertTrue(json_values_equal(-0.0, 0))
        self.assertTrue(json_values_equal({"nested": [1, -2.0]}, {"nested": [1.0, -2]}))
        integer = 2**53 + 1
        self.assertFalse(json_values_equal(integer, float(integer)))

    def test_objects_ignore_key_order_and_require_matching_keys(self):
        first = {"scale": 1, "nested": {"enabled": True, "rate": 0.5}}
        second = {"nested": {"rate": 0.5, "enabled": True}, "scale": 1.0}
        self.assertTrue(json_values_equal(first, second))
        self.assertFalse(json_values_equal({"first": 1}, {"second": 1}))
        self.assertFalse(json_values_equal(first, {**second, "extra": None}))

    def test_arrays_preserve_order_and_length(self):
        self.assertTrue(json_values_equal([], []))
        self.assertFalse(json_values_equal([1, 2], [2, 1]))
        self.assertFalse(json_values_equal([1], [1, 2]))
        self.assertFalse(json_values_equal([], {}))

    def test_non_json_values_and_non_string_keys_are_rejected(self):
        for value in [(1, 2), {1, 2}, object(), b"value", {1: "value"}]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "JSON"):
                    json_values_equal(value, None)
                with self.assertRaisesRegex(ValueError, "JSON"):
                    json_values_equal(None, value)

    def test_nonfinite_numbers_are_rejected(self):
        for value in [float("nan"), float("inf"), -float("inf")]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "finite"):
                json_values_equal({"nested": [value]}, {"nested": [value]})

    def test_invalid_values_are_rejected_even_in_unequal_branches(self):
        for first, second in [({"one": 1, "bad": object()}, {"two": 2}),
                              ([], [float("nan")]),
                              (None, {"bad": (1,)})]:
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                json_values_equal(first, second)

    def test_circular_containers_are_rejected(self):
        circular_list = []
        circular_list.append(circular_list)
        circular_dict = {}
        circular_dict["self"] = circular_dict
        for value in [circular_list, circular_dict]:
            with self.subTest(value_type=type(value)), self.assertRaisesRegex(ValueError, "circular"):
                json_values_equal(value, None)

    def test_shared_containers_are_valid_and_not_changed(self):
        shared = {"rate": 1.0}
        value = [shared, shared]
        self.assertTrue(json_values_equal(value, [{"rate": 1}, {"rate": 1}]))
        self.assertEqual(value, [{"rate": 1.0}, {"rate": 1.0}])
        self.assertIs(value[0], shared)
        self.assertIs(value[1], shared)


if __name__ == "__main__":
    unittest.main()
