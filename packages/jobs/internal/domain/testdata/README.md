# Python interoperability fixtures

These expected values come from the existing Python manager's domain and
principal-ID contracts, independently of the Go implementation. They cover
canonical JSON and hashes, Unicode, 1,000 deterministic floating-point bit
patterns, normalized/defaulted job specifications, invalid specifications, and
confined artifact locators.

Go tests consume the frozen JSON and need no Python installation. To regenerate
it from the checked-out reference, install the Python manager's development
dependencies and run from the repository root:

```sh
python packages/jobs/internal/domain/testdata/generate.py
```

The fixture records the source commit and SHA-256 of both reference modules.
Review changed expected values against both implementations.
