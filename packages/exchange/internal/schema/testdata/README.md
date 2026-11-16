# Frozen schema and text-pattern fixtures

The JSON expected results in this directory were recorded independently from the
former Python server before that implementation was removed. Native Go tests use
them to preserve existing validation behavior; no Python server is required.

Their Python version fields describe historical provenance, not an installed
service dependency. Preserve these expected results when refactoring. Intentional
validation changes require independently reviewed cases and compatibility
analysis, rather than regenerating answers from the implementation under test.
The historical generators remain available through Git history.
