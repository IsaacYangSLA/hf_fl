# Frozen interoperability fixtures

These expected values were recorded from the former Python manager before its
server implementation was removed. They are independent of the Go implementation
and preserve the existing client and retained-data contracts: canonical JSON and
hashes, Unicode, deterministic floating-point patterns, normalized/defaulted job
specifications, invalid specifications, and confined artifact locators.

Go tests consume the frozen JSON without Python or a reference server. The fixture
records the historical source revision and module hashes. Do not regenerate
expected results from the implementation being tested. Any intentional contract
change requires separately reviewed expected cases and compatibility analysis.
The historical source remains available in Git for provenance.
