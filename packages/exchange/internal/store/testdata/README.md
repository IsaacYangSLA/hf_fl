# Exchange retained-state fixtures

These immutable data fixtures preserve the historical persistence contract without
requiring the removed Python server or its dependencies during Go tests.

- The parent `schema.json` freezes migration SQL, column kinds, nullability and
  client defaults. `TestFrozenSchemaAndDefaultManifest` pins its reviewed hash;
  changing a published revision requires migration review. The manifest explicitly
  retains the historical nonempty publication-role default; the old exporter
  incorrectly flattened every callable list default to an empty list. Immutable
  baseline migration SQL is unchanged.
- `orm_inputs.json` exercises all 15 application tables.
- `orm_null_inputs.json` includes explicit scalar null defaults, JSON null/string
  values and an automatically assigned event identifier.
- `orm_expected.json` and `orm_null_expected.json` contain independently frozen
  historical row values. Current-time defaults are omitted and checked separately
  for valid values and exact preservation across a native close/reopen.
- `orm_retained_sqlite.json` and `orm_null_retained_sqlite.json` contain ordered SQL
  statements from historical retained databases. Native tests restore them into
  fresh disposable databases, reopen and verify every application row.

The expected rows and retained databases were frozen from source revision
`e5b9dc52be155f281cac6ec8cb41d20a8c25e8cb`, using its original Python persistence
mappings with SQLAlchemy 2.1.8. The executable generator was removed with the
reference server; generated data is retained for compatibility checks.

Set `HF2L_EXCHANGE_TEST_DATABASE_URL` to a disposable PostgreSQL database to enable
that backend's native gates. Each test creates and removes its own namespace.
SQLite retained-state and default tests run without external services. Normal
service startup and readiness checks do not initialize a database.

Canonical document and account-identity fixtures live under
`internal/domain/testdata`; they preserve historical encodings, number spelling,
Unicode and large integer behavior.
