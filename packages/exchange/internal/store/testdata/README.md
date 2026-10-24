# Exchange persistence oracles

These are reference compatibility fixtures for the independent Go Exchange.
No native production service invokes Python.

- The parent schema.json contains the frozen Python migration baseline plus all
  SQLAlchemy client defaults and column kinds.
- export_schema.py checks that manifest against the reference source. Use its
  --write option only when reviewing a compatible schema/default update;
  published migration revisions remain immutable.
- orm_inputs.json exercises every one of the 15 application tables.
- orm_null_inputs.json additionally exercises explicit scalar None defaults,
  JSON null/string values and an automatically assigned event ID.
- schema_oracle.py creates or reads retained state with the actual reference ORM.
  SQLite and PostgreSQL fixtures use only owned disposable state.

Set HF2L_EXCHANGE_TEST_PYTHON to an interpreter with the reference Exchange server
dependencies. Set HF2L_EXCHANGE_TEST_DATABASE_URL to a disposable PostgreSQL
database to enable actual PostgreSQL gates. Each PostgreSQL test creates and
removes its own UUID-named schema. Ordinary store.Open, startup and readiness
checks never initialize a database.

Canonical JSON and principal fixtures live under internal/domain/testdata.
They preserve Python ASCII-versus-UTF8 encoding, float spelling, Unicode and
large integer behavior.
