"""Run the sandboxed Python training/build adapter, never a manager server."""
from .runtime import main

raise SystemExit(main())
