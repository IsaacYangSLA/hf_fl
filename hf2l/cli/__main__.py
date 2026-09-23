"""Allow ``python -m hf2l.cli`` as well as the ``hf2l`` console script."""

from hf2l.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
