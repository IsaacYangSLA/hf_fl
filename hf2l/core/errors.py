"""Errors shared by FL protocol consumers."""


class ProtocolError(ValueError):
    """A document violates the FL wire contract before contextual validation."""
