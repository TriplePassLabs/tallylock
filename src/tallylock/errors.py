"""Shared exceptions for TallyLock's public interfaces."""

from __future__ import annotations


class TallyLockError(Exception):
    """An expected validation failure from a TallyLock primitive."""

    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
