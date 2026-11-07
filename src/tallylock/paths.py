"""Shared portable namespace rules with separate wire and storage bounds."""
from __future__ import annotations

import unicodedata

from . import canonical
from .errors import TallyLockError


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TallyLockError(message)


def validate_path(path: str, *, limit: int = 1024) -> str:
    """Preserve exact NFC spelling while rejecting ambiguous components."""
    _require(isinstance(path, str), "artifact path must be a string")
    canonical.dumps(path)
    _require(bool(path) and not path.startswith("/") and "\\" not in path,
             f"invalid artifact path: {path!r}")
    _require(unicodedata.normalize("NFC", path) == path,
             f"artifact path is not NFC: {path!r}")
    _require(not any(unicodedata.category(char) == "Cc" for char in path),
             f"control character in artifact path: {path!r}")
    _require(len(path.encode("utf-8")) <= limit, f"artifact path exceeds {limit} bytes: {path!r}")
    for component in path.split("/"):
        _require(component not in ("", ".", "..") and not component.endswith((".", " "))
                 and ":" not in component, f"invalid artifact component in {path!r}")
        _require(len(component.encode("utf-8")) <= 255,
                 f"artifact component exceeds 255 bytes in {path!r}")
    return path


def validate_paths(paths, *, limit: int = 1024, directories=()) -> None:
    """Reject aliases and file/directory collisions throughout the namespace."""
    _require(isinstance(paths, (list, tuple, dict)), "inventory paths must be a collection")
    prefixes: dict[str, tuple[str, bool]] = {}
    entries = [(path, False) for path in directories] + [(path, True) for path in paths]
    for path, file_entry in entries:
        validate_path(path, limit=limit)
        parts = path.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            folded = unicodedata.normalize("NFC", prefix.casefold())
            is_file = file_entry and index == len(parts)
            prior = prefixes.get(folded)
            if prior is not None:
                _require(prior[0] == prefix and not prior[1] and not is_file,
                         f"artifact path collision: {prior[0]!r} and {prefix!r}")
            else:
                prefixes[folded] = (prefix, is_file)
