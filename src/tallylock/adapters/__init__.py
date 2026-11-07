"""Adapters that bring other tools' records into TallyLock, and TallyLock records out."""
from .inspect_log import import_inspect
from .intoto import to_intoto
from .proofbundle import verify_proofbundle

__all__ = ["import_inspect", "to_intoto", "verify_proofbundle"]
