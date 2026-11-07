"""Dispatch ``python -m tallylock`` through the installed command interface."""
from .cli import main

raise SystemExit(main())
