"""Bounded, deliberately incomplete V9 ingestion foundation."""

from .limits import Limits
from .supervisor import ingest

__all__ = ["Limits", "ingest"]
