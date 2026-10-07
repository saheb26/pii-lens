"""Highlight high-risk personal data in text."""

from pii_lens.detector import Finding, detect

__all__ = ["Finding", "detect", "__version__"]

__version__ = "0.1.0"
