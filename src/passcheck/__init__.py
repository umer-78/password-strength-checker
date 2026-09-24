"""Offline password strength analysis."""

from .analyzer import Report, analyze
from .generate import generate_password

__all__ = ["Report", "analyze", "generate_password"]
__version__ = "1.0.0"
