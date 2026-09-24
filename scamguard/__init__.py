"""ScamGuard: scam detection for Uzbek, Russian and English messages."""

from .analyzer import analyze, Verdict

__all__ = ["analyze", "Verdict"]
__version__ = "0.1.0"
