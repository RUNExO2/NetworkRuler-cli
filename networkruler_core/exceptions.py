class NetworkRulerError(Exception):
    """Base exception for NetworkRuler v2."""


class UnsupportedPlatformError(NetworkRulerError):
    """Raised when an operation is unavailable on the current platform."""


class SafetyCheckError(NetworkRulerError):
    """Raised when an operation fails a required safety check."""

