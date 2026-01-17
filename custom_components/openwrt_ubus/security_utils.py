"""Security utilities for handling sensitive data."""

from __future__ import annotations

import logging
from typing import Any, Dict
import re

_LOGGER = logging.getLogger(__name__)

# Sensitive keys that should be redacted in logs
SENSITIVE_KEYS = {
    "password",
    "passwd",
    "session",
    "token",
    "key",
    "secret",
    "auth",
    "credential",
    "private_key",
    "certificate"
}


def redact_sensitive_data(data: Any, replace_with: str = "***REDACTED***") -> Any:
    """Redact sensitive information from data structures for logging.

    Args:
        data: The data to sanitize (can be dict, list, string, or any type)
        replace_with: String to replace sensitive values with

    Returns:
        Sanitized data with sensitive information redacted
    """
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Check if key contains sensitive information
            if isinstance(key, str) and any(
                sensitive_word in key.lower()
                for sensitive_word in SENSITIVE_KEYS
            ):
                sanitized[key] = replace_with
            else:
                sanitized[key] = redact_sensitive_data(value, replace_with)
        return sanitized

    elif isinstance(data, list):
        return [redact_sensitive_data(item, replace_with) for item in data]

    elif isinstance(data, tuple):
        return tuple(redact_sensitive_data(item, replace_with) for item in data)

    # For strings, check for potential sensitive information patterns
    elif isinstance(data, str):
        # Basic pattern detection for potential sensitive data
        if _looks_like_sensitive(data):
            return replace_with
        return data

    # For other types, return as-is
    return data


def _looks_like_sensitive(text: str) -> bool:
    """Check if text looks like sensitive information."""
    # Basic heuristics for detecting sensitive data patterns
    text_lower = text.lower()

    # Check for session-like patterns (alphanumeric strings of certain lengths)
    if re.match(r'^[a-f0-9]{16,}$', text_lower):
        return True

    # Check for base64-like patterns
    if re.match(r'^[a-zA-Z0-9+/]{20,}={0,2}$', text):
        return True

    # Check for API key patterns
    if re.match(r'^[a-zA-Z0-9_-]{20,}$', text):
        return True

    return False


def safe_log_data(data: Any, level: str = "debug", extra_context: str = "") -> None:
    """Safely log data with sensitive information redacted.

    Args:
        data: Data to log
        level: Log level ('debug', 'info', 'warning', 'error')
        extra_context: Additional context to include in log message
    """
    sanitized_data = redact_sensitive_data(data)

    message = "Data log"
    if extra_context:
        message = f"{message} ({extra_context})"

    log_func = getattr(_LOGGER, level)
    log_func("%s: %s", message, sanitized_data)


class CredentialManager:
    """Manages credentials securely."""

    def __init__(self, host: str, username: str, password: str):
        """Initialize credential manager.

        Args:
            host: OpenWrt device host
            username: Username for authentication
            password: Password for authentication
        """
        self.host = host
        self.username = username
        self._password = password  # Keep internal
        self._session_id = None

    @property
    def password(self) -> str:
        """Get password for internal use only."""
        return self._password

    @property
    def session_id(self) -> str | None:
        """Get current session ID."""
        return self._session_id

    @session_id.setter
    def session_id(self, value: str | None) -> None:
        """Set session ID."""
        self._session_id = value

    def get_connection_info(self) -> Dict[str, Any]:
        """Get connection info with sensitive data redacted for logging.

        Returns:
            Dictionary with connection info, passwords redacted
        """
        return {
            "host": self.host,
            "username": self.username,
            "password": "***REDACTED***",
            "has_session": self._session_id is not None
        }

    def __str__(self) -> str:
        """String representation with sensitive data redacted."""
        return f"CredentialManager(host={self.host}, username={self.username})"
