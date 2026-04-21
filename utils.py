"""Utility helpers for password analysis."""

import math
from typing import Dict


def is_valid_password(password: str) -> bool:
    """Return False for empty or whitespace-only inputs."""
    return bool(password and password.strip())


def _normalized_for_entropy(password: str) -> str:
    """Remove whitespace characters from entropy-related calculations."""
    return "".join(ch for ch in password if not ch.isspace())


def detect_character_sets(password: str) -> Dict[str, bool]:
    """Return which character groups are present in the password."""
    normalized = _normalized_for_entropy(password)
    return {
        "lowercase": any(ch.islower() for ch in normalized),
        "uppercase": any(ch.isupper() for ch in normalized),
        "digits": any(ch.isdigit() for ch in normalized),
        "symbols": any(not ch.isalnum() for ch in normalized),
    }


def calculate_charset_size(password: str) -> int:
    """
    Estimate effective character set size based on detected groups.

    Groups:
    - lowercase letters: 26
    - uppercase letters: 26
    - digits: 10
    - symbols: 32 (common printable symbol estimate)
    """
    if not is_valid_password(password):
        return 0

    sets = detect_character_sets(password)
    size = 0

    if sets["lowercase"]:
        size += 26
    if sets["uppercase"]:
        size += 26
    if sets["digits"]:
        size += 10
    if sets["symbols"]:
        size += 32

    return size


def calculate_entropy(password: str) -> float:
    """
    Compute password entropy with:
    entropy = length * log2(charset_size)
    """
    if not is_valid_password(password):
        return 0.0

    normalized = _normalized_for_entropy(password)
    length = len(normalized)
    charset_size = calculate_charset_size(password)

    if length == 0 or charset_size == 0:
        return 0.0

    return length * math.log2(charset_size)


def format_duration(seconds: float) -> str:
    """Convert seconds into a human-friendly crack-time string."""
    if seconds <= 0:
        return "instant"
    if math.isinf(seconds):
        return "effectively uncrackable with brute force"

    minute = 60
    hour = 60 * minute
    day = 24 * hour
    year = 365 * day

    if seconds < 1:
        return "less than 1 second"
    if seconds < minute:
        return f"{seconds:.2f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.2f} minutes"
    if seconds < day:
        return f"{seconds / hour:.2f} hours"
    if seconds < year:
        return f"{seconds / day:.2f} days"
    if seconds < 1_000 * year:
        return f"{seconds / year:.2f} years"

    return f"{seconds / year:,.0f} years"