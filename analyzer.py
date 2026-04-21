"""Core analysis logic for password strength estimation."""

import math
from typing import Dict

from utils import (
    calculate_charset_size,
    calculate_entropy,
    detect_character_sets,
    format_duration,
    is_valid_password,
)


GUESSES_PER_SECOND = 10**10  # 10 billion guesses/second


def generate_feedback(password: str, entropy: float) -> list[str]:
    """Generate human-readable security suggestions for a password."""
    feedback: list[str] = []
    normalized = password.lower()
    length = len(password)

    # Length guidance
    if length < 8:
        feedback.append("Use at least 8 characters; 12+ is recommended for stronger security.")
    elif length < 12:
        feedback.append("Increase length to 12+ characters to significantly improve resistance.")

    # Character variety guidance
    has_lower = any(ch.islower() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)

    if has_lower and not (has_upper or has_digit or has_symbol):
        feedback.append("Avoid lowercase-only passwords; add uppercase letters, numbers, and symbols.")
    if password.isalpha():
        feedback.append("Letters-only passwords are easier to crack; include numbers and symbols.")
    if password.isdigit():
        feedback.append("Numbers-only passwords are weak; combine letters, numbers, and symbols.")

    # Common pattern checks
    common_patterns = ("123", "password", "qwerty", "abc", "111")
    matched_patterns = [pattern for pattern in common_patterns if pattern in normalized]
    if matched_patterns:
        feedback.append(
            "Avoid common patterns or dictionary terms (found: "
            + ", ".join(matched_patterns)
            + ")."
        )

    # Entropy guidance
    if entropy < 28:
        feedback.append("Entropy is low (<28 bits). This password is vulnerable to brute-force attacks.")
    elif entropy <= 50:
        feedback.append("Entropy is moderate (28-50 bits). Improve complexity for better security margin.")
    else:
        feedback.append("Good entropy (>50 bits). Maintain uniqueness and avoid password reuse.")

    if not feedback:
        feedback.append("Password profile looks solid. Keep using unique passwords per account.")

    return feedback


def estimate_crack_time_seconds(entropy: float) -> float:
    """Estimate brute-force crack time in seconds."""
    if entropy <= 0:
        return 0.0

    try:
        combinations = 2.0 ** entropy
    except OverflowError:
        return math.inf

    return combinations / GUESSES_PER_SECOND


def classify_strength(entropy: float) -> str:
    """Map entropy to a strength label."""
    if entropy < 28:
        return "VERY WEAK"
    if entropy < 36:
        return "WEAK"
    if entropy < 60:
        return "MODERATE"
    if entropy < 80:
        return "STRONG"
    return "VERY STRONG"


def analyze_password(password: str) -> Dict[str, object]:
    """Run full analysis for a password."""
    if not is_valid_password(password):
        return {
            "length": len(password),
            "charset_size": 0,
            "entropy": 0,
            "entropy_bits": 0,
            "crack_time": "Invalid password",
            "strength": "VERY WEAK",
            "charsets": {
                "lowercase": False,
                "uppercase": False,
                "digits": False,
                "symbols": False,
            },
            "feedback": ["Password cannot be empty or only spaces"],
            "guesses_per_second": GUESSES_PER_SECOND,
        }

    charset_size = calculate_charset_size(password)
    entropy = calculate_entropy(password)
    crack_seconds = estimate_crack_time_seconds(entropy)
    charsets = detect_character_sets(password)
    feedback = generate_feedback(password, entropy)

    return {
        "length": len(password),
        "charset_size": charset_size,
        "entropy": round(entropy, 2),
        "entropy_bits": round(entropy, 2),
        "crack_time": format_duration(crack_seconds),
        "strength": classify_strength(entropy),
        "charsets": charsets,
        "feedback": feedback,
        "guesses_per_second": GUESSES_PER_SECOND,
    }