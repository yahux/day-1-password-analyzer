"""CLI entrypoint for Password Strength Analyzer."""

import sys

from analyzer import analyze_password

try:
    from colorama import Fore, Style, init

    init(autoreset=True)
except ImportError:
    raise SystemExit(
        "colorama is required for this CLI output style. Install with: pip install colorama"
    )


def get_color(strength: str) -> str:
    """Return display color for a strength label."""
    if strength in {"VERY WEAK", "WEAK"}:
        return Fore.RED
    if strength == "MODERATE":
        return Fore.YELLOW
    return Fore.GREEN


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("\n🔐 Password Strength Analyzer\n")

    password = input("Enter password: ")
    result = analyze_password(password)

    print("\n📊 Result:")
    print(f"Entropy: {result['entropy']} bits")
    print(f"Crack Time: {result['crack_time']}")

    strength = result["strength"]
    print(f"Strength: {get_color(strength)}{strength}{Style.RESET_ALL}")

    print("\n🧠 Feedback:")
    for item in result["feedback"]:
        print(f"- {item}")


if __name__ == "__main__":
    main()