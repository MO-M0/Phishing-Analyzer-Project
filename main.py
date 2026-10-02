"""
main.py
-------
Covers assignment requirement #11:
    11. Provide a simple and user-friendly interface for analyzing an email.

This is the file you actually run: `python main.py`
It does three things:
1. List every sample .eml file in data/samples/.
2. Let you pick one (or type 'all' to run every sample at once).
3. Print a formatted report using analyzer/risk_engine.py.
"""

import os
import sys

from analyzer.parser import load_email
from analyzer.risk_engine import analyze, AnalysisResult

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "data", "samples")


def print_report(result: AnalysisResult):
    """
    Formats one AnalysisResult into the exact style shown in the
    assignment's 'Example Expected Output' section.
    """
    email = result.email
    print("=" * 60)
    print("PHISHING EMAIL ANALYSIS")
    print("=" * 60)
    # print(f"File        : {os.path.basename(email.filename)}")
    print(f"Sender      : {email.sender}")
    print(f"Reply-To    : {email.reply_to or '(none)'}")
    # print(f"Subject     : {email.subject}")
    print(f"Risk Score  : {result.score}/100")
    print(f"Risk Level  : {result.level}")
    print("-" * 60)
    if result.indicators:
        print("Indicators:")
        for i, ind in enumerate(result.indicators, start=1):
            print(f"  {i}. {ind.label}  (+{ind.points} pts)")
    else:
        print("Indicators: none detected")
    print("=" * 60)
    print()


def list_samples() -> list:
    if not os.path.isdir(SAMPLES_DIR):
        return []
    return sorted(f for f in os.listdir(SAMPLES_DIR) if f.endswith(".eml"))


def main():
    samples = list_samples()
    if not samples:
        print(f"No .eml sample files found in {SAMPLES_DIR}")
        sys.exit(1)

    print("Phishing Email Analyzer")
    print("Available sample emails:")
    for idx, name in enumerate(samples, start=1):
        print(f"  {idx}. {name}")
    print("  a. Analyze ALL samples")
    print()

    choice = input("Enter a number, or 'a' for all: ").strip().lower()

    if choice == "a":
        chosen_files = samples
    else:
        try:
            chosen_files = [samples[int(choice) - 1]]
        except (ValueError, IndexError):
            print("Invalid choice.")
            sys.exit(1)

    for filename in chosen_files:
        full_path = os.path.join(SAMPLES_DIR, filename)
        parsed = load_email(full_path)
        result = analyze(parsed)
        print_report(result)


if __name__ == "__main__":
    main()
