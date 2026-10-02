"""
sender_analysis.py
-------------------
Covers assignment requirements #1 and #2:
    1. Analyze the sender email address and sender domain.
    2. Check for Reply-To address mismatches.

Every "check_*" function below returns a list of "Indicator" objects.
An Indicator is just a small labeled fact: what was found, and how many
risk points it's worth. The risk_engine.py file later adds all these
points up across every module.
"""

import re
from dataclasses import dataclass

# Brand names attackers commonly impersonate, and the lookalike patterns
# scammers use instead of the real domain (typosquatting / character swaps).
KNOWN_BRANDS = {
    "paypal": ["paypa1", "paypall", "paypal-secure", "paypa1-security"],
    "microsoft": ["micros0ft", "microsft", "microsoft-support"],
    "apple": ["appIe", "apple-id", "apple-verify"],
    "google": ["g00gle", "googlle"],
    "bank": ["secure-bank", "bank-verify", "bank-alert"],
}


@dataclass
class Indicator:
    label: str      # human-readable description shown in the final report
    points: int      # how much this adds to the risk score


def _extract_domain(email_address: str) -> str:
    """
    Pull just the domain out of a string like:
        "Security Team <security@paypa1-security.example>"
    We use regex to grab whatever is between '@' and the closing '>' or end
    of string.
    """
    match = re.search(r'@([\w\.-]+)', email_address)
    return match.group(1).lower() if match else ""


def check_sender(sender: str) -> list:
    """
    Requirement #1: look at the sender address/domain itself and flag
    known red flags like a brand name misspelled inside the domain.
    """
    indicators = []
    domain = _extract_domain(sender)

    if not domain:
        indicators.append(Indicator("Sender address could not be parsed", 10))
        return indicators

    for brand, lookalikes in KNOWN_BRANDS.items():
        # Only report each brand once, even if more than one lookalike
        # pattern for it matches the same domain.
        if any(fake in domain for fake in lookalikes) and brand not in domain:
            indicators.append(
                Indicator(f"Sender domain '{domain}' looks like a fake version of '{brand}'", 30)
            )

    # Free webmail domains pretending to be a company are a classic sign.
    free_webmail = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    if any(domain.endswith(fw) for fw in free_webmail) and any(
        word in sender.lower() for word in ["security", "support", "billing", "admin", "helpdesk"]
    ):
        indicators.append(
            Indicator(f"Sender claims to be an official department but uses free webmail domain '{domain}'", 20)
        )

    return indicators


def check_reply_to_mismatch(sender: str, reply_to: str) -> list:
    """
    Requirement #2: a legitimate company almost always replies from the
    same domain it sent from. If Reply-To points somewhere else entirely,
    that's a strong phishing signal (it's how the attacker gets your reply
    instead of the real company).
    """
    indicators = []
    if not reply_to:
        return indicators  # No Reply-To header set, nothing to compare.

    sender_domain = _extract_domain(sender)
    reply_domain = _extract_domain(reply_to)

    if sender_domain and reply_domain and sender_domain != reply_domain:
        indicators.append(
            Indicator(
                f"Reply-To domain '{reply_domain}' does not match sender domain '{sender_domain}'",
                25,
            )
        )
    return indicators
