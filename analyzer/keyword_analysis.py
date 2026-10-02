"""
keyword_analysis.py
--------------------
Covers assignment requirement #5:
    5. Detect suspicious or phishing-related keywords in the subject and body.

Phishing emails lean heavily on psychological pressure: urgency, fear of
losing access, and requests to "verify" or "confirm" something right now.
We keep a list of common trigger phrases and scan for them.
"""

from analyzer.sender_analysis import Indicator

URGENCY_PHRASES = [
    "act now", "urgent", "immediately", "verify your account",
    "suspended", "unusual activity", "click here", "limited time",
    "confirm your identity", "your account will be locked",
    "final notice", "expire", "reset your password now",
]

CREDENTIAL_HARVEST_PHRASES = [
    "enter your password", "confirm your ssn", "update your billing",
    "provide your credit card", "login to verify",
]


def check_keywords(subject: str, body: str) -> list:
    """
    Lowercases the subject + body once, then checks how many phrases from
    each list appear. Each matched phrase adds points, but we cap how many
    times the *same category* can contribute so one repeated word doesn't
    dominate the whole score.
    """
    indicators = []
    text = f"{subject} {body}".lower()

    urgency_hits = [p for p in URGENCY_PHRASES if p in text]
    if urgency_hits:
        indicators.append(
            Indicator(f"Urgency/pressure language detected: {', '.join(urgency_hits[:3])}", min(10 * len(urgency_hits), 30))
        )

    credential_hits = [p for p in CREDENTIAL_HARVEST_PHRASES if p in text]
    if credential_hits:
        indicators.append(
            Indicator(f"Credential-harvesting language detected: {', '.join(credential_hits[:3])}", min(15 * len(credential_hits), 30))
        )

    return indicators
