"""
risk_engine.py
---------------
Covers assignment requirements #8, #9, and #10:
    8. Calculate a risk score based on detected indicators.
    9. Classify the email as LOW, MEDIUM, HIGH, or CRITICAL risk.
    10. Display the indicators/reasons that contributed to the risk level.

This file does NOT do any detection itself. It calls each detection module,
collects their Indicator lists into one combined list, adds up the points,
caps the total at 100, and maps the total onto a risk label.

Keeping this "orchestration only" separation is a common software design
pattern: each analysis module can be tested/changed independently, and this
engine just wires them together.
"""

from dataclasses import dataclass

from analyzer.parser import ParsedEmail
from analyzer.sender_analysis import check_sender, check_reply_to_mismatch
from analyzer.url_analysis import check_urls
from analyzer.keyword_analysis import check_keywords
from analyzer.attachment_analysis import check_attachments


@dataclass
class AnalysisResult:
    email: ParsedEmail
    indicators: list
    score: int
    level: str


def _score_to_level(score: int) -> str:
    """Simple threshold mapping. Adjust these cutoffs if you want the
    software to behave more or less strictly."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


def analyze(email: ParsedEmail) -> AnalysisResult:
    """
    Runs every detection module against the parsed email and produces one
    final AnalysisResult. This is the single function main.py needs to call.
    """
    indicators = []
    indicators += check_sender(email.sender)
    indicators += check_reply_to_mismatch(email.sender, email.reply_to)
    indicators += check_urls(email.urls, email.sender)
    indicators += check_keywords(email.subject, email.body)
    indicators += check_attachments(email.attachments)

    raw_score = sum(i.points for i in indicators)
    score = min(raw_score, 100)  # cap so one email can't exceed 100/100
    level = _score_to_level(score)

    return AnalysisResult(email=email, indicators=indicators, score=score, level=level)
