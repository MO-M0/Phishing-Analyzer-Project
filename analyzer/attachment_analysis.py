"""
attachment_analysis.py
-----------------------
Covers assignment requirement #6:
    6. Check attachments and identify potentially risky file types.

IMPORTANT (per the assignment's Safety Requirement): this module only ever
looks at the attachment *filename*. It never opens, extracts, or executes
attachment content. That would be unsafe and is explicitly out of scope.
"""

from analyzer.sender_analysis import Indicator

# File types that can run code directly, or commonly wrap something that
# does (macros, scripts, double extensions).
HIGH_RISK_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1"]
MEDIUM_RISK_EXTENSIONS = [".zip", ".rar", ".docm", ".xlsm", ".html", ".iso"]


def check_attachments(attachments: list) -> list:
    indicators = []

    for filename in attachments:
        lower_name = filename.lower()

        if any(lower_name.endswith(ext) for ext in HIGH_RISK_EXTENSIONS):
            indicators.append(Indicator(f"High-risk executable attachment: {filename}", 35))
        elif any(lower_name.endswith(ext) for ext in MEDIUM_RISK_EXTENSIONS):
            indicators.append(Indicator(f"Potentially risky attachment type: {filename}", 15))

        # A "double extension" like invoice.pdf.exe is a classic disguise
        # trick — it looks like a harmless PDF at a glance.
        parts = lower_name.split(".")
        if len(parts) > 2 and parts[-1] in [e.strip(".") for e in HIGH_RISK_EXTENSIONS]:
            indicators.append(Indicator(f"Attachment uses a disguised double extension: {filename}", 20))

    return indicators
