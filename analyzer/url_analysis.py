"""
url_analysis.py
----------------
Covers assignment requirements #3, #4, and #7:
    3. Extract and analyze URLs contained in the email.
    4. Detect suspicious URLs or domains.
    7. Identify possible mismatches between the sender domain and URL domain.

(URL *extraction* itself already happened in parser.py — this file focuses
on judging whether the extracted URLs look dangerous.)
"""

import re
from urllib.parse import urlparse
from analyzer.sender_analysis import Indicator, _extract_domain

# Services that shorten links, hiding the real destination. Widely abused
# in phishing because the victim can't see where they'll actually land.
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"]

# A raw IP address instead of a domain name in a URL is unusual for
# legitimate businesses and common in phishing kits.
IP_URL_PATTERN = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

SUSPICIOUS_TLDS = [".zip", ".top", ".xyz", ".click", ".gq", ".tk"]


def _domain_of(url: str) -> str:
    """Use urllib to safely pull just the hostname out of a full URL."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def check_urls(urls: list, sender: str) -> list:
    """
    Loops over every URL found in the email body and checks it against a
    handful of independent red flags. Multiple flags can fire on the same
    URL (e.g. a shortener AND a domain mismatch).
    """
    indicators = []
    if not urls:
        return indicators

    sender_domain = _extract_domain(sender)

    for url in urls:
        domain = _domain_of(url)

        if any(domain.endswith(s) for s in URL_SHORTENERS):
            indicators.append(Indicator(f"URL uses a link shortener ({domain}), destination is hidden", 20))

        if IP_URL_PATTERN.match(url):
            indicators.append(Indicator(f"URL uses a raw IP address instead of a domain name ({url})", 25))

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            indicators.append(Indicator(f"URL uses a high-risk top-level domain ({domain})", 15))

        # Requirement #7: does the link point somewhere different from
        # where the email claims to be from? A real PayPal email should
        # only link to paypal.com, not some unrelated domain.
        if sender_domain and domain and sender_domain not in domain and domain not in sender_domain:
            indicators.append(
                Indicator(f"Link domain '{domain}' does not match sender domain '{sender_domain}'", 20)
            )

    return indicators
