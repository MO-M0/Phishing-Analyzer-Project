"""
parser.py
---------
Job of this file: take a raw .eml file (a standard email file format) and turn
it into a plain, simple Python object with just the fields we care about:
sender, reply_to, subject, body text, list of URLs, list of attachment names.

Everything downstream (sender_analysis.py, url_analysis.py, etc.) works with
this simple object instead of touching raw email files again.
"""

import re
from email import policy
from email.parser import BytesParser
from dataclasses import dataclass, field


@dataclass
class ParsedEmail:
    """
    A @dataclass is a normal Python class where you just declare the fields
    and Python auto-generates the __init__ for you. This object is basically
    a labeled container: parsed.sender, parsed.subject, etc.
    """
    filename: str
    sender: str
    reply_to: str
    subject: str
    body: str
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)


# A simple pattern that matches most http/https URLs inside plain text.
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')


def _extract_urls(text: str) -> list:
    """Find every http(s) URL inside a block of text using regex."""
    if not text:
        return []
    # Strip common trailing punctuation like '.' or ')' that regex can pick up
    # by mistake at the end of a sentence.
    found = URL_PATTERN.findall(text)
    return [u.rstrip('.,)>"\'') for u in found]


def load_email(path: str) -> ParsedEmail:
    """
    Reads one .eml file from disk and returns a ParsedEmail object.

    Steps:
    1. Open the file in binary mode ("rb") because email files can contain
       mixed encodings, and Python's email parser expects bytes.
    2. BytesParser + policy.default understands the standard email format
       (headers like From/Subject, plus multipart bodies and attachments)
       so we don't have to parse that structure by hand.
    3. Pull out the headers we need.
    4. Walk the message parts to separate body text from attachments.
    """
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender = msg.get("From", "") or ""
    reply_to = msg.get("Reply-To", "") or ""
    subject = msg.get("Subject", "") or ""

    body_text = ""
    attachments = []

    if msg.is_multipart():
        # A multipart email is like a folder containing several pieces:
        # a text part, maybe an HTML part, maybe attachment files.
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if filename:
                # This part is an attached file, not body text.
                attachments.append(filename)
            elif part.get_content_type() == "text/plain" and "attachment" not in content_disposition:
                # This part is the readable body of the email.
                try:
                    body_text += part.get_content()
                except Exception:
                    pass
    else:
        # Simple email: no attachments, just one body.
        try:
            body_text = msg.get_content()
        except Exception:
            body_text = str(msg.get_payload())

    urls = _extract_urls(body_text)

    return ParsedEmail(
        filename=path,
        sender=sender.strip(),
        reply_to=reply_to.strip(),
        subject=subject.strip(),
        body=body_text.strip(),
        urls=urls,
        attachments=attachments,
    )
