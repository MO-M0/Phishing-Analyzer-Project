# Phishing Email Analyzer 

A Python software that analyzes synthetic email files (`.eml`) and
flags indicators commonly associated with phishing attempts, then produces
a risk score (0–100) and a LOW / MEDIUM / HIGH / CRITICAL classification, developed by

## Student Information
```
NAME: Amole Moyinoluwa Candice
LEVEL: 300lv
PHONE NUMBER: 09028183275
```


Built for a cybersecurity practical assignment. **All sample emails in
`data/samples/` are synthetic** — no real people, credentials, or
organizations are involved, and no attachment content is ever opened or
executed.

## File Explanation and How they work
```
main.py                  -> command-line interface
analyzer/parser.py        -> reads a .eml file into a simple Python object
analyzer/sender_analysis.py   -> it analyzes sender domain + Reply-To mismatch
analyzer/url_analysis.py      -> it checks suspicious URL / domain mismatch
analyzer/keyword_analysis.py  -> it checks urgency / credential-harvesting phrase and words
analyzer/attachment_analysis.py -> it checks for risky attachment file type
analyzer/risk_engine.py       -> it combines all checks into one score and makes verdict
data/samples/*.eml        -> contains the synthetic sample emails for testing
```

Each analysis module returns a list of "indicators" (a short description +
a point value). `risk_engine.py` adds the points together, caps the total
at 100, and maps the score onto a risk level:

Score -> Level
80–100 -> CRITICAL
50–79 -> HIGH
25–49 -> MEDIUM
0–24 -> LOW 

## Setup
Requires Python 3.9+. No external packages are needed.



## Usage

Run the tool and choose a sample email by number, or `a` to analyze all of
them at once:
Example:

```
Phishing Email Analyzer
Available sample emails:
  1. sample1_paypal_phish.eml
  2. sample2_bank_phish.eml
  3. sample3_invoice_phish.eml
  ............................
  ..........................

  a. Analyze ALL samples

Enter a number, or 'a' for all: 1
```

Example output:

```
============================================================
PHISHING EMAIL ANALYSIS
============================================================
Sender      : PayPal Security <security@paypa1-security.example>
Reply-To    : support@gmail.com
Risk Score  : 100/100
Risk Level  : CRITICAL
------------------------------------------------------------
Indicators:
  1. Sender domain 'paypa1-security.example' looks like a fake version of 'paypal'  (+30 pts)
  2. Reply-To domain 'gmail.com' does not match sender domain 'paypa1-security.example'  (+25 pts)
  3. URL uses a link shortener (bit.ly), destination is hidden  (+20 pts)
  4. Link domain 'bit.ly' does not match sender domain 'paypa1-security.example'  (+20 pts)
  5. Urgency/pressure language detected: act now, urgent, immediately  (+30 pts)
============================================================
```

## Adding your own test emails

Drop any additional `.eml` file into `data/samples/` — it will automatically
appear in the tool's menu next time you run it. Keep all content synthetic.

## Safety

This tool only reads email headers, body text, and attachment **filenames**.
It never opens, extracts, or executes attachment contents, and it makes no
network requests. It is intended purely for defensive, educational analysis.
