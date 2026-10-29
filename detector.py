
import ipaddress
import re
from urllib.parse import urlparse


def analyze_url(url):
    """Analyze a URL for common phishing warning signs."""

    url = url.strip()

    if not url:
        return 0, ["Please enter a URL."], "No assessment"

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname or "." not in hostname:
        return (
            100,
            ["The URL has a missing or unusual hostname."],
            "Higher risk",
        )

    score = 0
    findings = []

    # Check whether HTTPS is used.
    if parsed.scheme.lower() != "https":
        score += 10
        findings.append("The URL does not use HTTPS.")

    # Check whether the URL uses an IP address.
    try:
        ipaddress.ip_address(hostname)
        score += 25
        findings.append(
            "The URL uses an IP address instead of a domain name."
        )
    except ValueError:
        pass

    # Check for unusually long URLs.
    if len(url) > 100:
        score += 10
        findings.append("The URL is unusually long.")

    # Check for an @ symbol in the network location.
    if "@" in parsed.netloc:
        score += 25
        findings.append(
            "The URL contains an @ symbol in its network location."
        )

    # Check for common URL-shortening services.
    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
    }

    if hostname.lower() in shorteners:
        score += 15
        findings.append(
            "The URL uses a known URL shortening service."
        )

    # Check for suspicious words in the hostname.
    suspicious_words = {
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
    }

    hostname_parts = re.split(r"[^a-zA-Z0-9]+", hostname.lower())
    matched_words = suspicious_words.intersection(hostname_parts)

    if matched_words:
        score += 15
        findings.append(
            "The hostname contains suspicious words: "
            + ", ".join(sorted(matched_words))
            + "."
        )

    score = min(score, 100)

    if not findings:
        findings.append(
            "No suspicious characteristics from these checks were found."
        )

    if score >= 50:
        assessment = "Higher risk"
    elif score >= 25:
        assessment = "Use caution"
    else:
        assessment = "Lower risk"

    return score, findings, assessment


def analyze_email(email):
    """Analyze email text for common phishing warning signs."""

    if not email.strip():
        return 0, ["Please paste email text."], "No assessment"

    score = 0
    findings = []
    text = email.lower()

    # Check for urgent or threatening language.
    urgency_phrases = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "account suspended",
        "account will be closed",
    ]

    matched_urgency = [
        phrase for phrase in urgency_phrases if phrase in text
    ]

    if matched_urgency:
        score += 20
        findings.append(
            "Urgency or pressure language detected: "
            + ", ".join(matched_urgency)
            + "."
        )

    # Check for requests involving credentials or identity.
    credential_phrases = [
        "verify your password",
        "confirm your password",
        "login to your account",
        "verify your account",
        "update your payment",
        "confirm your identity",
    ]

    if any(phrase in text for phrase in credential_phrases):
        score += 25
        findings.append(
            "The message contains a possible credential or identity request."
        )

    # Check for prize and reward scam language.
    prize_phrases = [
        "you have won",
        "claim your prize",
        "free gift",
        "lottery winner",
        "claim your reward",
    ]

    matched_prizes = [
        phrase for phrase in prize_phrases if phrase in text
    ]

    if matched_prizes:
        score += 20
        findings.append(
            "Prize or reward scam language detected: "
            + ", ".join(matched_prizes)
            + "."
        )

    # Check for web links.
    if re.search(r"https?://|www\.", text):
        score += 15
        findings.append("The message contains a web link.")

    # Check for references to sensitive information.
    if re.search(
        r"\bpassword\b|\botp\b|one-time code|bank details",
        text,
    ):
        score += 15
        findings.append(
            "The message mentions sensitive information, such as "
            "passwords, OTPs, or bank details."
        )

    score = min(score, 100)

    if not findings:
        findings.append(
            "None of the configured warning patterns were detected."
        )

    if score >= 50:
        assessment = "Higher risk"
    elif score >= 25:
        assessment = "Use caution"
    else:
        assessment = "Lower risk"

    return score, findings, assessment
