import re
from urllib.parse import urlparse


URL_PATTERN = r'https?://[^\s<>"\']+'


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at"
}


SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq"
}


def extract_urls(text):
    """
    Extract URLs from email content.
    """

    if not text:
        return []

    urls = re.findall(URL_PATTERN, text)

    cleaned_urls = []

    for url in urls:

        url = url.rstrip(".,);]>}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def analyze_urls(urls):
    """
    Analyze extracted URLs for phishing-related indicators.
    """

    findings = []

    for url in urls:

        parsed = urlparse(url)

        domain = parsed.hostname or ""

        domain = domain.lower()

        # ---------------------------------------------
        # IP ADDRESS URL
        # ---------------------------------------------

        if re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            domain
        ):

            findings.append({
                "type": "IP Address URL",
                "severity": "High",
                "url": url,
                "evidence": f"URL uses IP address instead of domain: {domain}"
            })

        # ---------------------------------------------
        # URL SHORTENER
        # ---------------------------------------------

        if domain in SHORTENERS:

            findings.append({
                "type": "URL Shortener",
                "severity": "Medium",
                "url": url,
                "evidence": f"Known URL shortening service: {domain}"
            })

        # ---------------------------------------------
        # PUNYCODE
        # ---------------------------------------------

        if domain.startswith("xn--") or ".xn--" in domain:

            findings.append({
                "type": "Punycode Domain",
                "severity": "High",
                "url": url,
                "evidence": f"Internationalized/punycode domain detected: {domain}"
            })

        # ---------------------------------------------
        # SUSPICIOUS TLD
        # ---------------------------------------------

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):

            findings.append({
                "type": "Suspicious TLD",
                "severity": "Medium",
                "url": url,
                "evidence": f"Domain uses potentially suspicious TLD: {domain}"
            })

        # ---------------------------------------------
        # EXCESSIVE SUBDOMAINS
        # ---------------------------------------------

        domain_parts = domain.split(".")

        if len(domain_parts) >= 5:

            findings.append({
                "type": "Excessive Subdomains",
                "severity": "Medium",
                "url": url,
                "evidence": f"Domain contains many subdomain levels: {domain}"
            })

        # ---------------------------------------------
        # URL ENCODING
        # ---------------------------------------------

        if "%" in url:

            findings.append({
                "type": "Encoded URL",
                "severity": "Low",
                "url": url,
                "evidence": "URL contains percent-encoded characters."
            })

        # ---------------------------------------------
        # CREDENTIALS IN URL
        # ---------------------------------------------

        if parsed.username or parsed.password:

            findings.append({
                "type": "Credentials in URL",
                "severity": "High",
                "url": url,
                "evidence": "URL contains embedded username/password information."
            })

        # ---------------------------------------------
        # VERY LONG URL
        # ---------------------------------------------

        if len(url) > 150:

            findings.append({
                "type": "Unusually Long URL",
                "severity": "Low",
                "url": url,
                "evidence": f"URL length: {len(url)} characters."
            })

    return findings