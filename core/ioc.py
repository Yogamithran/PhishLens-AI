import re


IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

HASH_PATTERN = (
    r"\b[a-fA-F0-9]{32}\b|"
    r"\b[a-fA-F0-9]{40}\b|"
    r"\b[a-fA-F0-9]{64}\b"
)


def extract_iocs(text):
    """
    Extract common Indicators of Compromise (IOCs)
    from email content.
    """

    if not text:
        return {
            "ips": [],
            "domains": [],
            "emails": [],
            "hashes": []
        }

    # IP addresses
    ips = sorted(set(
        re.findall(IP_PATTERN, text)
    ))

    # Email addresses
    emails = sorted(set(
        re.findall(EMAIL_PATTERN, text)
    ))

    # Hashes
    hashes = sorted(set(
        re.findall(HASH_PATTERN, text)
    ))

    # Domains from URLs
    domains = set()

    urls = re.findall(
        r"https?://[^\s<>'\"]+",
        text
    )

    for url in urls:

        url = url.rstrip(".,);]}")

        match = re.match(
            r"https?://([^/:?#]+)",
            url
        )

        if match:

            domain = match.group(1).lower()

            # Do not classify IP addresses as domains
            if not re.fullmatch(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                domain
            ):
                domains.add(domain)

    return {
        "ips": ips,
        "domains": sorted(domains),
        "emails": emails,
        "hashes": hashes
    }