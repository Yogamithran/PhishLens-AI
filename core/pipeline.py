from core.parser import parse_email
from core.headers import analyze_headers
from core.authentication import analyze_authentication
from core.urls import extract_urls, analyze_urls
from core.ioc import extract_iocs
from core.risk import calculate_risk
from core.mitre import map_to_mitre


def analyze_email(email_text):
    """
    Run the complete deterministic PhishLens investigation pipeline.
    """

    # -------------------------
    # 1. Parse email
    # -------------------------

    email_data = parse_email(email_text)

    # -------------------------
    # 2. Header analysis
    # -------------------------

    header_findings = analyze_headers(email_data)

    # -------------------------
    # 3. Authentication analysis
    # -------------------------

    auth_results = analyze_authentication(
        email_data.get(
            "authentication_results",
            ""
        )
    )

    auth_findings = auth_results.get(
        "findings",
        []
    )

    # -------------------------
    # 4. URL analysis
    # -------------------------

    urls = extract_urls(email_text)

    url_findings = analyze_urls(urls)

    # -------------------------
    # 5. IOC extraction
    # -------------------------

    iocs = extract_iocs(email_text)

    # -------------------------
    # 6. Combine findings
    # -------------------------

    all_findings = (
        header_findings
        + auth_findings
        + url_findings
    )

    # -------------------------
    # 7. Risk calculation
    # -------------------------

    risk = calculate_risk(
        all_findings
    )

    # -------------------------
    # 8. MITRE mapping
    # -------------------------

    mitre = map_to_mitre(
        all_findings
    )

    # -------------------------
    # Final investigation result
    # -------------------------

    return {
        "email": email_data,
        "urls": urls,
        "iocs": iocs,
        "findings": all_findings,
        "authentication": auth_results,
        "risk": risk,
        "mitre": mitre
    }