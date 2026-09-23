SEVERITY_WEIGHTS = {
    "Critical": 30,
    "High": 20,
    "Medium": 10,
    "Low": 5,
    "Info": 0
}


def calculate_risk(all_findings):
    """
    Calculate an explainable phishing risk score
    from deterministic security findings.
    """

    score = 0
    evidence = []

    for finding in all_findings:

        severity = finding.get("severity", "Info")

        weight = SEVERITY_WEIGHTS.get(
            severity,
            0
        )

        score += weight

        if weight > 0:

            evidence.append({
                "type": finding.get(
                    "type",
                    "Unknown"
                ),
                "severity": severity,
                "weight": weight,
                "evidence": finding.get(
                    "evidence",
                    ""
                )
            })

    # Prevent score from exceeding 100
    score = min(score, 100)

    # Determine risk level
    if score >= 80:
        level = "Critical"

    elif score >= 60:
        level = "High"

    elif score >= 30:
        level = "Medium"

    elif score > 0:
        level = "Low"

    else:
        level = "Informational"

    return {
        "score": score,
        "level": level,
        "evidence": evidence
    }