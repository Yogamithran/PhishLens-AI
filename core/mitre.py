MITRE_RULES = {
    "Urgency / Social Engineering": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access"
    },

    "IP Address URL": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access"
    },

    "URL Shortener": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access"
    },

    "Punycode Domain": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access"
    },

    "Potential Brand Impersonation": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access"
    },

    "Reply-To Mismatch": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access"
    }
}


def map_to_mitre(findings):
    """
    Map deterministic phishing findings to
    predefined MITRE ATT&CK techniques.
    """

    mappings = []
    seen = set()

    for finding in findings:

        finding_type = finding.get("type")

        rule = MITRE_RULES.get(finding_type)

        if not rule:
            continue

        technique_id = rule["technique_id"]

        if technique_id in seen:
            continue

        seen.add(technique_id)

        mappings.append({
            "technique_id": technique_id,
            "technique": rule["technique"],
            "tactic": rule["tactic"],
            "trigger": finding_type,
            "evidence": finding.get(
                "evidence",
                ""
            )
        })

    return mappings