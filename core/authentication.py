import re


def analyze_authentication(authentication_results):
    """
    Analyze SPF, DKIM and DMARC results from
    the Authentication-Results header.
    """

    results = {
        "spf": "NONE",
        "dkim": "NONE",
        "dmarc": "NONE",
        "findings": []
    }

    if not authentication_results:
        results["findings"].append({
            "type": "Missing Authentication Results",
            "severity": "Medium",
            "evidence": "Authentication-Results header was not present."
        })

        return results

    auth = authentication_results.lower()

    # SPF
    spf_match = re.search(r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", auth)

    if spf_match:
        results["spf"] = spf_match.group(1).upper()

    # DKIM
    dkim_match = re.search(r"\bdkim\s*=\s*(pass|fail|none|neutral|temperror|permerror)", auth)

    if dkim_match:
        results["dkim"] = dkim_match.group(1).upper()

    # DMARC
    dmarc_match = re.search(r"\bdmarc\s*=\s*(pass|fail|none|bestguesspass|temperror|permerror)", auth)

    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).upper()

    # -------------------------------------------------
    # FINDINGS
    # -------------------------------------------------

    if results["spf"] in ["FAIL", "SOFTFAIL", "PERMERROR"]:

        results["findings"].append({
            "type": "SPF Authentication Failure",
            "severity": "High",
            "evidence": f"SPF result: {results['spf']}"
        })

    elif results["spf"] == "PASS":

        results["findings"].append({
            "type": "SPF Passed",
            "severity": "Info",
            "evidence": "SPF authentication passed."
        })

    if results["dkim"] in ["FAIL", "PERMERROR"]:

        results["findings"].append({
            "type": "DKIM Authentication Failure",
            "severity": "High",
            "evidence": f"DKIM result: {results['dkim']}"
        })

    elif results["dkim"] == "PASS":

        results["findings"].append({
            "type": "DKIM Passed",
            "severity": "Info",
            "evidence": "DKIM authentication passed."
        })

    if results["dmarc"] in ["FAIL", "PERMERROR"]:

        results["findings"].append({
            "type": "DMARC Authentication Failure",
            "severity": "High",
            "evidence": f"DMARC result: {results['dmarc']}"
        })

    elif results["dmarc"] == "PASS":

        results["findings"].append({
            "type": "DMARC Passed",
            "severity": "Info",
            "evidence": "DMARC authentication passed."
        })

    return results