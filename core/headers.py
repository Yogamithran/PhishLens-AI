def analyze_headers(email_data):
    """
    Analyze email headers for suspicious relationships
    and useful SOC investigation evidence.
    """

    findings = []

    sender = email_data.get("from", "")
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")
    message_id = email_data.get("message_id", "")

    # -------------------------------------------------
    # FROM / REPLY-TO ANALYSIS
    # -------------------------------------------------

    if reply_to and reply_to != "Not found":

        sender_domain = extract_domain(sender)
        reply_domain = extract_domain(reply_to)

        if (
            sender_domain
            and reply_domain
            and sender_domain.lower() != reply_domain.lower()
        ):

            findings.append({
                "type": "Reply-To Mismatch",
                "severity": "High",
                "evidence": (
                    f"From domain: {sender_domain} | "
                    f"Reply-To domain: {reply_domain}"
                )
            })

        else:

            findings.append({
                "type": "Reply-To Present",
                "severity": "Info",
                "evidence": reply_to
            })

    # -------------------------------------------------
    # RETURN-PATH ANALYSIS
    # -------------------------------------------------

    if return_path and return_path != "Not found":

        sender_domain = extract_domain(sender)
        return_domain = extract_domain(return_path)

        if (
            sender_domain
            and return_domain
            and sender_domain.lower() != return_domain.lower()
        ):

            findings.append({
                "type": "Return-Path Mismatch",
                "severity": "Medium",
                "evidence": (
                    f"From domain: {sender_domain} | "
                    f"Return-Path domain: {return_domain}"
                )
            })

    # -------------------------------------------------
    # MESSAGE-ID
    # -------------------------------------------------

    if message_id == "Not found" or not message_id:

        findings.append({
            "type": "Missing Message-ID",
            "severity": "Low",
            "evidence": "Message-ID header was not present."
        })

    # -------------------------------------------------
    # DISPLAY NAME ANALYSIS
    # -------------------------------------------------

    if sender and sender != "Not found":

        display_name, sender_address = split_sender(sender)

        if display_name and sender_address:

            sender_domain = extract_domain(sender_address)

            common_brands = [
                "microsoft",
                "google",
                "amazon",
                "apple",
                "paypal",
                "linkedin",
                "github",
                "facebook"
            ]

            display_lower = display_name.lower()

            for brand in common_brands:

                if brand in display_lower:

                    findings.append({
                        "type": "Potential Brand Impersonation",
                        "severity": "Medium",
                        "evidence": (
                            f"Display name '{display_name}' "
                            f"contains brand keyword '{brand}' "
                            f"while sender domain is '{sender_domain}'."
                        )
                    })

    return findings


# -------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------

def extract_domain(email_address):
    """
    Extract domain from an email address.
    """

    if not email_address:
        return None

    if "@" not in email_address:
        return None

    address = email_address.split("@")[-1]

    address = address.strip(
        " <>\"'"
    )

    return address


def split_sender(sender):
    """
    Split a sender value such as:

    Microsoft Security <alert@evil.example>

    into:

    display name
    email address
    """

    if "<" in sender and ">" in sender:

        display_name = sender.split("<")[0].strip()

        email_address = (
            sender.split("<")[1]
            .split(">")[0]
            .strip()
        )

        return display_name, email_address

    return None, sender.strip()