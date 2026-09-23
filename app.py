import streamlit as st
import requests
import json

from core.pipeline import analyze_email


# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------

st.set_page_config(
    page_title="PhishLens AI",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(0, 180, 255, 0.14), transparent 28%),
        radial-gradient(circle at 90% 15%, rgba(90, 50, 255, 0.12), transparent 30%),
        radial-gradient(circle at 50% 100%, rgba(0, 120, 255, 0.08), transparent 35%),
        linear-gradient(135deg, #030712 0%, #07111f 50%, #020617 100%);
    color: #e5f4ff;
}

.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: 0.18;
    background-image:
        linear-gradient(rgba(0, 200, 255, 0.06) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 200, 255, 0.06) 1px, transparent 1px);
    background-size: 40px 40px;
    mask-image: linear-gradient(to bottom, black, transparent 90%);
    z-index: 0;
}

.block-container {
    position: relative;
    z-index: 1;
    padding-top: 2rem;
    padding-bottom: 4rem;
    max-width: 1400px;
}

h1 {
    color: #e8f8ff !important;
    font-weight: 800 !important;
    letter-spacing: -1px;
    text-shadow:
        0 0 10px rgba(0, 200, 255, 0.45),
        0 0 30px rgba(0, 120, 255, 0.2);
}

h2, h3 {
    color: #d9f3ff !important;
    font-weight: 700 !important;
}

p, label, .stMarkdown {
    color: #b9cfe0;
}

[data-testid="stCaptionContainer"] {
    color: #6fa9c8 !important;
}

.stTextArea textarea {
    background: rgba(3, 12, 24, 0.88) !important;
    color: #dff7ff !important;
    border: 1px solid rgba(0, 190, 255, 0.35) !important;
    border-radius: 12px !important;
    box-shadow:
        inset 0 0 20px rgba(0, 120, 255, 0.05),
        0 0 15px rgba(0, 150, 255, 0.05);
}

.stTextArea textarea:focus {
    border: 1px solid rgba(0, 220, 255, 0.8) !important;
    box-shadow:
        0 0 0 1px rgba(0, 220, 255, 0.25),
        0 0 25px rgba(0, 180, 255, 0.15) !important;
}

.stButton > button {
    width: 100%;
    min-height: 48px;
    border: 1px solid rgba(0, 220, 255, 0.6);
    border-radius: 10px;
    background: linear-gradient(
        135deg,
        rgba(0, 150, 220, 0.9),
        rgba(0, 80, 180, 0.9)
    );
    color: white;
    font-weight: 700;
    letter-spacing: 0.4px;
    box-shadow:
        0 0 15px rgba(0, 180, 255, 0.2),
        inset 0 0 15px rgba(255, 255, 255, 0.05);
    transition: all 0.2s ease;
}

.stButton > button:hover {
    border-color: #5ee7ff;
    box-shadow:
        0 0 25px rgba(0, 200, 255, 0.4),
        0 0 50px rgba(0, 120, 255, 0.15);
    transform: translateY(-1px);
}

[data-testid="stMetric"] {
    background:
        linear-gradient(
            145deg,
            rgba(8, 25, 43, 0.9),
            rgba(3, 12, 25, 0.9)
        );
    border: 1px solid rgba(0, 180, 255, 0.22);
    border-radius: 14px;
    padding: 18px;
    box-shadow:
        0 0 20px rgba(0, 120, 255, 0.07),
        inset 0 0 20px rgba(0, 180, 255, 0.025);
}

[data-testid="stMetricLabel"] {
    color: #6fa9c8 !important;
    font-weight: 600;
}

[data-testid="stMetricValue"] {
    color: #e7faff !important;
    font-weight: 800;
}

[data-testid="stExpander"] {
    background: rgba(5, 18, 32, 0.78);
    border: 1px solid rgba(0, 170, 255, 0.18);
    border-radius: 12px;
    box-shadow: 0 0 20px rgba(0, 100, 255, 0.05);
}

code {
    color: #7eeaff !important;
}

[data-testid="stCodeBlock"] {
    border: 1px solid rgba(0, 170, 255, 0.18);
    border-radius: 10px;
}

[data-testid="stAlert"] {
    border-radius: 10px;
    background: rgba(5, 18, 32, 0.78);
}

hr {
    border: none !important;
    height: 1px !important;
    background: linear-gradient(
        90deg,
        transparent,
        rgba(0, 200, 255, 0.5),
        rgba(90, 70, 255, 0.4),
        transparent
    ) !important;
    margin: 25px 0 !important;
}

[data-testid="stSidebar"] {
    background:
        linear-gradient(
            180deg,
            #030a14 0%,
            #061525 50%,
            #020711 100%
        );
    border-right: 1px solid rgba(0, 180, 255, 0.15);
}

[data-testid="stSidebar"] * {
    color: #b9d9ea;
}

header[data-testid="stHeader"] {
    background: rgba(2, 8, 18, 0.75);
}

::-webkit-scrollbar {
    width: 8px;
}

::-webkit-scrollbar-track {
    background: #020617;
}

::-webkit-scrollbar-thumb {
    background: #12435c;
    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background: #087fa8;
}

@media (max-width: 768px) {
    .block-container {
        padding-left: 1rem;
        padding-right: 1rem;
    }

    h1 {
        font-size: 2rem !important;
    }
}

</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------
# OLLAMA AI
# ---------------------------------------------------------

def ask_ollama(investigation_data):

    prompt = f"""
You are a cybersecurity SOC analyst assistant.

Analyze the following phishing email investigation data.

IMPORTANT:
- Do not invent evidence.
- Use only the supplied investigation data.
- Do not create unsupported MITRE ATT&CK techniques.
- Explain the evidence clearly.
- Distinguish detected evidence from analyst interpretation.
- Give practical SOC analyst actions.
- This is an analyst-assistance report, not a confirmed verdict.

Investigation Data:

{json.dumps(investigation_data, indent=2)}

Return exactly these sections:

ASSESSMENT:
Explain whether the email appears suspicious and why.

KEY EVIDENCE:
List the strongest detected indicators.

ATTACK TYPE:
Describe the likely phishing/social-engineering technique based only on the evidence.

MITRE ATT&CK:
Use ONLY the MITRE mappings already supplied in the investigation data.
Do not invent additional technique IDs.

SOC ACTIONS:
Give practical defensive investigation steps.

CONFIDENCE:
Give Low, Medium, or High confidence and explain why.
"""

    try:

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:1b",
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        response.raise_for_status()

        result = response.json()

        return result.get(
            "response",
            "No AI response returned."
        )

    except Exception as e:

        return f"AI connection error: {e}"


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.title("🛡️ PhishLens AI")

st.write(
    "AI-Powered Phishing Email Investigation Platform"
)

st.caption(
    "Deterministic security analysis + Local AI SOC Copilot"
)


# ---------------------------------------------------------
# EMAIL INPUT
# ---------------------------------------------------------

st.subheader("📧 Email Investigation")

email_text = st.text_area(
    "Paste a suspicious email",
    height=300,
    placeholder="Paste raw email headers and body here..."
)


# ---------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------

if st.button(
    "🔍 Analyze Email",
    type="primary"
):

    if not email_text.strip():

        st.warning(
            "Please paste an email first."
        )

    else:

        # -------------------------------------------------
        # RUN COMPLETE SECURITY PIPELINE
        # -------------------------------------------------

        with st.spinner(
            "Running PhishLens security analysis..."
        ):

            result = analyze_email(
                email_text
            )

        email_data = result["email"]
        authentication = result["authentication"]
        urls = result["urls"]
        iocs = result["iocs"]
        findings = result["findings"]
        risk = result["risk"]
        mitre = result["mitre"]


        # -------------------------------------------------
        # TOP METRICS
        # -------------------------------------------------

        st.divider()

        col1, col2, col3, col4 = st.columns(4)

        with col1:

            st.metric(
                "Risk Score",
                f"{risk['score']}/100"
            )

        with col2:

            st.metric(
                "Risk Level",
                risk["level"]
            )

        with col3:

            st.metric(
                "URLs Found",
                len(urls)
            )

        with col4:

            st.metric(
                "Findings",
                len(findings)
            )


        # -------------------------------------------------
        # EMAIL HEADERS
        # -------------------------------------------------

        st.subheader("📋 Email Headers")

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**From:**",
                email_data["from"]
            )

            st.write(
                "**To:**",
                email_data["to"]
            )

            st.write(
                "**Subject:**",
                email_data["subject"]
            )

            st.write(
                "**Date:**",
                email_data["date"]
            )

        with col2:

            st.write(
                "**Reply-To:**",
                email_data["reply_to"]
            )

            st.write(
                "**Return-Path:**",
                email_data["return_path"]
            )

            st.write(
                "**Message-ID:**",
                email_data["message_id"]
            )


        # -------------------------------------------------
        # AUTHENTICATION
        # -------------------------------------------------

        st.subheader(
            "🔐 Authentication Analysis"
        )

        auth_col1, auth_col2, auth_col3 = st.columns(3)

        with auth_col1:

            st.metric(
                "SPF",
                authentication["spf"]
            )

        with auth_col2:

            st.metric(
                "DKIM",
                authentication["dkim"]
            )

        with auth_col3:

            st.metric(
                "DMARC",
                authentication["dmarc"]
            )

        if authentication["findings"]:

            with st.expander(
                "View Authentication Findings"
            ):

                for finding in authentication["findings"]:

                    st.write(
                        f"**{finding['severity']} — "
                        f"{finding['type']}**"
                    )

                    st.caption(
                        finding["evidence"]
                    )


        # -------------------------------------------------
        # URL ANALYSIS
        # -------------------------------------------------

        st.subheader(
            "🔗 URL Analysis"
        )

        if urls:

            for url in urls:

                st.code(
                    url
                )

            url_findings = [
                finding
                for finding in findings
                if "url" in finding
            ]

            if url_findings:

                with st.expander(
                    "URL Security Findings"
                ):

                    for finding in url_findings:

                        st.warning(
                            f"{finding['severity']} — "
                            f"{finding['type']}"
                        )

                        st.caption(
                            finding["evidence"]
                        )

        else:

            st.info(
                "No URLs found."
            )


        # -------------------------------------------------
        # IOC EXTRACTION
        # -------------------------------------------------

        st.subheader(
            "🔎 IOC Extraction"
        )

        ioc_col1, ioc_col2 = st.columns(2)

        with ioc_col1:

            st.write("**IP Addresses**")

            if iocs["ips"]:
                for ip in iocs["ips"]:
                    st.code(ip)
            else:
                st.caption("None detected.")

            st.write("**Domains**")

            if iocs["domains"]:
                for domain in iocs["domains"]:
                    st.code(domain)
            else:
                st.caption("None detected.")

        with ioc_col2:

            st.write("**Email Addresses**")

            if iocs["emails"]:
                for email in iocs["emails"]:
                    st.code(email)
            else:
                st.caption("None detected.")

            st.write("**Hashes**")

            if iocs["hashes"]:
                for file_hash in iocs["hashes"]:
                    st.code(file_hash)
            else:
                st.caption("None detected.")


        # -------------------------------------------------
        # SECURITY FINDINGS
        # -------------------------------------------------

        st.subheader(
            "🚨 Security Findings"
        )

        if findings:

            for finding in findings:

                severity = finding["severity"]

                if severity == "High":
                    st.error(
                        f"🔴 {severity} — "
                        f"{finding['type']}"
                    )

                elif severity == "Medium":
                    st.warning(
                        f"🟠 {severity} — "
                        f"{finding['type']}"
                    )

                elif severity == "Low":
                    st.info(
                        f"🟡 {severity} — "
                        f"{finding['type']}"
                    )

                else:
                    st.write(
                        f"{severity} — "
                        f"{finding['type']}"
                    )

                st.caption(
                    finding["evidence"]
                )

        else:

            st.success(
                "No suspicious findings detected."
            )


        # -------------------------------------------------
        # RISK ASSESSMENT
        # -------------------------------------------------

        st.subheader(
            "📊 Risk Assessment"
        )

        st.progress(
            risk["score"] / 100
        )

        if risk["level"] == "Critical":

            st.error(
                f"Critical Risk — "
                f"{risk['score']}/100"
            )

        elif risk["level"] == "High":

            st.error(
                f"High Risk — "
                f"{risk['score']}/100"
            )

        elif risk["level"] == "Medium":

            st.warning(
                f"Medium Risk — "
                f"{risk['score']}/100"
            )

        elif risk["level"] == "Low":

            st.info(
                f"Low Risk — "
                f"{risk['score']}/100"
            )

        else:

            st.success(
                f"Informational — "
                f"{risk['score']}/100"
            )

        st.caption(
            "Risk score is generated from deterministic "
            "security findings and is not a probability "
            "or confirmed verdict."
        )


        # -------------------------------------------------
        # MITRE ATT&CK
        # -------------------------------------------------

        st.subheader(
            "🎯 MITRE ATT&CK Mapping"
        )

        if mitre:

            for technique in mitre:

                st.markdown(
                    f"### {technique['technique_id']} — "
                    f"{technique['technique']}"
                )

                st.write(
                    f"**Tactic:** "
                    f"{technique['tactic']}"
                )

                st.write(
                    f"**Detection Trigger:** "
                    f"{technique['trigger']}"
                )

                st.caption(
                    f"Evidence: "
                    f"{technique['evidence']}"
                )

        else:

            st.info(
                "No deterministic MITRE ATT&CK "
                "mapping was generated."
            )


        # -------------------------------------------------
        # AI SOC COPILOT
        # -------------------------------------------------

        st.divider()

        st.subheader(
            "🤖 AI SOC Copilot"
        )

        investigation_data = {

            "email": email_data,

            "authentication": authentication,

            "urls": urls,

            "iocs": iocs,

            "findings": findings,

            "risk": risk,

            "mitre": mitre
        }

        with st.spinner(
            "PhishLens AI is investigating the evidence..."
        ):

            ai_result = ask_ollama(
                investigation_data
            )

        st.markdown(
            ai_result
        )


        # -------------------------------------------------
        # RAW INVESTIGATION DATA
        # -------------------------------------------------

        with st.expander(
            "🔎 View Complete Investigation Data"
        ):

            st.json(
                investigation_data
            )


        st.success(
            "Email investigation completed successfully."
        )