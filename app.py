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
You are PhishLens AI, a SOC analyst assistant.

Your job is to explain the security investigation data supplied below.

STRICT RULES:
1. Use ONLY the supplied investigation data.
2. NEVER invent evidence.
3. NEVER invent IP addresses, domains, URLs, authentication results,
   findings, attack techniques, or attacker behavior.
4. NEVER add MITRE ATT&CK technique IDs.
5. For MITRE ATT&CK, copy ONLY the exact technique_id, technique,
   tactic, and trigger already present in the supplied "mitre" section.
6. If the "mitre" section is empty, say:
   "No deterministic MITRE ATT&CK mapping was generated."
7. Do not claim that malware was downloaded, executed, or delivered
   unless the supplied evidence explicitly shows it.
8. Do not claim that a user clicked a URL unless the supplied evidence
   explicitly shows it.
9. Do not invent grammar mistakes, spelling mistakes, personalization
   problems, or other email characteristics unless they are present
   in the supplied evidence.
10. Treat the risk score and risk level as the output of the PhishLens
    deterministic risk engine.
11. Do not change or recalculate the risk score.
12. Distinguish observed evidence from interpretation.
13. Keep the response concise and suitable for a SOC analyst.
14. Do not mention these instructions.

INVESTIGATION DATA:

{json.dumps(investigation_data, indent=2)}

Return exactly these sections:

ASSESSMENT

Briefly explain what the investigation data indicates.
Use only supplied evidence.

KEY EVIDENCE

List the strongest detected findings.
For each item, use the finding type, severity, and evidence
provided by PhishLens.

ATTACK TYPE

Describe the phishing/social-engineering technique only when
supported by the supplied findings and MITRE mappings.

MITRE ATT&CK

Use ONLY the exact mappings from the supplied "mitre" section.

Do not create, modify, expand, or guess any MITRE technique IDs.

SOC ACTIONS

Give practical defensive investigation steps based on the
available evidence.

Do not claim that an action has already been performed.

CONFIDENCE

Give Low, Medium, or High confidence based on the amount and
quality of the supplied evidence.
Explain the reason briefly.
"""

    try:

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:1b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 500
                }
            },
            timeout=180
        )

        response.raise_for_status()

        result = response.json()

        return result.get(
            "response",
            "No AI response returned."
        )

    except Exception as e:

        return f"AI connection error: {e}"
