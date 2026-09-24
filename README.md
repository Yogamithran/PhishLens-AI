# 🛡️ PhishLens AI

## AI-Assisted Phishing Email Investigation Platform

PhishLens AI is a cybersecurity investigation platform for analyzing suspicious emails using explainable security rules and a local AI SOC Copilot.

## 🚀 Features

- Email header investigation
- SPF / DKIM / DMARC analysis
- Suspicious URL detection
- IOC extraction
- Explainable risk scoring
- Evidence-based MITRE ATT&CK mapping
- Local Ollama AI SOC Copilot
- Security findings and investigation evidence
- Streamlit cybersecurity dashboard

## 🏗️ Architecture

```text
Email Input
     │
     ▼
Email Parser
     │
     ├── Header Analysis
     ├── SPF / DKIM / DMARC
     ├── URL Intelligence
     └── IOC Extraction
              │
              ▼
       Explainable Risk Engine
              │
              ▼
       MITRE ATT&CK Mapping
              │
              ▼
       Local AI SOC Copilot
              │
              ▼
       Investigation Dashboard
