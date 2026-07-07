# SOAR Bridge Pipeline 🛡️

> **Portfolio project** — A lightweight, open-source Security Automation & Orchestration (SOAR) bridge built in Python. Ingests raw vulnerability alerts, uses Google Gemini AI to extract threat intelligence, maps behavior to MITRE ATT\&CK, and auto-generates both a structured Incident Ticket and a Sigma detection rule.

---

## 🔍 What This Does

```
[Mock Alert Data]
      │
      ▼
[Gemini AI Analysis]  ←── Structured system prompt (deterministic output)
      │
      ├──► Threat Vector Extraction
      ├──► MITRE ATT&CK Technique Mapping
      └──► IoC Identification (IPs, processes, files, network)
           │
           ├──► output/incident_ticket.md   (Markdown incident report)
           └──► output/detection_rule.yml   (Sigma YAML detection stub)
```

### Pipeline Stages

| Stage | Description |
|---|---|
| **1. Input** | Hardcoded mock alert dict — simulates a SIEM/EDR raw alert (CVE-2024-47177 / CUPS RCE) |
| **2. AI Analysis** | Gemini 2.0 Flash parses unstructured log text; extracts threat vector, consequence, and IoCs |
| **3. ATT\&CK Mapping** | LLM maps the behavior to a MITRE technique ID with a rationale |
| **4. Output A** | Structured Markdown Incident Ticket (Executive Summary + Technical Details + Actions) |
| **5. Output B** | YAML Sigma detection rule stub targeting the identified threat vector |

---

## ⚡ Quick Start

### Prerequisites
- Python 3.10+
- A free [Google Gemini API key](https://aistudio.google.com/app/apikey)

### 1. Clone & set up environment

```bash
# Windows (PowerShell)
cd C:\Users\YourName\Projects\soar-bridge
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# Linux / macOS
cd ~/Projects/soar-bridge
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set your API key

```powershell
# Windows PowerShell
$env:GEMINI_API_KEY = "your-actual-api-key-here"
```

```bash
# Linux / macOS
export GEMINI_API_KEY="your-actual-api-key-here"
```

### 3. Run the pipeline

```bash
python app.py
```

---

## 📂 Output Files

After a successful run, check the `output/` directory:

| File | Description |
|---|---|
| `output/incident_ticket.md` | Full incident report with executive summary, IoCs, and remediation steps |
| `output/detection_rule.yml` | Sigma-format YAML detection rule stub ready for SIEM tuning |

---

## 🧩 Mock Alert — CVE-2024-47177 (CUPS RCE)

The included mock alert simulates a **real-world, critical-severity** exploitation scenario:

- **Vulnerability**: OpenPrinting CUPS `cups-browsed` Remote Code Execution
- **CVSS Score**: 9.8 (Critical)
- **Attack Method**: Attacker-controlled IPP server injects malicious PPD `FoomaticRIPCommandLine` attribute → `cups-browsed` executes arbitrary command → reverse shell spawned
- **Impact**: Unauthenticated RCE, outbound C2 connection, file system persistence

This is a real CVE class published in late 2024, making the demo technically credible.

---

## 🗂️ Project Structure

```
soar-bridge/
├── app.py                  # Main pipeline script
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── output/                 # Auto-created on first run
    ├── incident_ticket.md  # Generated incident report
    └── detection_rule.yml  # Generated Sigma rule stub
```

---

## 🏗️ Architecture Decisions

### Why Gemini Flash?
- Fast inference, low cost, free tier available — ideal for a portfolio demo
- `temperature=0.1` ensures highly deterministic, repeatable output

### Why a JSON schema in the system prompt?
This is the core of **Detection-as-Code** thinking: by forcing the LLM to emit structured JSON, the downstream Python code can reliably parse it and render it into any format (Markdown, YAML, CSV, API payload) — exactly how enterprise SOAR connectors work.

### Why Sigma format?
[Sigma](https://sigmahq.io/) is the industry-standard, vendor-agnostic detection rule language. Rules can be compiled to Splunk SPL, Elastic KQL, Microsoft Sentinel KQL, and more via `sigma-cli`.

---

## 🔮 Potential Extensions

- [ ] Replace mock data with live feeds (VirusTotal API, Shodan, MISP)
- [ ] Add Jira/ServiceNow ticket creation via REST API
- [ ] Integrate `sigma-cli` to compile rules to Splunk/Elastic automatically
- [ ] Build a simple Flask/FastAPI web UI for the pipeline
- [ ] Add a vector DB for historical alert deduplication

---

## 📜 License

MIT — free to fork, modify, and showcase.
