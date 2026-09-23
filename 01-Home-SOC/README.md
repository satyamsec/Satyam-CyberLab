
# 🛡️ Project 01: Home SOC Lab

**A hands-on Security Operations Center lab built with VirtualBox, Ubuntu, Wazuh, Sysmon, and Suricata — covering infrastructure design, endpoint & network monitoring, attack simulation, and detection engineering.**

| | |
|---|---|
| **Analyst** | Satyam Singh |
| **Type** | Home-built SOC lab (portfolio / learning project) |
| **Compiled** | September 23, 2026 |
| **Status** | Phases 1–8 Complete · Phase 9 Drafted (Deferred) |
| **Environment** | Oracle VirtualBox · 3 guest VMs on 1 host |

> 📄 **[Download the full 23-page report (.docx)](./Home-SOC-Lab-Full-Report.docx)** — includes all screenshots and detailed evidence.

---

## 📖 Executive Summary

This project is a consolidated record of a home-built Security Operations Center (SOC) lab, developed for hands-on blue-team practice. It follows a 10-phase roadmap: designing an isolated lab network, standing up a Wazuh SIEM, building Windows and Linux victim endpoints, deploying Sysmon and Suricata for telemetry and network intrusion detection, generating simulated attack activity, investigating the resulting alerts, and engineering custom detection rules.

**Key achievement:** Built a fully functional detection pipeline that ingested both endpoint telemetry (Sysmon, Linux PAM) and network traffic (Suricata) into a central Wazuh SIEM, then verified it end-to-end by simulating attacks and investigating the resulting alerts — producing **three formal incident reports**.

A significant and recurring theme throughout the build was **methodical troubleshooting**: every VM networking issue, service crash, typo, and misconfiguration was diagnosed to root cause and resolved rather than worked around.

---

## 🏗️ Architecture

Each VM runs **two network adapters**:

| Adapter | Type | Purpose |
|---|---|---|
| Adapter 1 | NAT | Internet access (updates, package installs) |
| Adapter 2 | Host-Only (192.168.56.0/24) | Private lab network — all VM-to-VM traffic |

> **Note:** The Host-Only network's DHCP server was **disabled** in favor of static IPs, preventing addresses from silently changing on reboot and breaking agent connectivity.

### Machine Roles

| Machine | OS | Role | IP Address |
|---|---|---|---|
| **Wazuh-Server** | Ubuntu 24.04 LTS | SIEM (Indexer, Manager, Dashboard) | `192.168.56.10` |
| **Windows-Victim** | Windows 10 Pro | Endpoint target (Sysmon + Agent 001) | `192.168.56.20` |
| **Linux-Victim** | Ubuntu Server 24.04 | Endpoint target (Agent 002) | `192.168.56.30` |

---

## 📋 Phase Status

| # | Phase | Status |
|---|---|---|
| 1 | Lab Network Design | ✅ Complete |
| 2 | Wazuh Server Build | ✅ Complete |
| 3 | Windows Victim & Agent Enrollment | ✅ Complete |
| 4 | Sysmon Installation & Detection | ✅ Complete |
| 5 | Linux Victim VM | ✅ Complete |
| 6 | Suricata (Network IDS) | ✅ Complete |
| 7 | Generate Events & Verify Detection | ✅ Complete |
| 8 | Investigate Alerts | ✅ Complete |
| 9 | Detection Engineering | ⏸️ Drafted (Deferred) |
| 10 | Documentation | ✅ Complete |

---

## 🔍 Incident Reports

Three formal investigations were completed, each following real SOC methodology (identify host → examine evidence → classify → map to MITRE ATT&CK → recommend response).

### 📌 IR-001 — Encoded PowerShell Execution

| Field | Value |
|---|---|
| **Date** | September 14, 2026 |
| **Host** | Windows-Victim (Agent 001) |
| **Detection Source** | Sysmon → Wazuh |
| **Wazuh Rule** | 92057 (Level 12 — High) |
| **MITRE ATT&CK** | T1059.001 — Command & Scripting Interpreter (PowerShell) |
| **Verdict** | ✅ Benign — Authorized simulation |

A base64-encoded PowerShell command (`-EncodedCommand`) was executed on Windows-Victim. Sysmon captured the full command line and Wazuh's decoder matched the encoded pattern — confirming the pipeline works end-to-end.

```powershell
powershell -EncodedCommand VwByAGkAdAB1AC0ASABvAHMAdAAGAcc...
# Decoded: Write-Host 'Hello from a simulated event'
Full details → Download the full report · Section 9.1

📌 IR-002 — Custom Suricata ICMP Rule
Field	Value
Host	Linux-Victim → Windows-Victim
Detection Source	Suricata → Wazuh
Signature ID	1000001
Verdict	✅ Benign — Test rule
A custom Suricata rule was written to detect ICMP traffic on the Host-Only interface. Getting it to fire required resolving three compounding issues (rule not referenced in config, stray YAML characters, wrong rule directory).

suricata
alert icmp any any -> any any (msg:"SOC-LAB TEST ALERT - ICMP Detected"; sid:1000001; rev:1;)
Full details → Download the full report · Section 9.2

📌 IR-003 — Ransomware Simulation (FIM)
Field	Value
Host	Windows-Victim (Agent 001)
Detection Source	Wazuh Syscheck (File Integrity Monitoring)
Detection Rule	554 (generic — "File added to the system")
Verdict	✅ Benign — Simulated attack
A custom Python ransomware simulator created dummy .locked files and a HOW_TO_DECRYPT.txt ransom note in %TEMP%\ransim_demo. Wazuh FIM detected every file drop with full forensic metadata (SHA1, size, owner, Windows ACL).

The honest gap: Detection relied on Wazuh's generic rule 554 rather than a purpose-built ransomware signature. This directly motivated the Phase 9 rules drafted below.

Full details → Download the full report · Section 9.3

🧪 Detection Engineering (Phase 9 — Drafted)
Four custom Wazuh rules were drafted to move beyond generic detection — turning a raw "file added" event into a named, high-severity ransomware alert. These were scoped and reviewed but not implemented (deliberate decision).

Rule 100002 (level 12): Detects .locked files.

xml
<rule id="100002" level="12">
  <if_sid>554</if_sid>
  <field name="file" type="pcre2">\.locked$</field>
  <description>Ransomware indicator: file encrypted with .locked extension on $(file)</description>
</rule>
Rule 100003 (level 12): Detects HOW_TO_DECRYPT.txt ransom notes.

xml
<rule id="100003" level="12">
  <if_sid>554</if_sid>
  <field name="file" type="pcre2">HOW_TO_DECRYPT\.txt$</field>
  <description>Ransomware indicator: ransom note dropped on $(file)</description>
</rule>
Rule 100004 (level 15): Correlation rule — escalates to confirmed ransomware if both rules fire on the same host within 120 seconds.

xml
<rule id="100004" level="15" frequency="2" timeframe="120">
  <if_matched_sid>100002</if_matched_sid>
  <if_sid>100003</if_sid>
  <same_source_ip />
  <description>RANSOMWARE ATTACK CONFIRMED: encrypted files + ransom note detected on same host within 2 minutes</description>
</rule>
Full details → Download the full report · Section 11

🔧 Troubleshooting Highlights
33 distinct problems were encountered and resolved during this build. The full log is in the report — here are the most instructive:

#	Problem	Root Cause	Fix
18	wazuh-manager crashed; agent connections refused	Root filesystem 100% full (6.9 GB Vulnerability Detector cache)	Cleared stale cache; freed 13 GB; restarted
20	Disk filled again shortly after	vd/feed regrew	Permanently disabled Vulnerability Detector
26	nmap scan produced no Suricata alert	rules_loaded: 0 — no ruleset installed	Ran suricata-update
28	Custom Suricata rule never fired	local.rules never added to suricata.yaml	Added explicitly to rule-files list
29	Suricata config failed to parse	Stray "aa" characters in YAML	Located and removed with nano
💡 Key lesson: A full disk can silently masquerade as a networking problem. Always check df -h early when a service crashes.

Full log → Download the full report · Section 13

🎯 Skills Demonstrated
SOC Operations — Log ingestion, alert triage, incident documentation

Detection Engineering — Wazuh rule authoring, Suricata signatures, MITRE ATT&CK mapping

Endpoint Security — Sysmon configuration, File Integrity Monitoring (FIM)

Network Security — IDS deployment, packet analysis, nmap, Wireshark fundamentals

Infrastructure — VirtualBox networking, Netplan, static IP management

Root-Cause Troubleshooting — Systematic diagnosis of 33 distinct issues

⚠️ Ethics & Safety
All security testing documented in this project was performed in controlled, isolated lab environments against systems I own. No unauthorized testing was conducted. The ransomware simulation tool is non-destructive — it creates dummy files only and performs no real encryption.

Full 23-page report with all screenshots and command-level evidence:
📄 Home-SOC-Lab-Full-Report.docx
