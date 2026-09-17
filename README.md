# Authorized Penetration Test — Metasploit Lab

## Scope and Authorization

**All targets used in this project are explicitly authorized:**

| Target | IP | Authorization Basis |
|---|---|---|
| Metasploitable2 | 192.168.3.130 | Self-hosted VM on isolated host-only network. Intentionally vulnerable by design — created specifically for security training. |
| TryHackMe "Blue" | 10.65.159.150 | Authorized lab environment. TryHackMe Terms of Service explicitly permit full exploitation of lab machines. |

**No production systems, real organizations, or unauthorized targets were accessed at any point during this project.**

---

## Objective

Conduct an authorized penetration test against two intentionally vulnerable targets, exploit known vulnerabilities using Metasploit Framework, and produce a structured pentest report in the same format used in professional vulnerability disclosure — including CVSS scoring, MITRE ATT&CK mapping, reproduction steps, and remediation recommendations.

---

## Findings Summary

| # | Vulnerability | CVE | CVSS | Severity | Target |
|---|---|---|---|---|---|
| 1 | vsftpd 2.3.4 Backdoor RCE | CVE-2011-2523 | 10.0 | CRITICAL | 192.168.3.130 |
| 2 | Samba usermap_script RCE | CVE-2007-2447 | 10.0 | CRITICAL | 192.168.3.130 |
| 3 | rexec Cleartext Auth Service | N/A | 7.5 | HIGH | 192.168.3.130 |
| 4 | MS17-010 EternalBlue SMB RCE | CVE-2017-0144 | 9.8 | CRITICAL | 10.65.159.150 |

**Result:** Both targets fully compromised (root / NT AUTHORITY\SYSTEM) via unpatched publicly known vulnerabilities.

---

## Tools Used

- Metasploit Framework v6.4
- Nmap 7.99
- Kali Linux 2026.2
- TryHackMe AttackBox

---

## Reconnaissance

### Nmap — Targeted Port Scan
![Nmap targeted scan](metasploitable2/screenshots/nmap_targeted.png)

### Nmap — Full Port Scan (Key Services)
![Nmap full scan](metasploitable2/screenshots/nmap_full_scan_top.png)

---

## Finding 1 — vsftpd 2.3.4 Backdoor (CVE-2011-2523)

**Severity:** CRITICAL | **CVSS:** 10.0 | **MITRE:** T1190

vsftpd 2.3.4 contains a backdoor introduced into the source code by a malicious actor. Sending a username ending in `:)` triggers a root shell on port 6200. Exploited via `exploit/unix/ftp/vsftpd_234_backdoor`.

![Finding 1 — vsftpd root shell](metasploitable2/screenshots/finding1_vsftpd_root.png)

**Result:** `uid=0(root) gid=0(root)`

---

## Finding 2 — Samba usermap_script RCE (CVE-2007-2447)

**Severity:** CRITICAL | **CVSS:** 10.0 | **MITRE:** T1210

Samba 3.0.20 allows unauthenticated command injection via shell metacharacters in the username field when `username map script` is enabled. Exploited via `exploit/multi/samba/usermap_script`.

![Finding 2 — Samba root shell](metasploitable2/screenshots/finding2_samba_root.png)

**Result:** `uid=0(root) gid=0(root)`

---

## Finding 3 — rexec Cleartext Authentication Service

**Severity:** HIGH | **CVSS:** 7.5 | **MITRE:** T1021

The rexec service (TCP port 512) is running and transmits credentials in cleartext. Any network observer can capture credentials via packet capture. Confirmed via Metasploit `auxiliary/scanner/rservices/rexec_login`.

![Finding 3 — rexec service](metasploitable2/screenshots/finding3_rexec.png)

---

## Finding 4 — MS17-010 EternalBlue SMB RCE (CVE-2017-0144)

**Severity:** CRITICAL | **CVSS:** 9.8 | **MITRE:** T1210

Windows Server 2008 R2 unpatched against MS17-010. EternalBlue exploits a buffer overflow in SMBv1 to achieve unauthenticated remote code execution at SYSTEM level. Exploited via `exploit/windows/smb/ms17_010_eternalblue`.

### Vulnerability Verified
![MS17-010 verified](thm_blue/screenshots/thm_blue_ms17010_verified.png)

### SYSTEM Access Achieved
![EternalBlue SYSTEM](thm_blue/screenshots/finding4_eternalblue_system.png)

**Result:** `NT AUTHORITY\SYSTEM`

---

## Repository Structure

```
metasploit-pentest-report/
├── README.md
├── reports/
│   └── pentest_report_v1.docx
├── metasploitable2/
│   └── screenshots/
│       ├── lab_setup_metasploitable_ip.png
│       ├── nmap_targeted.png
│       ├── nmap_full_scan_top.png
│       ├── nmap_full_scan_bottom.png
│       ├── msfconsole_launch.png
│       ├── finding1_vsftpd_root.png
│       ├── finding2_samba_root.png
│       └── finding3_rexec.png
└── thm_blue/
    └── screenshots/
        ├── thm_blue_nmap.png
        ├── thm_blue_ms17010_verified.png
        └── finding4_eternalblue_system.png
```

---

## Report

The full structured pentest report (with detailed reproduction steps, evidence, business impact, and remediation for all 4 findings) is available in [`reports/pentest_report_v1.docx`](reports/pentest_report_v1.docx).
