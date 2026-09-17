# Red Team Assessment Report
## CASE-26: Sliver C2 Adversary Emulation Lab

**Classification:** Simulated / Educational Lab  
**Assessment Date:** 2026-09-17  
**Prepared by:** Ronan Kongala  
**Environment:** Isolated VMware NAT network  
**Attacker:** REMnux 192.168.93.137  
**Victim:** Windows 11 Enterprise (90-day eval, IP: [FILL AFTER INSTALL])  
**C2 Framework:** Sliver v1.7.7  

---

## 1. Executive Summary

This report documents a full-chain adversary emulation exercise performed against a Windows 11 Enterprise target in an isolated lab environment. The assessment simulated a threat actor who obtained initial access and progressed through persistence, privilege escalation, credential dumping, lateral movement, and exfiltration using the Sliver C2 framework.

**Techniques executed:** 7 MITRE ATT&CK techniques across 6 tactics  
**Credentials obtained:** [FILL -- e.g., 2 NTLM hashes, 1 plaintext password]  
**Persistence mechanisms established:** 1 (registry run key)  
**Privilege level achieved:** SYSTEM  
**Detection rules authored:** 3 Sigma rules  

**Key finding:** A single HTTPS beacon executed with standard user privileges was sufficient to achieve SYSTEM context, dump credentials, and simulate data exfiltration -- all over a single encrypted C2 channel that blends with normal HTTPS traffic.

---

## 2. Assessment Scope and Rules of Engagement

| Parameter | Value |
|---|---|
| Scope | Single Windows 11 Enterprise VM on isolated VMware NAT subnet |
| Out of scope | Host machine, internet, production systems |
| Network | 192.168.93.x VMware NAT only |
| Authorization | Self-authorized lab environment -- no production systems affected |
| Constraints | No destructive payloads; no real credential exfiltration beyond VM boundary |
| Objectives | Execute full kill chain, document 7+ ATT&CK techniques, author detection rules |

---

## 3. Attack Narrative

### Phase 1 -- Initial Access and C2 Establishment

**Technique:** T1204.002 -- User Execution: Malicious File  
**Technique:** T1071.001 -- Application Layer Protocol: Web Protocols  

The attacker compiled a Sliver HTTPS beacon (`CASE26-beacon.exe`) on REMnux using the Sliver C2 server running as a systemd service on port 443. The beacon used symbol obfuscation and compiled in 4m11s for the windows/amd64 target architecture.

The beacon was transferred to the victim machine via [FILL -- HTTP/SMB/RDP file copy]. Upon execution by the victim user, the beacon established an encrypted HTTPS callback to the REMnux listener (192.168.93.137:443) with a 60-second beacon interval.

**Evidence:**
- Sliver console: `[*] Beacon CASE26-beacon ([FILL session ID]) -- [FILL victim IP]`
- Sysmon EventID 3: outbound connection from [beacon process] to 192.168.93.137:443
- Screenshot: [FILL -- 04_beacon_connecting.png]

---

### Phase 2 -- Persistence

**Technique:** T1547.001 -- Boot or Logon Autostart Execution: Registry Run Keys  

From the active Sliver beacon session, a registry run key was written to maintain persistence across reboots without elevated privileges.

**Command executed:**
```
[FILL -- Sliver registry command or shell command used]
```

**Registry artifact:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: [FILL]
Data: [FILL -- path to beacon executable]
```

**Evidence:**
- Sysmon EventID 13: registry value set on target key
- Screenshot: [FILL -- 05_persistence_registry.png]

---

### Phase 3 -- Privilege Escalation

**Technique:** T1134.001 -- Access Token Manipulation: Token Impersonation/Theft  

With an established beacon session, privilege escalation was performed using Sliver's built-in `getsystem` command, which uses named pipe impersonation to steal a SYSTEM token.

**Command executed:**
```
getsystem
```

**Result:** [FILL -- e.g., "Elevated to NT AUTHORITY\SYSTEM"]

**Evidence:**
- Sliver console output showing SYSTEM context
- Screenshot: [FILL -- 06_privesc_system.png]

---

### Phase 4 -- Credential Dumping

**Technique:** T1003.001 -- OS Credential Dumping: LSASS Memory  

From SYSTEM context, Mimikatz was executed to dump credentials from LSASS memory.

**Commands executed:**
```
[FILL -- method of delivering mimikatz: execute-assembly, shell, etc.]
sekurlsa::logonpasswords
```

**Credentials obtained:**
| Account | Type | Hash/Password |
|---|---|---|
| [FILL] | NTLM | [FILL -- redact in public repo] |
| [FILL] | Plaintext | [FILL -- redact in public repo] |

**Evidence:**
- Mimikatz output showing credential dump
- Sysmon EventID 10: process access to lsass.exe with GrantedAccess 0x1010
- Screenshot: [FILL -- 07_mimikatz_dump.png]

---

### Phase 5 -- Lateral Movement

**Technique:** T1550.002 -- Use Alternate Authentication Material: Pass the Hash  

The NTLM hash obtained from the credential dump was used to authenticate to a remote service on the victim without requiring the plaintext password.

**Command executed:**
```
[FILL -- pth command used, tool, target]
```

**Result:** [FILL -- e.g., "Authenticated to \\victim\C$ as [user] via PtH"]

**Evidence:**
- Screenshot: [FILL -- 08_pass_the_hash.png]

---

### Phase 6 -- Exfiltration Simulation

**Technique:** T1041 -- Exfiltration Over C2 Channel  

Simulated sensitive files (staged on the victim for demonstration purposes) were transferred back to the REMnux C2 server over the existing Sliver HTTPS beacon channel.

**Files exfiltrated (simulated):**
- `credentials.txt` -- simulated credential store
- `network-topology.txt` -- simulated internal network map

**Command executed:**
```
download C:\Users\[user]\Documents\credentials.txt
```

**Evidence:**
- Sliver download confirmation
- File received on REMnux at /tmp/
- Screenshot: [FILL -- 09_exfiltration.png]

---

## 4. Technical Findings Summary

| # | Technique ID | Technique Name | Tactic | Severity | Evidence Artifacts |
|---|---|---|---|---|---|
| 1 | T1204.002 | User Execution: Malicious File | Execution | High | beacon.exe execution, Sysmon process create |
| 2 | T1071.001 | Application Layer Protocol: Web Protocols | C2 | High | Sysmon network connection EventID 3 |
| 3 | T1547.001 | Registry Run Keys | Persistence | High | Sysmon registry set EventID 13 |
| 4 | T1134.001 | Token Impersonation | Privilege Escalation | Critical | Sliver getsystem output |
| 5 | T1003.001 | LSASS Memory Dump | Credential Access | Critical | Mimikatz output, Sysmon EventID 10 |
| 6 | T1550.002 | Pass the Hash | Lateral Movement | Critical | PtH authentication log |
| 7 | T1041 | Exfil Over C2 Channel | Exfiltration | High | Sliver download log, file on REMnux |

---

## 5. Detection Recommendations

### Host-Based

| Detection | Rule | Data Source |
|---|---|---|
| HTTPS beacon from non-browser | Sigma Rule 1 (sigma-rules.md) | Sysmon EventID 3 |
| Registry run key write | Sigma Rule 2 (sigma-rules.md) | Sysmon EventID 13 |
| LSASS memory access | Sigma Rule 3 (sigma-rules.md) | Sysmon EventID 10 |
| Mimikatz privilege keywords | YARA rule on memory/disk | Memory forensics |
| Unexpected SYSTEM token | EDR behavioral rule | Windows Security Event 4672 |

### Network-Based

| Detection | Method |
|---|---|
| C2 beacon timing regularity | Network flow analysis -- low-variance intervals to single IP on 443 |
| HTTPS to non-CDN IP on 443 | DNS + SSL cert inspection -- Sliver uses self-signed cert |
| Large outbound transfers during off-hours | DLP / NetFlow anomaly detection |

### Recommended Controls

1. **EDR tuning** -- Alert on any process accessing lsass.exe that is not in the approved security product allowlist
2. **AppLocker / WDAC** -- Block execution of unsigned binaries from user-writable paths
3. **Credential Guard** -- Enable to prevent LSASS credential dumping even with SYSTEM access
4. **Network segmentation** -- Limit workstation-to-workstation traffic to prevent lateral movement
5. **SSL inspection** -- Inspect HTTPS traffic at the proxy layer to detect self-signed C2 certificates

---

## 6. ATT&CK Coverage

Layer file: `attck-navigator-layer.json`  
Navigator URL: https://mitre-attack.github.io/attack-navigator/  
Import the JSON to visualize 7 techniques across 6 tactics.

Tactics covered: Execution, Command and Control, Persistence, Privilege Escalation, Credential Access, Lateral Movement, Exfiltration

---

## 7. Conclusion

The lab demonstrated that a single HTTPS beacon -- indistinguishable from normal web traffic at the packet level -- can serve as a complete attack platform from initial access through data exfiltration. Standard perimeter controls (firewall, AV signature scanning) did not prevent any stage of the kill chain. Detection required behavioral rules (EDR process access monitoring, network flow timing analysis) rather than signature-based defenses.

All activity was performed in an isolated lab environment with no production systems, real credentials, or internet connectivity involved.

---

*Report generated: 2026-09-17 | CASE-26 | github.com/ronankongala/red-team-c2-lab*
