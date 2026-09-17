# CASE-26 Sigma Detection Rules

Three Sigma rules authored against own red team activity in the Sliver C2 adversary emulation lab.
Tools: Sysmon (EventIDs 3, 10, 13) on Windows 11 Enterprise victim.

---

## Rule 1 -- Sliver C2 HTTPS Beacon Pattern (T1071.001)

```yaml
title: Sliver C2 HTTPS Beacon -- Periodic Connection to Single External Host
id: a1f3c2e4-7b89-4d01-bc34-e5f6a7890123
status: experimental
description: >
  Detects periodic HTTPS connections from a non-browser process to a single external
  destination on port 443, consistent with Sliver C2 beacon behavior. Sliver beacons
  use HTTPS with configurable jitter intervals; the pattern is low-frequency, regular,
  and originates from a process with no browser ancestry.
author: Ronan Kongala
date: 2026-09-17
references:
  - https://github.com/BishopFox/sliver
  - https://attack.mitre.org/techniques/T1071/001/
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    EventID: 3
    DestinationPort: 443
    Initiated: 'true'
  filter_browsers:
    Image|endswith:
      - '\chrome.exe'
      - '\firefox.exe'
      - '\msedge.exe'
      - '\iexplore.exe'
      - '\brave.exe'
      - '\opera.exe'
  filter_system:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
    Image|endswith:
      - '\svchost.exe'
      - '\MsMpEng.exe'
      - '\wuauclt.exe'
  condition: selection and not filter_browsers and not filter_system
falsepositives:
  - Legitimate update clients and background telemetry agents
  - Custom enterprise applications making HTTPS calls on a schedule
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1071
```

---

## Rule 2 -- Registry Run Key Persistence (T1547.001)

```yaml
title: Suspicious Registry Run Key Modification -- Persistence via Autostart
id: b2e4d6f8-9012-4e23-cd45-f6a7b8901234
status: experimental
description: >
  Detects writes to Windows registry Run keys used for persistence, where the
  executing image is not a known-good system binary or package manager. Adversaries
  use HKCU and HKLM Run keys to maintain persistence across reboots without requiring
  elevated privileges (HKCU) or with elevated privileges (HKLM).
author: Ronan Kongala
date: 2026-09-17
references:
  - https://attack.mitre.org/techniques/T1547/001/
logsource:
  product: windows
  category: registry_set
detection:
  selection:
    EventID: 13
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\'
      - '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\'
  filter_legitimate:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Program Files\'
      - 'C:\Program Files (x86)\'
    Image|endswith:
      - '\msiexec.exe'
      - '\OneDriveSetup.exe'
      - '\Teams.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Software installers legitimately adding run keys during setup
  - Group Policy or MDM-managed run key entries
level: high
tags:
  - attack.persistence
  - attack.t1547.001
  - attack.t1547
```

---

## Rule 3 -- LSASS Memory Access for Credential Dumping (T1003.001)

```yaml
title: Unauthorized Process Access to LSASS -- Credential Dumping Indicator
id: c3f5e7a9-0123-4f34-de56-a7b8c9012345
status: experimental
description: >
  Detects a process requesting PROCESS_VM_READ or PROCESS_ALL_ACCESS to lsass.exe,
  which is the primary indicator of Mimikatz-style credential dumping. Legitimate
  access to LSASS is restricted to security products (AV/EDR) and debugging tools.
  Access from unexpected processes is a high-confidence indicator of T1003.001.
author: Ronan Kongala
date: 2026-09-17
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://github.com/gentilkiwi/mimikatz
logsource:
  product: windows
  category: process_access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x143a'
      - '0x1fffff'
  filter_security_products:
    SourceImage|startswith:
      - 'C:\Program Files\Windows Defender\'
      - 'C:\Program Files\CrowdStrike\'
      - 'C:\Program Files\Carbon Black\'
      - 'C:\Windows\System32\lsass.exe'
      - 'C:\Windows\System32\werfault.exe'
      - 'C:\Windows\System32\taskmgr.exe'
  condition: selection and not filter_security_products
falsepositives:
  - EDR/AV products that inspect LSASS for detection purposes
  - Windows Error Reporting on LSASS crash
  - Debugging tools used by developers in authorized environments
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003
```

---

## Validation Notes

These rules were authored against own red team activity in CASE-26.
After lab execution, validate each rule against:
- Rule 1: Sysmon NetworkConnect logs during beacon check-in intervals
- Rule 2: Sysmon RegistryEvent logs after persistence step (T1547.001)
- Rule 3: Sysmon ProcessAccess logs after running Mimikatz against lsass.exe

Screenshot each rule hit for GitHub documentation (`screenshots/sigma_rule_1_hit.png` etc.)
