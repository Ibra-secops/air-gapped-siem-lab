# Detection Rules - Implementation Checklist (27 Rules)

A list of real rules, each tied to a specific log source, event ID, and the NCA Essential Cybersecurity Controls (ECC-2:2024) control it supports. Ordered by log source so you can build them step by step (easiest first).

**Status:** ☐ Not built | ⚙️ In progress | ✅ Built and tested

---

## Active Directory / Domain Controller (Windows Event Log)

| # | Rule | Event ID | ECC Control | Status |
|---|---|---|---|---|
| 1 | User added to Domain Admins group | 4728 | 2-2-3-3, 2-2-3-4, 2-12-3-2 | ✅ |
| 2 | New domain user account created | 4720 | 2-2-3-1, 2-12-3-1 | ✅ |
| 3 | User account deleted | 4726 | 2-2-3-5, 2-12-3-1 | ✅ |
| 4 | Admin account password changed | 4724 | 2-2-3-2, 2-12-3-2 | ✅ |
| 5 | Disabled account re-enabled | 4722 | 2-2-3-5, 2-12-3-2 | ✅ |
| 6 | Repeated failed logon attempts (brute-force) | 4625 (5+ within 5 min) | 2-2-3-2, 2-12-3-4 | ✅ |
| 7 | Successful logon outside working hours | 4624 (time-filtered) | 2-12-3-4 | ✅ |
| 8 | GPO changed outside normal maintenance window | 5136 | 2-12-3-1 | ✅ |
| 9 | Event log cleared (covering tracks) | 1102 | 2-12-3-1, 2-12-3-4 | ✅ |
| 10 | Access to admin share (ADMIN$/C$) | 5140 | 2-2-3-3 | ✅ |

## Windows Client / Sysmon (after install)

> Note: Rules #15-#20 use native Windows Event Log auditing (Security /
> Windows Defender logs) or Wazuh FIM rather than Sysmon directly - Sysmon
> (#11-14, #21) and native auditing both require WIN-CLIENT to be fully
> configured, which is why they're grouped together here. See the new "Log
> Source" column below for the exact source of each rule.

| # | Rule | Event ID | Log Source | ECC Control | Status |
|---|---|---|---|---|---|
| 11 | Encoded PowerShell execution (`-EncodedCommand`) | 1 (Process Creation) | Sysmon | 2-3-3-1, 2-12-3-1 | ✅ |
| 12 | Process created from an unusual path (e.g. Temp) | 1 | Sysmon | 2-3-3-1 | ✅ |
| 13 | Unexpected outbound network connection (shouldn't happen at all) | 3 (Network Connection) | Sysmon | 2-5-3-5 | 🟡 |
| 14 | Registry value changed in a sensitive path (Run keys - persistence) | 13 (Registry Value Set) | Sysmon | 2-3-3-1 | ✅ |
| 15 | Scheduled task created or modified | 1 + Event 4698 | Sysmon + Windows Event Log (Security) | 2-3-3-1 | ✅ |
| 16 | New service created on the system | 4697 / Sysmon 1 | Windows Event Log (System) / Sysmon | 2-3-3-1 | ✅ |
| 17 | New USB device connected | Windows Event 6416 | Windows Event Log (Security) | 2-3-3-2 | ✅ |
| 18 | Large number of files copied to USB in a short time | FIM + disk monitoring | Wazuh FIM (syscheck) | 2-3-3-2 | ✅ |
| 19 | Windows Defender disabled | Event 5001 | Windows Event Log (Windows Defender) | 2-3-3-1 | ✅ |
| 20 | Windows Firewall disabled | Event 4950 | Windows Event Log (Security) | 2-3-3-1 | ✅ |
| 21 | Lateral movement via remote command execution (WinRM - PsExec alternative) | Sysmon 1 (parent process wsmprovhost.exe) | Sysmon | 2-2-3-2 | ✅ |

## Ubuntu App Server

| # | Rule | Source | ECC Control | Status |
|---|---|---|---|---|
| 22 | Repeated failed SSH attempts | `/var/log/auth.log` | 2-2-3-2, 2-12-3-4 | ✅ |
| 23 | Sensitive file modified (e.g. `/etc/passwd` or app config file) | Wazuh FIM | 2-7 (Data & Information Protection) | ✅ |
| 24 | Backend application file changed (added/modified/deleted) | Wazuh FIM | 2-7 (Data & Information Protection) | ✅ |
| 25 | Data exfiltration via file transfer tools (scp/curl/wget/rsync/nc) | Linux Audit Daemon (auditd) | 2-7, 2-5-3-5 | ✅ |

## Detection Pipeline Integrity

| # | Rule | Source | ECC Control | Status |
|---|---|---|---|---|
| 26 | Wazuh agent stopped sending data | Wazuh Manager (agent status) | 2-12-3-4 | ✅ |
| 27 | Manual system clock change | Event 4616 | 2-3-3-4 (Clock Synchronization) | ✅ |

---

## About the ECC Control column

Each rule is mapped to a control from the Saudi National Cybersecurity Authority's Essential Cybersecurity Controls (ECC-2:2024) - the current official baseline, replacing ECC-1:2018. Full control text: nca.gov.sa.

## How to document each rule

Each rule gets its own file, e.g. `rule-01-admin-group-add.md`, following the structure used across `rules/rule-01-*.md` through `rules/rule-27-*.md`: Overview, Field/Value table, build steps, evidence, lessons learned, status.

## Suggested build order

1. Start with **AD rules (1-10)** - they use plain Windows Event Log, no Sysmon needed, fastest to get working.
2. Install **Sysmon** on WIN-CLIENT (and DC if you want), then do rules 11-21.
3. **Ubuntu rules (22-25)** in parallel, since they're independent of Windows.
4. **Pipeline integrity rules (26-27)** last - you need working agents first to test them.

**Realistic goal:** Don't try to build all of them in one sitting. 2-3 fully documented, well-tested rules per day is better than 10 rushed ones with no real false-positive testing.
