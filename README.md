# Air-Gapped SIEM Lab

A hands-on lab I built to learn SIEM operations for offline, internet-isolated environments - infrastructure setup, attack simulation, and detection, all documented as I went.

> ⚠️ All commands and detection tests in this project were run inside an isolated, air-gapped lab environment. Several of them (disabling Defender/Firewall, modifying `/etc/passwd`, GPO changes) are deliberately disruptive and should never be run on a production system.

## Why Air-Gapped?

A lot of real-world environments, especially the security-sensitive ones, are deliberately cut off from the internet to shrink the external attack surface. But that isolation just shifts the risk inward: with no external attacker to worry about, insider threats become the main concern.

On an air-gapped network, someone malicious or just careless can move around quietly, and if it isn't caught early, one suspicious action can snowball into a fully compromised network. Catching that first signal is really what this whole lab is about.

I built it around detecting things like:

- Adding a user to an admin/privileged group
- Suspicious process execution (e.g. encoded PowerShell commands)
- Unauthorized registry modifications
- Unexpected changes to file permissions or content
- Command-line execution patterns that don't match normal behavior

I only used internet access during initial staging - downloading agent installers and packages before a machine joined the isolated network (see `02-dc-setup.md`, `03-app-server-setup.md`, `04-windows-client-setup.md` for exactly how each machine was staged). The detection rules themselves all assume zero internet connectivity by design - no cloud threat intel, no external enrichment. I also mapped each rule to a control from Saudi Arabia's NCA Essential Cybersecurity Controls (ECC-2:2024) - see [`detection-rules-checklist.md`](detection-rules-checklist.md) for the full list.

## Goal

Build a small, isolated Active Directory + Wazuh SIEM environment to practice log collection, detection engineering, and incident analysis, and document the whole process as a public portfolio project.

## Architecture

Four VMs on a single isolated host-only network (`192.168.50.0/24`):

| VM | Role | OS | IP |
|---|---|---|---|
| DC01 | Domain Controller | Windows Server | 192.168.50.131 |
| WIN-CLIENT | Domain-joined workstation | Windows 10 | 192.168.50.129 |
| APP01 | Application server | Ubuntu Server | 192.168.50.130 |
| SIEM-SRV | Wazuh (manager + indexer + dashboard) | Ubuntu / Wazuh OVA | 192.168.50.132 |

All VMs run on VMware Workstation, isolated from the outside network (Host-only VMnet).

## Tools Used

- **Hypervisor:** VMware Workstation Pro
- **SIEM:** Wazuh 4.14.7
- **Directory Services:** Active Directory Domain Services

## Documentation Index

- [01 - Network Setup](01-network-setup.md)
- [02 - Domain Controller Setup](02-dc-setup.md)
- [03 - Application Server Setup](03-app-server-setup.md)
- [04 - Windows Client Setup](04-windows-client-setup.md)
- [05 - Wazuh (SIEM) Setup](05-wazuh-setup.md)
- [06 - Sysmon Setup](06-sysmon-setup.md)
- [07 - Wazuh SCA (CIS Benchmarks)](07-sca-hardening.md)
- [Decision Log](decision-log.md) - why each major tool/design choice was made
- [Detection Rules Checklist](detection-rules-checklist.md) - 27 rules, build order, progress tracker
- [Screenshot Guide](screenshot-guide.md) - what to capture at each stage

## Status

🟢 Infrastructure up and running - DC, App server, Windows client, and Wazuh dashboard all operational.
🟢 26 of 27 detection rules built, tested end-to-end, and documented - Active Directory (1-10), Windows Client/Sysmon (11-21), Ubuntu App Server (22-25), and Detection Pipeline Integrity (26-27).
🟡 Rule #13 is built and its logic is verified, but not tested end-to-end against a genuine external destination - the lab network is fully air-gapped, so there's no way to simulate real outbound traffic. Details in `rules/rule-13-external-connection.md`.
🟢 Project complete.

## Disclaimer

This lab is fully isolated and does not reflect any production environment. All hostnames, IPs, and configurations are lab-only.
