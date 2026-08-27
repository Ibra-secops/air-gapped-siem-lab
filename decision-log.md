# Decision Log

Key project-level decisions - what happened and what it taught. Rule-specific decisions and troubleshooting live in each rule's own **Lessons Learned** section (`rules/rule-XX-*.md`).

---

**Wazuh over ELK or Splunk.** Chose Wazuh as a single ready-to-deploy appliance instead of building ELK from scratch or hitting Splunk's 500MB/day free-tier cap. Confirmed working by checking all three services (indexer, manager, dashboard) and built-in MITRE ATT&CK mappings on the dashboard.

**Built around a "no internet" assumption from day one.** The network, the rules, everything assumes zero internet access - a more realistic model for security-sensitive isolated environments, where insider threats (not external attackers) are the real risk. No Kali/attacker VM was used, since external-attack techniques (phishing, C2) don't apply once internet is removed.

**Mapped every rule to NCA ECC-2:2024.** Each of the 27 rules ties to a specific control in Saudi Arabia's current Essential Cybersecurity Controls baseline, so the project reflects a real regulatory requirement rather than a generic best practice. Version confirmed directly from the official PDF on nca.gov.sa.

**Pinned SIEM-SRV's IP to static.** It was DHCP and drifted from `.2` to `.132` after a reboot, breaking every agent's connection since their configs still pointed at the old address. Re-enrolled all agents and pinned the manager's IP static (via `systemd-networkd`, no `nmcli` on this OVA) - a floating manager IP can break the whole lab on any reboot. Full steps in `05-wazuh-setup.md`.

**Windows audit subcategories can silently reset.** Found `"User Account Management"` (used by Rules #02-#05) and `"Security Group Management"` (Rule #01) back at `No Auditing` in a later session, despite being confirmed working originally. Root cause not fully confirmed (a reboot or GPO refresh are both plausible). Check `auditpol /get /subcategory:"<name>"` first if a previously-working rule stops firing with no other error.

---

## Rule-Specific Lessons

Every rule's write-up (`rules/rule-XX-*.md`) has its own **Lessons Learned**
section instead of duplicating that detail here. Notable examples: clock
drift silently hiding alerts (Rule 01), tracing a parent `if_sid` instead of
guessing (Rule 04), `alerts.log`'s inconsistent format (Rules 05/06), the
SIEM manager's clock vs. local time for `<time>` rules (Rule 07), audit
subcategory + SACL requirements (Rule 08), `if_sid` vs `if_matched_sid`
(Rule 23), the pcre2 backslash-escaping issue (Rule 12), the netcat/
`nc.openbsd` symlink discovery (Rule 25), and substituting WinRM for PsExec
in an air-gapped network (Rule 21).
