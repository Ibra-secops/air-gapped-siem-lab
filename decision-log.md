Decision Log

Key project-level decisions. Rule-specific troubleshooting lives in each rule's own Lessons Learned section (rules/rule-XX-*.md).

Wazuh over ELK or Splunk - single ready-to-deploy appliance, no build-from-scratch or free-tier caps.

Built around a "no internet" assumption - the whole lab (network, rules) assumes zero internet, modeling insider-threat risk rather than external attacks. No Kali/attacker VM, since phishing/C2 don't apply air-gapped.

Every rule mapped to NCA ECC-2:2024 - ties each of the 27 rules to a real Saudi regulatory control, not just a generic best practice.

Pinned SIEM-SRV's IP to static - it drifted from DHCP after a reboot and broke every agent's connection. Full steps in 05-wazuh-setup.md.

Windows audit subcategories can silently reset - found two (User Account Management, Security Group Management) back at No Auditing in a later session with no error anywhere. Check auditpol /get /subcategory:"<name>" first if a working rule goes quiet.

Rule-Specific Lessons

See each rule's own Lessons Learned section for details - clock drift (Rule 01), pcre2 escaping (Rule 12), WinRM over PsExec (Rule 21), and more.
