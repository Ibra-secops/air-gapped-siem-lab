# Rule #14 - Registry Persistence via Run/RunOnce Keys

**Status:** ✅ Built and tested

## Overview

This rule watches for a value getting added or changed under the `Run` or
`RunOnce` registry keys - probably the most common way malware sets itself
up to auto-start on every reboot.

| Field | Value |
|---|---|
| Log Source | Sysmon (WIN-CLIENT) |
| Sysmon Event ID | 13 (RegistryEvent - Value Set) |
| Wazuh Rule ID | 100016 (custom - built on `if_sid: 92300`) |
| Rule Description | Registry persistence: value set in Run/RunOnce key ($(win.eventdata.targetObject)) |
| Rule Level | 12 |
| MITRE ATT&CK | T1547.001 - Registry Run Keys / Startup Folder (Persistence, Privilege Escalation) |
| ECC Control | 2-3-3-1 |

## Steps

**Step 1 - Review the existing local_rules.xml file.**

```bash
sudo cat /var/ossec/etc/rules/local_rules.xml
```

![Local rules file overview](../screenshots/rules/rule-14-registry-run-persistence/01-local-rules-file-overview.png)

**Step 2 - Final rule content (rule ID 100016).**

```xml
<rule id="100016" level="12">
  <if_sid>92300</if_sid>
  <field name="win.eventdata.eventType">SetValue</field>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)\\\\CurrentVersion\\\\Run(Once)?\\\\</field>
  <description>Registry persistence: value set in Run/RunOnce key ($(win.eventdata.targetObject))</description>
  <mitre>
    <id>T1547.001</id>
  </mitre>
  <group>persistence,registry_run_key,</group>
</rule>
```

To add this rule directly to `local_rules.xml`:

```bash
sudo sed -i '$i\
<rule id="100016" level="12">\
  <if_sid>92300</if_sid>\
  <field name="win.eventdata.eventType">SetValue</field>\
  <field name="win.eventdata.targetObject" type="pcre2">(?i)\\\\\\\\CurrentVersion\\\\\\\\Run(Once)?\\\\\\\\</field>\
  <description>Registry persistence: value set in Run/RunOnce key ($(win.eventdata.targetObject))</description>\
  <mitre>\
    <id>T1547.001</id>\
  </mitre>\
  <group>persistence,registry_run_key,</group>\
</rule>' /var/ossec/etc/rules/local_rules.xml
sudo grep -A 9 'id="100016"' /var/ossec/etc/rules/local_rules.xml
```

Same double-backslash-escaping note as Rule #12 and Rule #13 applies here - the `pcre2` field needs 4 literal backslashes per path separator in the file, so the `sed` command needs 8 (since `sed` collapses each `\\` to `\`). Worth confirming with the `grep` above that it landed correctly.

![Rule 100016 final content](../screenshots/rules/rule-14-registry-run-persistence/02-rule-100016-final-content.png)

**Step 3 - Locate Sysmon Event ID 13 ruleset files.**

```bash
sudo find /var/ossec -iname "*sysmon*" -type f 2>/dev/null
```

![Find Sysmon rule files](../screenshots/rules/rule-14-registry-run-persistence/03-find-sysmon-rule-files.png)

**Step 4 - Inspect the dedicated Event ID 13 ruleset.**

```bash
sudo cat /var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

![Sysmon Event 13 ruleset file content](../screenshots/rules/rule-14-registry-run-persistence/04-sysmon-id13-file-content.png)

**Step 5 - Base rule 92300 (Run/RunOnce detection, level 0).**

Rule 92300 is a built-in Wazuh rule that silently classifies any
registry write under `CurrentVersion\Run` (including `WOW6432Node` and
`RunOnce` variants). Rule 100016 links to it directly via `if_sid`,
since it already matches the exact behavior we want to detect.

![Rule 92300 detail](../screenshots/rules/rule-14-registry-run-persistence/05-rule-92300-detail.png)

**Step 6 - Confirm Event ID 13 alerts already fire in this environment.**

```bash
sudo grep '"eventID":"13"' /var/ossec/logs/alerts/alerts.json | head -3
```

This confirms a sibling rule (92307) from the same ruleset file was
already firing successfully on real registry events in the lab,
validating that the base rule chain is active.

![Existing Event ID 13 alerts](../screenshots/rules/rule-14-registry-run-persistence/06-eventid13-existing-alerts.png)

**Step 7 - Trigger a test event (GUI action / PowerShell - WIN-CLIENT).**

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Rule14Verified" -Value "C:\Windows\System32\calc.exe" -PropertyType String -Force
```

![Client PowerShell registry value creation](../screenshots/rules/rule-14-registry-run-persistence/10-client-powershell-registry-value.png)

**Step 8 - Confirm the alert in alerts.json.**

```bash
sudo grep '"id":"100016"' /var/ossec/logs/alerts/alerts.json
```

![alerts.json match for rule 100016](../screenshots/rules/rule-14-registry-run-persistence/07-alerts-json-rule100016-match.png)

**Step 9 - Confirm the alert in the Wazuh dashboard (Discover).**

Search: `rule.id: 100016`

![Dashboard Discover search for rule 100016](../screenshots/rules/rule-14-registry-run-persistence/08-dashboard-discover-rule100016.png)

**Step 10 - Expanded alert detail.**

![Expanded dashboard alert detail](../screenshots/rules/rule-14-registry-run-persistence/09-dashboard-alert-detail-expanded.png)

Confirmed fields:
- `rule.id`: 100016
- `rule.level`: 12
- `rule.mitre.id`: T1547.001
- `rule.mitre.tactic`: Persistence, Privilege Escalation
- `rule.mitre.technique`: Registry Run Keys / Startup Folder
- `rule.description`: Registry persistence: value set in Run/RunOnce key (HKU\S-1-5-21-1520905600-2831779732-1626254368-1104\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Rule14Verified)

## Lessons Learned

When a "theoretically correct" parent rule doesn't fire, link directly to a known-working built-in rule instead (used `92300`, not `61615`).
