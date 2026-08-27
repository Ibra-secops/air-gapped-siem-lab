# Screenshot Guide - What to Capture at Each Stage

Reference guide: check here before starting any step. General rule: **capture "before" and "after," not just the final result.**

---

## When building any detection rule - the most important and most repeated one

For each of the 27 rules, you need 3 screenshots in order:

1. **The event happening** - example: the CMD window while you run the suspicious command, or Event Viewer showing the raw event before it reaches Wazuh.
2. **The alert in the dashboard** - the Wazuh Dashboard page showing the alert, with the time and rule ID visible.
3. **The rule itself** - if you edited or added an XML rule, capture the code (from the terminal or text editor).

## When installing any new component (DC / App server / Client / Wazuh / Sysmon)

- The **start of installation** (version selection, base settings)
- Any **error message** you hit (even if you solved it) - this matters more than the success screenshot itself
- The **final confirmation** that the service is running (`systemctl status` or the Windows equivalent)

## When solving a technical problem (Troubleshooting)

- The original error (full, clear error message on screen)
- The command or check you used to diagnose it
- The result after the fix (a clear "before" and "after" difference)

This type of screenshot matters most for the Decision Log - troubleshooting stories are some of the most valuable documentation in this project.

## When setting up the network

- The **Virtual Network Editor** page (final settings after any change)
- The result of `ip a` or `ipconfig` from each machine after configuration
- A successful `ping` result between machines (proof the connection works)

## When registering a new agent

- The "Deploy new agent" page in the dashboard (the settings you chose)
- The command you ran on the machine itself
- The **Agents** page in the dashboard showing the new machine as **Active**

## When simulating an attack / insider threat scenario

- Every step in the scenario (if it spans several days, capture each day separately)
- The alerts tied to each step
- If you linked more than one event into one story, capture the timeline view in the dashboard if available

---

## A quick rule to remember

**If the screenshot doesn't show "what happened before" or "how you knew it worked" - take a second screenshot that does.** One screenshot of the final result is not enough for good documentation.

## File naming (organizing early saves time later)

```
screenshots/
├── 01-network/
├── 02-dc/
├── 05-wazuh/
├── 06-sysmon/
├── rules/
│   ├── rule-01-admin-group-add/
│   ├── rule-02-...
└── troubleshooting/
```

Each folder has its screenshots numbered simply (`01-before.png`, `02-alert.png`, `03-after.png`).
