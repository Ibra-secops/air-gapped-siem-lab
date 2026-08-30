# Screenshot Guide - What to Capture at Each Stage

General rule: capture "before" and "after," not just the final result. If a screenshot doesn't show what happened before or how you knew it worked, take a second one that does.

## Detection rules (3 per rule, most important category)

1. The event happening - the command running, or Event Viewer showing the raw event
2. The alert in the dashboard - rule ID and timestamp visible
3. The rule itself - the XML, from terminal or editor

## Installing a new component

- Any error you hit (matters more than the success shot)
- Final confirmation the service is running

## Troubleshooting

- The original error (full message)
- The fix, and a clear before/after result

## Network setup

- Final Virtual Network Editor settings
- `ip a` / `ipconfig` after configuration
- A successful `ping` between machines

## Registering an agent

- The "Deploy new agent" settings used
- The Agents page showing it as Active

## Attack simulation

- Each step, and the alert tied to it
- Timeline view if the story spans multiple events

## File naming

```
screenshots/
├── 01-network/
├── 02-dc/
├── 05-wazuh/
├── 06-sysmon/
└── rules/
    ├── rule-01-admin-group-add/
    ├── rule-02-.../
```

Number screenshots simply within each folder (`01-before.png`, `02-alert.png`, `03-after.png`).
