# 05 - Wazuh (SIEM) Setup

## Goal

Deploy Wazuh (manager + indexer + dashboard) as the central SIEM for the lab, on its own VM.

> Version used throughout this project: Wazuh OVA v4.14.7. Newer releases may use a different installation flow.

## What I did

1. Downloaded the official Wazuh OVA (v4.14.7) from the Wazuh docs (Installation alternatives → Virtual machine).
2. Imported it into VMware Workstation (`File → Open`, selected the `.ovf`).
3. Set the network adapter to **Custom: VMnet1**.
4. Logged into the console using the OVA's default credentials (documented in Wazuh's official OVA installation guide).
5. Opened the dashboard from another lab machine using the default `admin` credentials, then changed the password immediately:
   ```
   https://192.168.50.2
   ```
   (This was the manager's IP at first deploy - DHCP later gave it a different one, see below.)

## Issues Faced & How I Solved Them

### wazuh-manager failed to start - indexer timeout

First boot after import, `wazuh-manager` failed with a timeout. Checked `wazuh-indexer` and it was `failed (Result: timeout)`.

Ruled out RAM (`free -h` showed plenty free) and `vm.max_map_count` (already `262144`). Ran the indexer manually in the foreground:
```
sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch
```
It was working fine, just slow on first boot (loading plugins, TLS setup, several minutes) - longer than systemd's default timeout.

**Fix:** let it finish booting manually, then raised the timeout so it doesn't fail again after future reboots:
```
sudo systemctl edit wazuh-indexer
```
```ini
[Service]
TimeoutStartSec=300
```
```
sudo systemctl daemon-reload
```
Started `wazuh-manager` and `wazuh-dashboard`, enabled all three services:
```
sudo systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard
```

Dashboard briefly showed the manager API as "Offline" right after - fixed itself once the manager was confirmed running and the page refreshed.

### All three agents went disconnected after a reboot

Checked `ossec.log` on the manager, saw repeated:
```
wazuh-remoted: WARNING: Agent key already in use: agent ID '001'
wazuh-authd: WARNING: Duplicate name 'WIN-CLIENT', rejecting enrollment.
```

Checked the manager's real IP - `ip a` showed `192.168.50.132`, not `192.168.50.2` anymore. It was still DHCP, and a reboot gave it a new lease. Every agent's `ossec.conf` still pointed at the old `.2` address, so none of them could connect.

**Fix:**

1. Updated `<address>` to `192.168.50.132` in each agent's `ossec.conf`, deleted the old key, and let each one re-enroll:
   - Windows (DC01, WIN-CLIENT):
     ```powershell
     Stop-Service WazuhSvc -Force
     Remove-Item "C:\Program Files (x86)\ossec-agent\client.keys" -Force
     Start-Service WazuhSvc
     ```
   - Linux (APP01):
     ```bash
     sudo systemctl stop wazuh-agent
     sudo rm /var/ossec/etc/client.keys
     sudo systemctl start wazuh-agent
     ```
   - On the manager, removed the old conflicting entry first:
     ```bash
     sudo /var/ossec/bin/manage_agents -r 001
     sudo systemctl restart wazuh-manager
     ```
2. Pinned the manager's IP so it can't drift again. No `nmcli`, no Netplan on this VM - it uses `systemd-networkd` directly (`/etc/systemd/network/20-eth0.network`):
   ```ini
   [Match]
   Type=ether

   [Network]
   Address=192.168.50.132/24
   Gateway=192.168.50.254
   DNS=192.168.50.131
   ```
   ```bash
   sudo systemctl restart systemd-networkd
   ```
   `ip a` no longer shows `dynamic` next to the address - confirmed static.

## Result

Indexer, manager, and dashboard all running. Dashboard now at `https://192.168.50.132`, on a static IP. All three agents re-enrolled and Active.
