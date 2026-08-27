# 01 - Network Setup

## Goal

Create an isolated network for the lab so all VMs can communicate with each other without touching any external or production network.

## What I did

1. Opened **VMware Workstation → Edit → Virtual Network Editor**.
2. Used **VMnet1**, set as **Host-only**.
3. Configured:
   - Subnet IP: `192.168.50.0`
   - Subnet mask: `255.255.255.0`
   - DHCP enabled, range `192.168.50.128` - `192.168.50.254`
4. Set every VM's Network Adapter to **Custom: VMnet1** so all four machines share the same isolated segment.

## IP Assignment

| VM | IP | Method |
|---|---|---|
| DC01 | 192.168.50.131 | DHCP (VMnet1 pool) |
| WIN-CLIENT | 192.168.50.129 | DHCP (VMnet1 pool) |
| APP01 | 192.168.50.130 | Static (`nmcli`) |
| SIEM-SRV | 192.168.50.132 | Static (`systemd-networkd`) - see note below |

DC01 and WIN-CLIENT get their address from the VMnet1 DHCP pool automatically.

SIEM-SRV's address was `192.168.50.2` at first deploy, then changed to `192.168.50.132` after a reboot (was still DHCP) - broke all agent connections. Fixed by pinning it static. Full story in `05-wazuh-setup.md`.

APP01 needed a fixed address, set via `nmcli`:

```bash
sudo nmcli connection modify "Wired connection 1" \
  ipv4.addresses 192.168.50.130/24 \
  ipv4.gateway 192.168.50.254 \
  ipv4.dns 192.168.50.131 \
  ipv4.method manual

sudo nmcli connection down "Wired connection 1"
sudo nmcli connection up "Wired connection 1"
```

**Note on IP design:** `.130` and `.132` sit inside the DHCP pool (`.128`-`.254`) instead of outside it, which isn't ideal - a cleaner design would reserve the static addresses from a separate range (e.g. `.10`-`.50`) so they can never collide with a DHCP-assigned one. In this lab it never caused a problem in practice, since only two machines (DC01, WIN-CLIENT) ever pulled from DHCP and neither landed on `.130` or `.132`, but it's a design choice I'd fix first in a non-lab setup.

## Issues Faced & How I Solved Them

### Issue 1 - Ubuntu VM kept an old IP from a previous network

After re-attaching a VM's network adapter, the VM still reported the interface as `UP` but never actually communicated on the new subnet. Editing `netplan/*.yaml` directly had no effect because the system was managed by **NetworkManager**, not netplan directly (multiple leftover `netplan-*` connection profiles existed with no device attached).

**Fix:** Identified the active connection with `nmcli connection show`, then modified it directly via `nmcli connection modify` instead of editing YAML files.

### Issue 2 - New Ubuntu VM pulled an IP outside the lab subnet

After deleting and re-adding the VM's network adapter, it briefly picked up `192.168.0.122` and later `192.168.50.1` via DHCP - both unexpected. `192.168.50.1` turned out to be reserved for the VMware host adapter itself, not meant for guest VMs.

**Fix:** Set a static IP explicitly via `nmcli` instead of relying on DHCP for machines that need a fixed address.

### Issue 3 - "Destination host unreachable" between two working machines

Ping between two VMs failed with `Destination host unreachable` even though both were on the correct subnet. Root cause was an incorrectly, manually configured default gateway (set to `.1`) on the Windows client - `.1` is reserved for the VMware host adapter itself, not a real router. In a Host-only network like this one, there's no actual gateway/router device; `192.168.50.254` is just the address VMware's DHCP service was configured with, which the VMs had been using as a de facto default route.

**Fix:** Corrected the misconfigured gateway on the affected machine to `192.168.50.254`, matching what the rest of the lab was already using, and connectivity was restored. On a fully isolated /24 subnet like this, a default gateway isn't strictly required for host-to-host traffic - it only matters if a device is misconfigured to route through the wrong address.

## Lesson Learned

When a VM's network adapter is removed and re-added in VMware, the guest OS treats it as a brand-new NIC (new interface name, e.g. `ens160` → `ens33`), and any manual network configuration tied to the old interface name is silently lost. Best practice: configure the adapter fully in VMware settings first (correct VMnet, connected, connect-at-power-on), then apply IP configuration once inside the guest - and take a snapshot immediately after confirming connectivity.
