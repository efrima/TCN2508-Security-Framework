# Lab Setup Guide (Runbook)

## Overview

This guide explains how to set up a safe, isolated lab environment for testing the OffDef Suite framework.

## Required Software

### Attacker Machine
- **VirtualBox** or **VMware Workstation**
- **Kali Linux 2023.x** (or newer)
- Python 3.10+

### Target Machines
- **Metasploitable 2** - For network attacks (SSH, FTP, etc.)
- **DVWA** - For web attacks (SQLi, Command Injection, etc.)

## Network Setup

### Option 1: Host-Only Network (Recommended)
1. Create a Host-Only network in VirtualBox:
   - File → Host Network Manager → Create
   - Note the IP range (e.g., 192.168.56.0/24)

2. Configure ALL VMs to use this network:
   - VM Settings → Network → Adapter 1 → Host-Only Adapter

### Option 2: NAT Network
1. Create a NAT Network:
   - File → Preferences → Network → NAT Networks → Add
   
2. Configure VMs to use this NAT network

## VM Configuration

### Kali Linux (Attacker)
```bash
# Update and install dependencies
sudo apt update
sudo apt install python3-pip python3-scapy

# Clone the framework
git clone <repo-url>
cd proj

# Install Python dependencies
pip3 install -r requirements.txt

# Verify installation
python3 main_controller.py
```

### Metasploitable 2 (Target)
- Default credentials: `msfadmin:msfadmin`
- No configuration needed - vulnerable by design
- Note the IP address after boot

### DVWA (Target)
- Access via browser: `http://<DVWA-IP>/dvwa`
- Default credentials: `admin:password`
- Set Security Level to "Low" for testing

## Pre-Flight Checklist

Before running the framework:

- [ ] All VMs are on isolated network (no internet access)
- [ ] Noted IP addresses of all machines
- [ ] Verified connectivity with `ping`
- [ ] DVWA is accessible and logged in
- [ ] Running Kali as root (for Phase 5)

## Running the Framework

```bash
# Start the framework
sudo python3 main_controller.py

# Set target IP when prompted
# Navigate menu to select phases
```

## Troubleshooting

### "Permission denied" errors
- Run with `sudo`

### "Module not found" errors
- Install missing dependencies: `pip3 install <module>`

### No network connectivity
- Check VM network adapter settings
- Verify IP addresses are in same subnet

### Phase 5 not detecting attacks
- Ensure IDS is running BEFORE attacks
- Run attacks from a DIFFERENT terminal

## Safety Reminders

1. **NEVER** connect VMs to bridged/real network
2. Always verify target IP before attacks
3. Generate reports after each session
4. Clean up (restore ARP tables, kill processes)
