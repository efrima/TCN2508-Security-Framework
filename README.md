# OffDef Suite - Automated Offensive & Defensive Cybersecurity Framework

> **⚠️ WARNING: This tool is for AUTHORIZED LAB USE ONLY. Unauthorized use against systems you do not own or have explicit permission to test is ILLEGAL.**

## Overview

A modular Python-based framework that automates reconnaissance, vulnerability discovery, exploitation, and defensive countermeasures. Designed for educational purposes in isolated lab environments.

## Quick Start

### Prerequisites
- Python 3.10+
- Kali Linux (recommended) or any Linux with required tools
- Target VMs: Metasploitable 2, DVWA
- Root/sudo privileges for Phase 5 defensive modules

### Installation

```bash
git clone <your-repo-url>
cd proj
pip install -r requirements.txt
```

### Running the Framework

```bash
sudo python main_controller.py
```

## Module Overview

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | Port Scanner | Discovers open ports on target |
| 1 | Vuln Scanner | Matches services to CVE database |
| 2 | SSH Brute | Dictionary attack on SSH |
| 2 | ARP Spoof | MITM attack with packet sniffing |
| 2 | Keylogger | Local keystroke capture |
| 3 | C2 Server | Command & Control simulation |
| 4 | SQL Injection | Automated DB extraction |
| 4 | Command Injection | RCE exploitation |
| 4 | CORS/SSRF | Misconfiguration testing |
| 5 | IDS | Intrusion Detection System |
| 5 | Log Analyzer | Real-time SIEM monitoring |
| 5 | Defense Block | Automated countermeasures |

## Lab Setup Requirements

1. **Attacker Machine**: Kali Linux VM
2. **Target Machines**: 
   - Metasploitable 2 (for SSH, FTP, network attacks)
   - DVWA (for web attacks)
3. **Network**: Isolated NAT or Host-Only network

## Safety Features

- All modules verify target is on private IP range before execution
- Lab environment checks prevent accidental internet scanning
- Defensive modules can isolate compromised hosts

## Output Files

| File | Description |
|------|-------------|
| `project_telemetry.log` | Real-time event log (SIEM input) |
| `[recon]_vuln_report.json` | Port scan + CVE findings |
| `report_final.json` | Session summary with MITRE mappings |

## Authors

TCN2508 Project Team

## License

MIT License - See LICENSE file. **FOR AUTHORIZED LAB USE ONLY.**
