# Architecture Diagram

## Framework Overview (Mermaid)

```mermaid
graph TB
    subgraph "Main Controller"
        MC[main_controller.py]
    end
    
    subgraph "Phase 1: Reconnaissance"
        PS[port_scanner.py]
        VS[vuln_scanner.py]
    end
    
    subgraph "Phase 2: Exploitation"
        SSH[ssh_brute.py]
        ARP[arp_spoof.py]
        KL[keylogger_local.py]
    end
    
    subgraph "Phase 3: C2"
        C2S[c2_server.py]
        C2C[c2_client.py]
    end
    
    subgraph "Phase 4: Web Exploits"
        SQLI[sqli_exploit.py]
        CMD[cmd_injection.py]
        CORS[cors_ssrf.py]
    end
    
    subgraph "Phase 5: Defense"
        IDS[ids_detect.py]
        LA[log_analyzer.py]
        DB[defense_block.py]
    end
    
    subgraph "Output Files"
        TEL[project_telemetry.log]
        VR[vuln_report.json]
        FR[report_final.json]
    end
    
    MC --> PS
    MC --> VS
    MC --> SSH
    MC --> ARP
    MC --> KL
    MC --> C2S
    MC --> SQLI
    MC --> CMD
    MC --> CORS
    MC --> IDS
    MC --> LA
    MC --> DB
    
    PS --> TEL
    VS --> TEL
    VS --> VR
    SSH --> TEL
    ARP --> TEL
    KL --> TEL
    C2S --> TEL
    SQLI --> TEL
    CMD --> TEL
    CORS --> TEL
    IDS --> TEL
    DB --> TEL
    MC --> FR
    
    LA --> DB
    IDS --> LA
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACKER (Kali Linux)                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐                                            │
│  │   Main      │──────► Phase 1-4 Attack Modules            │
│  │ Controller  │                    │                        │
│  └─────────────┘                    │                        │
│         │                           ▼                        │
│         │              ┌────────────────────┐               │
│         │              │ project_telemetry  │◄──────────────┤
│         │              │      .log          │               │
│         │              └────────────────────┘               │
│         │                           │                        │
│         │                           ▼                        │
│         │              ┌────────────────────┐               │
│         └─────────────►│   Phase 5 IDS      │               │
│                        │   + Log Analyzer   │               │
│                        │   + Defense Block  │               │
│                        └────────────────────┘               │
│                                     │                        │
│                                     ▼                        │
│                        ┌────────────────────┐               │
│                        │  Countermeasures   │               │
│                        │  - Block IP        │               │
│                        │  - Isolate Host    │               │
│                        │  - Kill Processes  │               │
│                        └────────────────────┘               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    TARGET (Metasploitable/DVWA)              │
└─────────────────────────────────────────────────────────────┘
```

## MITRE ATT&CK Mapping

| Module | Technique ID | Technique Name |
|--------|--------------|----------------|
| Port Scanner | T1046 | Network Service Discovery |
| SSH Brute | T1110.001 | Brute Force: Password Guessing |
| ARP Spoof | T1557.002 | MITM: ARP Cache Poisoning |
| Keylogger | T1056.001 | Input Capture: Keylogging |
| C2 Server | T1071.001 | Application Layer Protocol |
| SQL Injection | T1190 | Exploit Public-Facing Application |
| Command Injection | T1059 | Command and Scripting Interpreter |
