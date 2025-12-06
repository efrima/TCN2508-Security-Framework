# Rules of Engagement

## Scope Definition

### In-Scope Targets
- Metasploitable 2 VM (IP: ____________)
- DVWA VM (IP: ____________)
- Other intentionally vulnerable VMs in isolated network

### Out-of-Scope
- Any system on the internet
- Production networks
- Systems belonging to others without written permission
- Critical infrastructure

## Engagement Rules

### Rule 1: Lab Environment Only
All testing MUST occur in an isolated network environment:
- Use Host-Only or NAT networking in VirtualBox/VMware
- Verify no route to internet before testing
- Confirm target IPs are in private ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x)

### Rule 2: Verify Before Attack
Before running any offensive module:
1. Confirm you are on the correct network
2. Verify target IP is your lab VM
3. Check that no production traffic is present

### Rule 3: Document Everything
- All testing sessions are logged to `project_telemetry.log`
- Generate reports after each session (Option 7)
- Keep records of what was tested and when

### Rule 4: Clean Up
After testing:
- Restore ARP tables if spoofing was used
- Remove persistence markers
- Stop all background processes (keylogger, C2)

### Rule 5: Defensive Posture
- Run Phase 5 defensive modules to understand detection
- Review logs to see how attacks appear to defenders
- Use hardening scripts to remediate findings

## Emergency Procedures

### If You Accidentally Hit Wrong Target
1. STOP all scans immediately (Ctrl+C)
2. Document what happened
3. Report to instructor/supervisor
4. Do NOT attempt to cover up

### If Framework Behaves Unexpectedly
1. Exit via Ctrl+C
2. Check running processes (`ps aux | grep python`)
3. Kill any orphan processes
4. Review telemetry logs


*By proceeding with this framework, I confirm I have read and will abide by these rules.*
