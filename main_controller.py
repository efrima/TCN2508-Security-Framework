import sys
import json
import logging
import time
import ipaddress
import os
import threading
import subprocess 
from datetime import datetime

# --- MODULE INTEGRATION ---
try: from port_scanner import PortScanner
except ImportError: print("[!] Warning: port_scanner.py is missing.")

try: from vuln_scanner import VulnScanner
except ImportError: print("[!] Warning: vuln_scanner.py is missing.")

try: from ssh_brute import SSHBrute
except ImportError: print("[!] Warning: ssh_brute.py is missing.")

try: from arp_spoof import ARPSpoofer
except ImportError: print("[!] Warning: arp_spoof.py is missing.")

# NOTE: keylogger_local is now run as a subprocess, not imported directly.
try: from c2_server import start_c2_server 
except ImportError: print("[!] Warning: c2_server.py is missing.")

try:
    from sqli_exploit import SQLInjector
    from cmd_injection import CommandInjector
    from cors_ssrf import MisconfigScanner
except ImportError: print("[!] Warning: Web exploit modules are missing.")

# Phase 5 Defense Modules
try:
    from ids_detect import IDS
    from log_analyzer import LogAnalyzer
    from defense_block import DefenseResponder
except ImportError as e:
    print(f"[!] Warning: Phase 5 Defense modules failed: {e}")

# --- TELEMETRY SETUP ---
logging.basicConfig(
    filename='project_telemetry.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(message)s'
)
logger = logging.getLogger("CORE")

class MainController:
    def __init__(self):
        self.operator = None
        self.target = None
        self.session_data = {
            "session_start": str(datetime.now()),
            "security_findings": [], 
            "raw_logs": [] 
        }
        self.authenticate_operator()

    def authenticate_operator(self):
        print("\n=== THINKCYBER OFF/DEF FRAMEWORK [TCN2508] ===")
        # simplified for testing
        self.operator = "Admin" 
        print(f"[*] Access Granted. Welcome, {self.operator}.")

    def set_target(self):
        print("\n--- TARGET CONFIGURATION ---")
        try:
            target_input = input("Enter Target IP (Lab Environment ONLY): ").strip()
            if not target_input: return

            # Basic IP Validation
            try:
                ip = ipaddress.ip_address(target_input)
            except ValueError:
                print("[!] Invalid IP address format.")
                return

            self.target = target_input
            logger.info(f"Target locked: {self.target}")
            print(f"[*] Target set to {self.target}")
            
        except (KeyboardInterrupt, EOFError):
            return

    # MITRE ATT&CK mapping for each attack type
    MITRE_MAP = {
        "Recon": {"technique": "T1046", "name": "Network Service Discovery"},
        "SSH_Brute": {"technique": "T1110.001", "name": "Brute Force: Password Guessing"},
        "ARP_Spoof": {"technique": "T1557.002", "name": "MITM: ARP Cache Poisoning"},
        "Keylogger": {"technique": "T1056.001", "name": "Input Capture: Keylogging"},
        "C2": {"technique": "T1071.001", "name": "Application Layer Protocol: Web"},
        "SQLi": {"technique": "T1190", "name": "Exploit Public-Facing Application"},
        "AuthBypass": {"technique": "T1078", "name": "Valid Accounts"},
        "CmdInjection": {"technique": "T1059", "name": "Command and Scripting Interpreter"},
        "CORS": {"technique": "T1189", "name": "Drive-by Compromise"},
        "SSRF": {"technique": "T1190", "name": "Exploit Public-Facing Application"},
    }

    def register_finding(self, attack_key, details):
        mitre = self.MITRE_MAP.get(attack_key, {"technique": "N/A", "name": "Unknown"})
        finding = {
            "timestamp": str(datetime.now()),
            "attack_type": attack_key,
            "mitre_technique": mitre["technique"],
            "mitre_name": mitre["name"],
            "details": details
        }
        self.session_data["security_findings"].append(finding)

    def run_phase_1(self):
        if not self.target: self.set_target()
        if not self.target: return
        print(f"\n[+] --- EXECUTING PHASE 1: RECONNAISSANCE ---")
        
        if 'PortScanner' in globals():
            try:
                # Threaded scan for speed
                # The updated PortScanner.run_scan() will now handle the printing of
                # counts and vulnerability names to the console.
                scanner = PortScanner(self.target, start_port=1, end_port=1024, threads=20, delay=0.05)
                recon_results = scanner.run_scan()
                
                # Register findings to the internal session log
                self.register_finding("Recon", f"Found {len(recon_results)} open ports.")
                
                # Pass to VulnScanner to match against CVE database
                if 'VulnScanner' in globals():
                    print("[*] Passing results to Vulnerability Scanner...")
                    vuln_tool = VulnScanner(recon_results)
                    vuln_findings = vuln_tool.analyze()
                    vuln_tool.save_report()  # Save vuln report to JSON file
            except Exception as e:
                print(f"[!] Phase 1 Error: {e}")
        
        # Pauses here so you can read the scanner output
        input("\n[Press Enter to return to Main Menu]")

    def run_phase_2(self):
        if not self.target: self.set_target()
        if not self.target: return

        while True:
            print(f"\n[+] --- PHASE 2 MENU: EXPLOITATION ---")
            print("1. SSH Brute Force")
            print("2. ARP Spoofing")
            print("3. Deploy Local Keylogger (Process Mode)")
            print("99. Return to Main Menu")
            
            choice = input("Select Attack Module: ").strip()

            if choice == '1' and 'SSHBrute' in globals():
                try:
                    user = input("Target Username: ")
                    attacker = SSHBrute(self.target, user)
                    password = attacker.run_attack()
                    if password:
                        self.register_finding("SSH_Brute", f"Credentials cracked: {user}:{password}")
                except Exception as e:
                    print(f"[!] SSH Module Error: {e}")

            elif choice == '2' and 'ARPSpoofer' in globals():
                gateway = input("Enter Gateway IP: ")
                try:
                    spoofer = ARPSpoofer(self.target, gateway)
                    self.register_finding("ARP_Spoof", "MITM Attack executed successfully.")
                    spoofer.run()
                except KeyboardInterrupt:
                    print("\n[*] Stopping ARP Attack...")
            
            elif choice == '3':
                print("[*] Starting Local Keylogger...")
                print("[i] Press ESC to stop, or use Phase 5 -> 'Anti-Keylogger' to terminate.")
                script_path = "keylogger_local.py"
                if os.path.exists(script_path):
                    try:
                        # Run keylogger and WAIT for it to finish
                        # This way we detect when it's killed by Phase 5 or stopped by ESC
                        proc = subprocess.Popen([sys.executable, script_path])
                        self.register_finding("Keylogger", "Active process spawned.")
                        
                        # Wait for keylogger to finish (ESC pressed or killed by Phase 5)
                        proc.wait()
                        
                        # Process has ended - return gracefully to menu
                        print("\n[*] Keylogger process ended.")
                        print("[*] Returning to Phase 2 menu...")
                        
                    except Exception as e:
                        print(f"[!] Keylogger Error: {e}")
                else:
                    print(f"[!] Error: {script_path} not found.")

            elif choice == '99': break

    def run_phase_3(self):
        print(f"\n[+] --- EXECUTING PHASE 3: C2 SERVER ---")
        print("[i] Press Ctrl+C to stop, or Phase 5 may isolate the host.")
        if 'start_c2_server' in globals():
            try:
                self.register_finding("C2", "C2 Server started.")
                start_c2_server()
            except KeyboardInterrupt:
                print("\n[*] C2 Server Stopped by operator.")
            except OSError as e:
                # Network disabled by Phase 5 (host isolation)
                print(f"\n[*] C2 Server terminated: {e}")
                print("[*] (Network may have been disabled by Phase 5)")
            except Exception as e:
                print(f"\n[*] C2 Server ended: {e}")
        
        print("[*] Returning to Main Menu...")
        input("[Press Enter to continue]")

    def run_phase_4(self):
        if not self.target: self.set_target()
        if not self.target: return
        target_url = self.target if self.target.startswith("http") else f"http://{self.target}"

        while True:
            print(f"\n[+] --- PHASE 4 MENU: WEB EXPLOITS ({target_url}) ---")
            print("1. SQL Injection")
            print("2. Command Injection / Auth Bypass")
            print("3. CORS / SSRF Scanner")
            print("4. Run All Web Exploits")
            print("99. Return to Main Menu")
            
            choice = input("Select Attack Module: ").strip()

            if choice == '1':
                if 'SQLInjector' in globals():
                    try:
                        print("\n[*] Running SQL Injection Module...")
                        result = SQLInjector(target_url).run_injection()
                        if result:
                            self.register_finding("SQLi", result)
                    except Exception as e:
                        print(f"[!] SQLi Error: {e}")
                else:
                    print("[!] SQLInjector module not loaded.")

            elif choice == '2':
                if 'CommandInjector' in globals():
                    try:
                        print("\n[*] Running Command Injection Module...")
                        injector = CommandInjector(target_url)
                        
                        # Run Auth Bypass Test
                        bypass_result = injector.test_auth_bypass()
                        if bypass_result:
                            self.register_finding("AuthBypass", bypass_result)
                        
                        # Run RCE Test
                        rce_result = injector.test_rce()
                        if rce_result:
                            self.register_finding("CmdInjection", rce_result)
                    except Exception as e:
                        print(f"[!] Command Injection Error: {e}")
                else:
                    print("[!] CommandInjector module not loaded.")

            elif choice == '3':
                if 'MisconfigScanner' in globals():
                    try:
                        print("\n[*] Running CORS/SSRF Scanner...")
                        scanner = MisconfigScanner(target_url)
                        
                        # Run CORS Test
                        cors_result = scanner.test_cors()
                        if cors_result:
                            self.register_finding("CORS", cors_result)
                        
                        # Run SSRF/LFI Test
                        ssrf_result = scanner.test_ssrf()
                        if ssrf_result:
                            self.register_finding("SSRF", ssrf_result)
                    except Exception as e:
                        print(f"[!] CORS/SSRF Error: {e}")
                else:
                    print("[!] MisconfigScanner module not loaded.")

            elif choice == '4':
                print("\n[*] Running ALL Web Exploit Modules...")
                
                # SQL Injection
                if 'SQLInjector' in globals():
                    try:
                        SQLInjector(target_url).run_injection()
                    except: pass
                
                # Command Injection
                if 'CommandInjector' in globals():
                    try:
                        injector = CommandInjector(target_url)
                        injector.test_auth_bypass()
                        injector.test_rce()
                    except: pass
                
                # CORS/SSRF
                if 'MisconfigScanner' in globals():
                    try:
                        scanner = MisconfigScanner(target_url)
                        scanner.test_cors()
                        scanner.test_ssrf()
                    except: pass
                
                print("\n[+] All Web Exploit modules completed.")

            elif choice == '99':
                break
            
            else:
                print("[!] Invalid selection.")

    def run_phase_5(self):
        while True:
            print("\n" + "="*60)
            print("[*] PHASE 5: DEFENSIVE OPERATIONS")
            print("1. Run Full SOC Mode (IDS + SIEM + Defense)")
            print("2. Run Hardening Check Only")
            print("3. Run Anti-Keylogger (Manual Trigger)")
            print("99. Return to Main Menu")
            
            choice = input("Select: ").strip()

            if choice == '1':
                print("[!] STARTING SOC MODE...")
                print("[i] Press Ctrl+C to stop monitoring.")
                time.sleep(1)

                # --- FIX: Pass self.target to IDS for auto-routing ---
                if 'IDS' in globals():
                    print(f"[*] Initializing IDS (Target: {self.target})...")
                    # If target is None, IDS will fallback to default interface
                    ids_engine = IDS(target_ip=self.target)
                    
                    t_ids = threading.Thread(target=ids_engine.start, daemon=True)
                    t_ids.start()

                # Start Log Analyzer
                if 'LogAnalyzer' in globals():
                    print("[*] Launching SIEM Analyzer...")
                    analyzer = LogAnalyzer()
                    try: 
                        analyzer.analyze() 
                    except KeyboardInterrupt: 
                        print("\n[!] SOC Mode Stopped.")
            
            elif choice == '2':
                if 'DefenseResponder' in globals(): DefenseResponder().run_hardening()
                
            elif choice == '3':
                if 'DefenseResponder' in globals(): DefenseResponder().anti_keylogger()

            elif choice == '99':
                break

    # Remediation guidance for each attack type
    REMEDIATION = {
        "Recon": "Close unnecessary ports. Use firewall rules to restrict access.",
        "SSH_Brute": "Enable account lockout. Use key-based authentication. Implement fail2ban.",
        "ARP_Spoof": "Use static ARP entries. Enable Dynamic ARP Inspection on switches.",
        "Keylogger": "Deploy endpoint protection. Monitor for unusual process activity.",
        "C2": "Block suspicious outbound connections. Monitor for beaconing behavior.",
        "SQLi": "Use parameterized queries. Validate and sanitize all inputs.",
        "AuthBypass": "Implement proper session management. Use MFA.",
        "CmdInjection": "Avoid shell commands. Sanitize inputs. Use allowlists.",
        "CORS": "Configure strict CORS policies. Never reflect arbitrary Origins.",
        "SSRF": "Validate URLs. Use allowlists. Block internal IP ranges.",
    }

    def generate_report(self):
        print("\n[*] Generating Report with MITRE Mappings & Remediation...")
        
        # Enrich findings with remediation
        for finding in self.session_data["security_findings"]:
            attack_type = finding.get("attack_type", "")
            finding["remediation"] = self.REMEDIATION.get(attack_type, "Review security controls.")
        
        filename = "report_final.json"
        with open(filename, "w") as f:
            json.dump(self.session_data, f, indent=4)
        
        # Print summary to console
        print(f"\n{'='*60}")
        print("ATTACK REPORT SUMMARY")
        print(f"{'='*60}")
        for finding in self.session_data["security_findings"]:
            print(f"\n[{finding.get('mitre_technique', 'N/A')}] {finding.get('attack_type')}")
            print(f"  MITRE: {finding.get('mitre_name', 'N/A')}")
            print(f"  Details: {finding.get('details')}")
            print(f"  Remediation: {finding.get('remediation')}")
        print(f"\n{'='*60}")
        print(f"[+] Full report saved to {filename}")

    def main_menu(self):
        while True:
            print("\n--- MAIN COMMAND MENU ---")
            print("1. Set Target IP")
            print("2. Run Phase 1 (Recon)")
            print("3. Run Phase 2 (Exploitation)")
            print("4. Run Phase 3 (C2 Server)")
            print("5. Run Phase 4 (Web Injection)")
            print("6. Run Phase 5 (DEFENSE/SOC)")
            print("7. Report & Exit")
            
            choice = input("Select: ").strip()
            
            if choice == "1": self.set_target()
            elif choice == "2": self.run_phase_1()
            elif choice == "3": self.run_phase_2()
            elif choice == "4": self.run_phase_3()
            elif choice == "5": self.run_phase_4()
            elif choice == "6": self.run_phase_5()
            elif choice == "7": self.generate_report(); break

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Warning: Defense modules require ROOT (sudo).")
    try:
        app = MainController()
        app.main_menu()
    except KeyboardInterrupt:
        print("\n[!] Bye.")