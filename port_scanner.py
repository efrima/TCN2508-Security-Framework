import socket
import logging
import ipaddress
import time
import json 
from concurrent.futures import ThreadPoolExecutor

# --- TELEMETRY SETUP ---
logger = logging.getLogger("PORT_SCANNER")

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=10, delay=0.05):
        self.target_input = target
        self.target_ip = None
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.delay = delay 
        
        self.resolve_target()
        self.verify_lab_environment()

    def _log_event(self, event_type, details):
        """
        Helper to structure logs as JSON for SIEM integration.
        """
        log_payload = {
            "event_type": event_type,
            "module": "[recon] PortScanner",
            "target": self.target_ip,
            "data": details
        }
        logger.info(json.dumps(log_payload))

    def resolve_target(self):
        try:
            self.target_ip = socket.gethostbyname(self.target_input)
            self._log_event("DNS_RESOLUTION", {
                "input": self.target_input,
                "resolved_ip": self.target_ip,
                "status": "Success"
            })
            print(f"[*] Resolved {self.target_input} to {self.target_ip}")
        except socket.error:
            self._log_event("DNS_ERROR", {
                "input": self.target_input,
                "status": "Failed"
            })
            print(f"[!] DNS Resolution Failed: {self.target_input}")
            return

    def verify_lab_environment(self):
        try:
            ip = ipaddress.ip_address(self.target_ip)
            if not ip.is_private and not ip.is_loopback:
                self._log_event("SAFETY_VIOLATION", {
                    "ip": self.target_ip,
                    "action": "Blocked"
                })
                raise ValueError(f"SAFETY VIOLATION: {self.target_ip} is PUBLIC.")
            
            self._log_event("SAFETY_CHECK", {
                "ip": self.target_ip,
                "status": "Passed",
                "type": "Private/Lab"
            })
        except ValueError as e:
            print(f"[!] {e}")
            # We let the main controller handle the exit if this fails, 
            # but raising error here stops execution.
            raise e

    def grab_banner(self, s):
        try:
            s.settimeout(1.0) 
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                return banner
        except socket.timeout:
            pass 
        except Exception:
            pass 

        try:
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            s.settimeout(2.0) 
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                return banner
            else:
                return "Unknown Service"
        except Exception:
            return "Unknown Service"

    def scan_port(self, port):
        if hasattr(self, 'is_blocked') and self.is_blocked:
            return None

        time.sleep(self.delay)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((self.target_ip, port))
            
            if result == 0:
                banner = self.grab_banner(s)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "tcp"
                
                self._log_event("PORT_OPEN", {
                    "port": port,
                    "service": service,
                    "banner": banner
                })
                
                s.close()
                return {"port": port, "service": service, "banner": banner}
            
            # Check for blockage (Network/Host Unreachable)
            # 101/113 = Linux, 10051/10065 = Windows
            elif result in [101, 113, 10051, 10065]: 
                if not hasattr(self, 'blocked_error_count'):
                    self.blocked_error_count = 0
                self.blocked_error_count += 1
                
                if self.blocked_error_count >= 5:
                    self.is_blocked = True
            
            s.close()
        except Exception:
            pass
        return None

    def run_scan(self):
        print(f"[*] Scanning {self.target_ip} ...")
        print(f"[*] Starting Lab-Only Scan on {self.target_ip}...")
        
        self._log_event("SCAN_START", {"mode": "Threaded", "ports": f"{self.start_port}-{self.end_port}"})
        
        # Initialize blockage tracking
        self.blocked_error_count = 0
        self.is_blocked = False

        ports = range(self.start_port, self.end_port + 1)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self.scan_port, ports)
        
        # Check if we were blocked execution
        if self.is_blocked:
            print("\n[!] Network blocked - Phase 5 may have isolated traffic")
            print("[*] Returning to menu...")
            return []

        clean_results = [r for r in results if r is not None]
        
        # Show just the count of open ports
        print("\n" + "="*50)
        print(f"[+] Open Ports Found: {len(clean_results)}")
        print("="*50)
        
        self._log_event("SCAN_COMPLETE", {"open_ports_count": len(clean_results)})
        return clean_results

if __name__ == "__main__":
    # Test execution
    try:
        scanner = PortScanner("192.168.137.131", start_port=1, end_port=100)
        scanner.run_scan()
    except Exception as e:
        print(f"Error: {e}")