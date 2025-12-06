import json
import logging
import os

# --- TELEMETRY SETUP ---
logger = logging.getLogger("VULN_SCANNER")

class VulnScanner:
    def __init__(self, scan_results, db_file="vuln_db.json"):
        self.scan_results = scan_results
        self.db_file = db_file
        self.vulnerabilities_found = []

    def _log_event(self, event_type, details, level="info"):
        """
        Structures logs as JSON for SIEM ingestion (Lab 3 requirement).
        """
        log_payload = {
            "event_type": event_type,
            "module": "[recon] VulnScanner",
            "data": details
        }
        msg = json.dumps(log_payload)
        
        # FIX: Use named logger instead of global logging object
        if level == "warning":
            logger.warning(msg)
        elif level == "error":
            logger.error(msg)
        else:
            logger.info(msg)

    def load_db(self):
        """Loads the local CVE database from disk."""
        if not os.path.exists(self.db_file):
            self._log_event("DB_ERROR", {"file": self.db_file, "error": "Not Found"}, level="error")
            print(f"[!] Database not found: {self.db_file}")
            return {}
        
        try:
            with open(self.db_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Error decoding {self.db_file}")
            return {}

    def analyze(self):
        print("[*] Analyzing services for vulnerabilities...")
        
        # Log Scan Start
        self._log_event("ANALYSIS_START", {"input_count": len(self.scan_results)})
        
        cve_db = self.load_db()
        
        for item in self.scan_results:
            banner = item.get("banner", "Unknown").lower() 
            port = item.get("port")
            
            # Match service banners to the local CVE database
            for software, vuln_info in cve_db.items():
                if software.lower() in banner:
                    finding = {
                        "host_port": port,
                        "software_detected": software,
                        "cve_id": vuln_info["cve"],
                        "description": vuln_info["description"],
                        "severity": vuln_info["severity"]
                    }
                    self.vulnerabilities_found.append(finding)
                    
                    # Telemetry for SIEM
                    self._log_event("VULN_DETECTED", {
                        "cve": vuln_info['cve'],
                        "severity": vuln_info['severity'],
                        "port": port,
                        "banner": banner,
                        "description": vuln_info['description']
                    }, level="warning")

        # Print results - only show vulnerable services that matched vuln_db.json
        print("\n" + "="*60)
        print(f"[+] Vulnerabilities Identified: {len(self.vulnerabilities_found)}")
        print("="*60)
        
        if self.vulnerabilities_found:
            for vuln in self.vulnerabilities_found:
                print(f" [!] Port {vuln['host_port']}: {vuln['software_detected']}")
                print(f"     CVE: {vuln['cve_id']} | Severity: {vuln['severity']}")
                print(f"     {vuln['description']}")
                print()
        else:
            print(" [-] No known vulnerabilities found in scanned services.")
        
        print("="*60)

        # Log Completion Summary
        status = "Vulnerable" if self.vulnerabilities_found else "Clean"
        self._log_event("ANALYSIS_COMPLETE", {
            "findings_count": len(self.vulnerabilities_found),
            "status": status
        })

        return self.vulnerabilities_found

    def save_report(self, filename="[recon]_vuln_report.json"):
        """Exports scan results (open ports + vulnerabilities) to a JSON file."""
        try:
            report_data = {
                "open_ports": self.scan_results,  # All discovered open ports
                "vulnerabilities": self.vulnerabilities_found  # Only matched CVEs
            }
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)
            
            print(f"[*] Report saved to {filename} ({len(self.scan_results)} ports, {len(self.vulnerabilities_found)} vulns)")
            
            # Log that the artifact was created
            self._log_event("REPORT_GENERATED", {
                "filename": filename,
                "open_ports_count": len(self.scan_results),
                "vulnerabilities_count": len(self.vulnerabilities_found)
            })
            
        except IOError as e:
            print(f"[!] Error saving report: {e}")
            self._log_event("REPORT_ERROR", {"error": str(e)}, level="error")

if __name__ == "__main__":
    # Mock data to demonstrate functionality without running the full recon module
    mock_recon_data = [
        {"port": 21, "service": "ftp", "banner": "vsftpd 2.3.4"},
        {"port": 80, "service": "http", "banner": "Apache httpd 2.4.49"}
    ]
    
    # Initialize and Run
    vuln_tool = VulnScanner(mock_recon_data)
    final_report = vuln_tool.analyze()
    
    # Generate the physical file (Requirement Fix)
    vuln_tool.save_report()
    
    # Console Output
    print("\n--- PHASE 1 REPORT ---")
    for vuln in final_report:
        print(f"[!] ALERT: {vuln['cve_id']} ({vuln['severity']}) - {vuln['description']}")