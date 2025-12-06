import json
import logging
import socket
import time
from collections import defaultdict
from scapy.all import sniff, TCP, IP, ARP, conf

LOG_FILE = "project_telemetry.log"
C2_PORT = 9999

def _setup_logger():
    logger = logging.getLogger("IDS")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(LOG_FILE)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(message)s"))
        logger.addHandler(fh)
    logger.propagate = False
    return logger

class IDS:
    def __init__(
        self,
        target_ip: str = None,
        interface: str = None,
        scan_window_sec: int = 10,
        scan_unique_port_threshold: int = 10,  # Reduced from 20 for faster detection
        ssh_window_sec: int = 15,
        ssh_attempt_threshold: int = 4,  # Reduced from 8 for faster detection
        cooldown_sec: int = 30
    ):
        """
        target_ip: victim IP we are attacking from Kali. Used to focus detection and route selection.
        """
        self.logger = _setup_logger()
        self.target_ip = target_ip
        # Pick interface used to reach the target so we sniff in the right place
        if interface:
            self.interface = interface
        else:
            try:
                # conf.route.route returns (iface, src, gw) for destination
                self.interface = conf.route.route(target_ip or "8.8.8.8")[0]
            except Exception:
                self.interface = conf.iface
        # Determine our local (Kali) IP on that interface for direction checks
        try:
            self.local_ip = conf.route.route(target_ip or "8.8.8.8")[1]
        except Exception:
            # Fallback
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                self.local_ip = s.getsockname()[0]
            except Exception:
                self.local_ip = "0.0.0.0"
            finally:
                s.close()

        # Port-scan tracking: for each peer, track last-seen timestamp per destination port (outbound) or source port (inbound)
        self.scan_window_sec = scan_window_sec
        self.scan_unique_port_threshold = scan_unique_port_threshold
        self.recent_ports_out = defaultdict(dict)  # dst_ip -> {dport: ts}
        self.recent_ports_in = defaultdict(dict)   # src_ip -> {sport: ts}

        # SSH brute tracking: per target
        self.ssh_window_sec = ssh_window_sec
        self.ssh_attempt_threshold = ssh_attempt_threshold
        self.ssh_attempts_out = defaultdict(list)  # dst_ip -> [ts,...]
        self.ssh_attempts_in = defaultdict(list)   # src_ip -> [ts,...] (not used, but kept for symmetry)

        # Cooldown per alert key (prevents spam)
        self.cooldown_sec = cooldown_sec
        self.last_alert = {}
        
        # ARP Spoof tracking
        self.arp_table = {}

        # Build a tight BPF filter to reduce noise
        if self.target_ip:
            self.bpf = f"(tcp and host {self.target_ip}) or arp"
        else:
            # No target specified - capture all TCP to detect scans
            self.bpf = "tcp or arp"

        self._print_banner()

    def _print_banner(self):
        print(f"[*] IDS on interface: {self.interface} | local IP: {self.local_ip}")
        if self.target_ip:
            print(f"[*] Monitoring activity involving target: {self.target_ip}")
        print(f"[*] Port-scan threshold: {self.scan_unique_port_threshold} unique dports in {self.scan_window_sec}s")
        print(f"[*] SSH brute threshold: {self.ssh_attempt_threshold} attempts in {self.ssh_window_sec}s")
        print(f"[*] C2 port monitored: {C2_PORT}")
        print("[*] Press Ctrl+C to stop.")

    def _log_event(self, event_type, details, severity="INFO"):
        payload = {
            "module": "[defense] IDS",
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        self.logger.info(json.dumps(payload))

    def _on_cooldown(self, key):
        now = time.time()
        last = self.last_alert.get(key, 0)
        return (now - last) < self.cooldown_sec

    def _trip_alert(self, key, console_msg, event_type, details, severity="WARNING"):
        if self._on_cooldown(key):
            return
        print(f"\n[IDS] {console_msg}")
        self._log_event(event_type, details, severity=severity)
        self.last_alert[key] = time.time()

    def _prune_map(self, m: dict, window: int):
        now = time.time()
        for peer, ports in list(m.items()):
            for p, ts in list(ports.items()):
                if now - ts > window:
                    del ports[p]
            if not ports:
                del m[peer]

    def _prune_list(self, d: dict, window: int):
        now = time.time()
        for peer, lst in list(d.items()):
            d[peer] = [t for t in lst if now - t <= window]
            if not d[peer]:
                del d[peer]

    def _handle_portscan(self, direction, peer_ip, port):
        now = time.time()
        if direction == "outbound":
            ports_map = self.recent_ports_out[peer_ip]
            ports_map[port] = now
            self._prune_map(self.recent_ports_out, self.scan_window_sec)
            count = len(ports_map)
            if count >= self.scan_unique_port_threshold:
                key = f"PS_OUT_{peer_ip}"
                msg = f"Outbound port scan from {self.local_ip} to {peer_ip} ({count} unique ports in {self.scan_window_sec}s)"
                details = {
                    "direction": "outbound",
                    "source": self.local_ip,
                    "destination": peer_ip,
                    "unique_ports_in_window": count
                }
                self._trip_alert(key, msg, "PORT_SCAN_OUTBOUND", details, severity="WARNING")
                # Reset for this peer to avoid immediate re-trigger
                self.recent_ports_out[peer_ip].clear()
        else:
            ports_map = self.recent_ports_in[peer_ip]
            ports_map[port] = now
            self._prune_map(self.recent_ports_in, self.scan_window_sec)
            count = len(ports_map)
            if count >= self.scan_unique_port_threshold:
                key = f"PS_IN_{peer_ip}"
                msg = f"Inbound port scan from {peer_ip} to {self.local_ip} ({count} unique ports in {self.scan_window_sec}s)"
                details = {
                    "direction": "inbound",
                    "source": peer_ip,
                    "destination": self.local_ip,
                    "unique_ports_in_window": count
                }
                self._trip_alert(key, msg, "PORT_SCAN_INBOUND", details, severity="WARNING")
                self.recent_ports_in[peer_ip].clear()

    def _handle_ssh_brute(self, direction, peer_ip):
        now = time.time()
        if direction == "outbound":
            lst = self.ssh_attempts_out[peer_ip]
            lst.append(now)
            self._prune_list(self.ssh_attempts_out, self.ssh_window_sec)
            if len(lst) >= self.ssh_attempt_threshold:
                key = f"SSH_OUT_{peer_ip}"
                msg = f"Outbound SSH brute attempts from {self.local_ip} to {peer_ip} (>= {self.ssh_attempt_threshold} in {self.ssh_window_sec}s)"
                details = {
                    "direction": "outbound",
                    "source": self.local_ip,
                    "destination": peer_ip,
                    "attempts_in_window": len(lst)
                }
                self._trip_alert(key, msg, "SSH_BRUTE_OUTBOUND", details, severity="WARNING")
                self.ssh_attempts_out[peer_ip].clear()
        else:
            lst = self.ssh_attempts_in[peer_ip]
            lst.append(now)
            self._prune_list(self.ssh_attempts_in, self.ssh_window_sec)
            if len(lst) >= self.ssh_attempt_threshold:
                key = f"SSH_IN_{peer_ip}"
                msg = f"Inbound SSH brute attempts from {peer_ip} to {self.local_ip} (>= {self.ssh_attempt_threshold} in {self.ssh_window_sec}s)"
                details = {
                    "direction": "inbound",
                    "source": peer_ip,
                    "destination": self.local_ip,
                    "attempts_in_window": len(lst)
                }
                self._trip_alert(key, msg, "SSH_BRUTE_INBOUND", details, severity="WARNING")
                self.ssh_attempts_in[peer_ip].clear()

    def _handle_c2(self, direction, peer_ip, sport, dport, flags):
        key = f"C2_{direction}_{peer_ip}"
        msg = f"C2 traffic detected ({direction}) peer={peer_ip} sport={sport} dport={dport}"
        details = {
            "direction": direction,
            "local_ip": self.local_ip,
            "peer_ip": peer_ip,
            "sport": sport,
            "dport": dport,
            "flags": int(flags)
        }
        self._trip_alert(key, msg, "C2_TRAFFIC", details, severity="CRITICAL")

    def _handle_arp(self, p):
        op = p[ARP].op
        if op == 2:  # is-at (reply)
            psrc = p[ARP].psrc
            hwsrc = p[ARP].hwsrc
            
            # Use 'arp' or 'ether' as protocol details
            # If we haven't seen this IP, just learn it
            if psrc not in self.arp_table:
                self.arp_table[psrc] = hwsrc
            elif self.arp_table[psrc] != hwsrc:
                # MAC address changed for known IP -> Likely Spoofing
                old_mac = self.arp_table[psrc]
                msg = f"ARP SPOOFING DETECTED! IP {psrc} changed MAC from {old_mac} to {hwsrc}"
                key = f"ARP_SPOOF_{psrc}"
                details = {
                    "ip": psrc,
                    "old_mac": old_mac,
                    "new_mac": hwsrc,
                    "attacker_mac": hwsrc
                }
                # Update table to look for next change
                self.arp_table[psrc] = hwsrc
                self._trip_alert(key, msg, "ARP_SPOOF", details, severity="CRITICAL")

    def _pkt(self, p):
        # ARP Handling
        if p.haslayer(ARP):
            self._handle_arp(p)
            return

        if not (p.haslayer(IP) and p.haslayer(TCP)):
            return

        ip = p[IP]
        tcp = p[TCP]
        src = ip.src
        dst = ip.dst
        sport = tcp.sport
        dport = tcp.dport
        flags = tcp.flags

        # Determine direction relative to this Kali host
        if src == self.local_ip:
            direction = "outbound"
            peer = dst
            peer_port = dport
        elif dst == self.local_ip:
            direction = "inbound"
            peer = src
            peer_port = sport
        else:
            # Not directly involving this host; ignore
            return

        # If target_ip was provided, ignore other peers to reduce noise
        if self.target_ip and peer != self.target_ip and dport != 22 and sport != 22 and dport != C2_PORT and sport == C2_PORT:
            return

        # Port scan detection: track SYNs across different ports
        if flags & 0x02:  # SYN set
            self._handle_portscan(direction, peer, peer_port)

            # SSH brute: many SYNs to port 22
            if (direction == "outbound" and dport == 22) or (direction == "inbound" and sport == 22):
                self._handle_ssh_brute(direction, peer)

        # C2 detection: any TCP traffic with port 9999
        if dport == C2_PORT or sport == C2_PORT:
            self._handle_c2(direction, peer, sport, dport, flags)

    def start(self):
        print(f"[*] IDS sniffing with BPF: {self.bpf}")
        try:
            sniff(iface=self.interface, filter=self.bpf, prn=self._pkt, store=False)
        except KeyboardInterrupt:
            print("\n[*] IDS stopped by operator.")
        except Exception as e:
            print(f"[!] IDS error: {e}")

if __name__ == "__main__":
    # Minimal standalone run (edit target_ip as needed)
    ids = IDS(target_ip=None)
    ids.start()
