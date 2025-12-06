import json
import logging
import os
import shlex
import subprocess

LOG_FILE = "project_telemetry.log"

def _setup_logger():
    logger = logging.getLogger("DEFENSE")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(LOG_FILE)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(message)s"))
        logger.addHandler(fh)
    logger.propagate = False
    return logger

def _run(cmd):
    """Run a shell command and return (rc, stdout, stderr)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out.strip(), err.strip()

class DefenseResponder:
    def __init__(self):
        self.logger = _setup_logger()

    def _log(self, action, details, severity="INFO"):
        payload = {"module": "[defense] DEFENSE", "event_type": action, "severity": severity, "details": details}
        self.logger.info(json.dumps(payload))

    def _need_root(self):
        return os.geteuid() != 0

    def _iptables_exists(self):
        return subprocess.call(["which", "iptables"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

    def _ensure_rule(self, chain, params):
        """
        Insert rule if not present (idempotent).
        Example: chain="OUTPUT", params=["-d", ip, "-j", "DROP"]
        """
        check_cmd = ["iptables", "-C", chain] + params
        insert_cmd = ["iptables", "-I", chain, "1"] + params
        rc, _, _ = _run(check_cmd)
        if rc != 0:
            rc2, _, err = _run(insert_cmd)
            return rc2 == 0, err
        return True, ""

    def block_ip(self, ip, direction="both"):
        """
        direction:
          - 'out'  -> drop outbound to ip (OUTPUT)
          - 'in'   -> drop inbound from ip (INPUT)
          - 'both' -> both directions
        """
        if self._need_root():
            print("[DEFENSE] Root required for firewall changes.")
            return

        if not self._iptables_exists():
            print("[DEFENSE] iptables not found. Install iptables or provide an nftables implementation.")
            return

        print(f"[*] Blocking IP {ip} (direction={direction})...")
        success = True
        errs = []

        if direction in ("in", "both"):
            ok, err = self._ensure_rule("INPUT", ["-s", ip, "-j", "DROP"])
            success &= ok
            if err: errs.append(err)

        if direction in ("out", "both"):
            ok, err = self._ensure_rule("OUTPUT", ["-d", ip, "-j", "DROP"])
            success &= ok
            if err: errs.append(err)

        if success:
            print("    [+] Firewall rule(s) in place.")
            self._log("BLOCK_IP", {"ip": ip, "direction": direction})
        else:
            print(f"    [!] Failed to apply firewall rules: {'; '.join(errs)}")
            self._log("BLOCK_IP_ERROR", {"ip": ip, "direction": direction, "errors": errs}, severity="ERROR")

    def _default_interface(self):
        # Try to read the default route interface
        rc, out, _ = _run(["ip", "route", "show", "default"])
        if rc == 0 and out:
            parts = out.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        # Fallback
        return "eth0"

    def isolate_host(self, interface=None):
        iface = interface or self._default_interface()
        if self._need_root():
            print("[DEFENSE] Root required to isolate host.")
            return
        print(f"[!!!] Isolating host: bringing interface {iface} DOWN")
        rc, _, err = _run(["ip", "link", "set", iface, "down"])
        if rc == 0:
            print("    [+] Interface disabled. To restore: sudo ip link set {} up".format(iface))
            self._log("ISOLATE_HOST", {"interface": iface}, severity="CRITICAL")
        else:
            print(f"    [!] Isolation failed: {err}")
            self._log("ISOLATE_HOST_ERROR", {"interface": iface, "error": err}, severity="ERROR")

    def anti_keylogger(self):
        """
        Kills processes running keylogger_local.py and truncates keylog_dump.txt.
        """
        print("[*] Anti-keylogger scan...")
        # Find PIDs by command line match
        rc, out, _ = _run(["pgrep", "-f", "keylogger_local.py"])
        killed_any = False
        if rc == 0 and out:
            for pid in out.strip().splitlines():
                pid = pid.strip()
                if pid:
                    print(f"    [!] Killing PID {pid}")
                    _run(["kill", "-9", pid])
                    killed_any = True

        # Clean the dump file if present
        if os.path.exists("[keylogger]_keylog_dump.txt"):
            try:
                with open("[keylogger]_keylog_dump.txt", "w") as f:
                    f.truncate(0)
                print("    [+] [keylogger]_keylog_dump.txt truncated.")
            except Exception as e:
                print(f"    [!] Could not truncate keylog_dump.txt: {e}")

        if killed_any:
            self._log("ANTI_KEYLOGGER", {"status": "killed"})
        else:
            print("    [*] No keylogger process found.")
            self._log("ANTI_KEYLOGGER", {"status": "clean"})

    def run_hardening(self):
        """Performs basic hardening checks and prints recommendations."""
        print("\n[*] Running Hardening Check...")
        print("="*50)
        
        checks_passed = 0
        total_checks = 0
        
        # Check 1: SSH root login disabled
        total_checks += 1
        ssh_config = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config):
            try:
                with open(ssh_config, 'r') as f:
                    content = f.read()
                    if "PermitRootLogin no" in content:
                        print("[+] SSH root login is disabled")
                        checks_passed += 1
                    else:
                        print("[!] WARNING: SSH root login may be enabled")
                        print("    Remediation: Set 'PermitRootLogin no' in /etc/ssh/sshd_config")
            except:
                print("[?] Could not read SSH config")
        else:
            print("[?] SSH config not found (may not be Linux)")
        
        # Check 2: Firewall status
        total_checks += 1
        if self._iptables_exists():
            rc, out, _ = _run(["iptables", "-L", "-n"])
            if rc == 0:
                if "DROP" in out or "REJECT" in out:
                    print("[+] Firewall has blocking rules configured")
                    checks_passed += 1
                else:
                    print("[!] WARNING: No DROP/REJECT rules in firewall")
                    print("    Remediation: Configure iptables with default DROP policy")
        else:
            print("[?] iptables not available")
        
        # Summary
        print("="*50)
        print(f"[*] Hardening Score: {checks_passed}/{total_checks} checks passed")
        
        if checks_passed < total_checks:
            print("[!] Review warnings above and apply remediations")
        else:
            print("[+] All basic hardening checks passed")
        
        self._log("HARDENING_CHECK", {"passed": checks_passed, "total": total_checks})

