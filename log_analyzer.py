import json
import os
import time
from defense_block import DefenseResponder

TELEMETRY_FILE = "project_telemetry.log"

class LogAnalyzer:
    def __init__(self, cooldown_sec=30, auto_isolate_on_c2=True):
        self.responder = DefenseResponder()
        self.cooldown_sec = cooldown_sec
        self.auto_isolate_on_c2 = auto_isolate_on_c2
        self.last_trigger = {}  # key -> last_ts

    def _on_cooldown(self, key):
        now = time.time()
        last = self.last_trigger.get(key, 0)
        return (now - last) < self.cooldown_sec

    def _trip(self, key):
        self.last_trigger[key] = time.time()

    def _maybe_json(self, line: str):
        # Try to parse the last JSON object in the line
        idx = line.find("{")
        if idx == -1:
            return None
        try:
            return json.loads(line[idx:].strip())
        except Exception:
            return None

    def follow(self, path):
        with open(path, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                yield line

    def handle_event(self, evt: dict):
        if not isinstance(evt, dict):
            return

        module = evt.get("module")
        etype = evt.get("event_type")
        details = evt.get("details", {})

        # IDS-driven triggers (note: module name now has [defense] prefix)
        if module == "[defense] IDS":
            if etype == "PORT_SCAN_OUTBOUND":
                target = details.get("destination")
                key = f"BLK_OUT_{target}"
                if target and not self._on_cooldown(key):
                    print(f"\n[SIEM] Outbound port scan detected. Blocking outbound traffic to {target}.")
                    self.responder.block_ip(target, direction="out")
                    self._trip(key)

            elif etype == "SSH_BRUTE_OUTBOUND":
                target = details.get("destination")
                key = f"BLK_SSH_OUT_{target}"
                if target and not self._on_cooldown(key):
                    print(f"\n[SIEM] Outbound SSH brute detected. Blocking outbound to {target}.")
                    self.responder.block_ip(target, direction="out")
                    self._trip(key)

            elif etype == "C2_TRAFFIC":
                key = "ISOLATE_ON_C2"
                if self.auto_isolate_on_c2 and not self._on_cooldown(key):
                    print("\n[SIEM] C2 traffic detected. Isolating host.")
                    self.responder.isolate_host()
                    self._trip(key)

            elif etype == "ARP_SPOOF":
                attacker = details.get("attacker_mac")
                key = f"ARP_SPOOF_{attacker}"
                if not self._on_cooldown(key):
                    print(f"\n[SIEM] CRITICAL: ARP Spoofing detected! Attacker MAC: {attacker}")
                    print("       This indicates a Man-in-the-Middle attack.")
                    self._trip(key)

        # C2 server confirmation (note: module name now has [c2] prefix)
        if module == "[c2] C2_SERVER" and etype in ("SESSION_ESTABLISHED", "STATUS"):
            if etype == "SESSION_ESTABLISHED":
                key = "ISOLATE_ON_C2"
                if self.auto_isolate_on_c2 and not self._on_cooldown(key):
                    print("\n[SIEM] C2 session established. Isolating host.")
                    self.responder.isolate_host()
                    self._trip(key)

        # Keylogger – just log it, do NOT auto-terminate (User controls this via Option 3)
        if module == "KEYLOGGER" and etype == "STARTED":
            key = "ANTI_KL"
            if not self._on_cooldown(key):
                print("\n[SIEM] Keylogger activity detected. (Manual termination available in Phase 5 Menu)")
                self._trip(key)

    def analyze(self):
        if not os.path.exists(TELEMETRY_FILE):
            print(f"[SIEM] {TELEMETRY_FILE} not found. Start the framework so modules can write telemetry.")
            return

        print(f"[*] SIEM Analyzer watching {TELEMETRY_FILE} ...")
        try:
            for line in self.follow(TELEMETRY_FILE):
                evt = self._maybe_json(line)
                if evt:
                    self.handle_event(evt)
        except KeyboardInterrupt:
            print("\n[*] SIEM stopped.")
        except Exception as e:
            print(f"[SIEM] Error: {e}")

if __name__ == "__main__":
    LogAnalyzer().analyze()
