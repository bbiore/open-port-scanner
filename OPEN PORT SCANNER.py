import socket
import random
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# = Configurable Constants =
PORTS = list(range(1, 1024)) + [3306, 3389, 8080, 8000, 8443]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.81.0",
    "nmap/7.93",
    "Netcat/1.12",
    "python-requests/2.31.0"
]
TIMEOUT = 0.5
BANNER_MAX_LENGTH = 128
MAX_THREADS = 100  # Maximum concurrent threads for scanning

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Failed to resolve {target}.")
        sys.exit(1)

def scan_port(target_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((target_ip, port))
            if result != 0:
                return port, False, ""
            banner_info = ""
            # HTTP/S banner grab
            if port in (80, 8080, 8000, 443, 8443):
                user_agent = random.choice(USER_AGENTS)
                http_req = f"GET / HTTP/1.1\r\nUser-Agent: {user_agent}\r\nHost: {target_ip}\r\n\r\n"
                try:
                    sock.sendall(http_req.encode())
                    banner = sock.recv(BANNER_MAX_LENGTH)
                    banner_info = f" [HTTP] {banner.decode(errors='replace').strip()[:80]}"
                except Exception:
                    pass
            # SSH banner
            elif port == 22:
                try:
                    sock.sendall(b"\n")
                    banner = sock.recv(80)
                    banner_info = f" [SSH] {banner.decode(errors='replace').strip()[:80]}"
                except Exception:
                    pass
            return port, True, banner_info
    except Exception:
        return port, False, ""

def main():
    target = input("Enter an IP or domain to scan: ").strip()
    target_ip = resolve_target(target)
    print(f"[*] Scanning {target} ({target_ip})...\n")

    open_ports = []
    total_ports = len(PORTS)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Submit all scanning tasks
        future_to_port = {executor.submit(scan_port, target_ip, port): port for port in PORTS}

        scanned_ports = 0
        try:
            for future in as_completed(future_to_port):
                port, is_open, banner = future.result()
                scanned_ports += 1
                percent = (scanned_ports / total_ports) * 100
                print(f"\rProgress: {scanned_ports}/{total_ports} ports scanned ({percent:.2f}%)", end="")
                sys.stdout.flush()
                if is_open:
                    open_ports.append((port, banner))
                # Optional pacing to reduce load, comment out if you want max speed
                # time.sleep(random.uniform(0.001, 0.01))
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user.")
            executor.shutdown(wait=False)
            sys.exit(0)

    print("\n\n[*] Scan completed.\n")

    if open_ports:
        print(f"[+] Open ports on {target} ({target_ip}):\n")
        for port, banner in sorted(open_ports):
            print(f"  - Port {port:<5} OPEN {banner}")
    else:
        print(f"[-] No open ports found on {target} ({target_ip}).")

if __name__ == "__main__":
    main()
