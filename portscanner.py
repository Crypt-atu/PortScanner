#! /bin/python3

#Port Scanner Tool
#Author: Crypt

import socket
import sys
import threading
import time
import signal
import argparse
import platform
from queue import Queue
from datetime import datetime

# Global variables
print_lock = threading.Lock()
open_ports = []
scan_active = True

# Display banner
def show_banner(hostname):
    system = platform.system()
    print(f"""
    ╔══════════════════════════════════════════════╗
    ║          PYTHON PORT SCANNER                 ║
    ╠══════════════════════════════════════════════╣
    ║  Host: {hostname:<30}        ║
    ║  System: {system:<28}        ║
    ║  Version: 1.0                                ║
    ║  Author: Crypt                               ║
    ╚══════════════════════════════════════════════╝
    """)

#Service Detector Function
def service_detector(port):
    try:
        service = socket.getservbyport(port)
        if service:
            with print_lock:
                return service
    except socket.error:
        with print_lock:
            print("Unknown Service")

# Port scanning function
def port_scan(port, target_ip, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))


            # if result == 0:
            #     with print_lock:
            #         print(f"Port {port}: OPEN")

                # Try to grab the banner
            try:
                banner = s.recv(1024)
                if banner:
                    banner_text = safe_decode(banner)
                    if result == 0:
                        service = service_detector(port)
                        with print_lock:
                            print(f"Port {port}: OPEN --> Service Running: ({service})")
                    with print_lock:
                        print(f"    └Banner: {banner_text}")
                    open_ports.append(port)
            except socket.timeout:
                pass  # Ignore timeout errors for banner grabbing
            except Exception as e:
                with print_lock:
                    print(f"    └ Could not grab banner: {str(e)}")


    except socket.error:
        pass  # Ignore socket errors


# Safe decode function
def safe_decode(banner_bytes):
    encodings = ["utf-8", "ascii", "latin-1", "utf-16", "cp1252", 
                 "iso-8859-2", "iso-8859-15", "shift-jis", "gb18030", "koi8-r"]

    for encoding in encodings:
        try:
            return banner_bytes.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return f"<binary data: {banner_bytes.hex()}>"

# Signal handler for graceful exit
def signal_handler(sig, frame):
    global scan_active
    print("\n[!] Received interrupt signal, shutting down gracefully...")
    scan_active = False
    sys.exit(0)

# Worker function
def worker(target_ip, timeout, port_queue):
    global scan_active
    while scan_active:
        try:
            port = port_queue.get(timeout=1)  # Wait for 1 second for new tasks
            port_scan(port, target_ip, timeout)
            #service_detector(port)#Service Detection
            port_queue.task_done()
        except:
            break  # Exit if no more ports

# Threaded scanner function
def threaded_scan(target_host, start_port, end_port, timeout, thread_count=100):
    global scan_active

    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{target_host}'")
        return

    print(f"\nStarting scan for {target_host} ({target_ip})")
    print(f"Scanning ports {start_port} to {end_port} using {thread_count} threads")
    print("Press Ctrl+C to stop the scan\n")

    start_time = datetime.now()
    
    # Ctimeoutreate and fill the port queue
    port_queue = Queue()
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Create and start worker threads
    threads = []
    for _ in range(min(thread_count, end_port - start_port + 1)):  # Limit threads dynamically
        t = threading.Thread(target=worker, args=(target_ip, timeout, port_queue))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads) and scan_active:
            time.sleep(0.5)  # Prevent CPU overuse
            remaining = port_queue.qsize()
            total = end_port - start_port + 1
            print(f"\rProgress: {total - remaining}/{total} ports scanned", end='', flush=True)

    except KeyboardInterrupt:
        scan_active = False
        print("\n[!] Keyboard interrupt received, stopping scan...")

    finally:
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=1.0)

        # Empty queue to release remaining tasks
        while not port_queue.empty():
            port_queue.get()
            port_queue.task_done()

        end_time = datetime.now()
        scan_duration = end_time - start_time

        print("\n\nScan completed!")
        print(f"Total scan time: {scan_duration}")
        print(f"Open ports found: {sorted(open_ports) if open_ports else 'None'}")

# Main function
def main():
    signal.signal(signal.SIGINT, signal_handler)  # Set signal handler here

    parser = argparse.ArgumentParser(
        description="Python Port Scanner",
        epilog="Example: ./port_scanner.py example.com -s 20 -e 80 -t 1.0"
    )

    parser.add_argument("target", help="Target host (IP or hostname)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout (default: 1.0 sec)")
    parser.add_argument("-c", "--threads", type=float, default=100, help="Threads (default: 100)")

    args = parser.parse_args()

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Error: Invalid port range (must be between 1 and 65535)")
        sys.exit(1)

    if args.threads < 1 or args.threads > 500:
        print("Error: Thread count must be between 1 and 500")
        sys.exit(1)

    show_banner(args.target)
    threaded_scan(args.target, args.start, args.end, args.timeout, args.threads)

if __name__ == "__main__":
    main()
