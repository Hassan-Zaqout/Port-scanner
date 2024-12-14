import socket
import argparse
from datetime import datetime
import threading
import csv
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import sys

# RUN BY PYTHON3 Finalproject2.py FOR INTERACTIVE MODE
# OR python3 Finalproject2.py --targets [IP OR IPS] --mode [quick/thorough/custom_range/custom_list] --filter [open/closed/all] --log [logfile] --csv [csvfile] FOR COMMAND LINE MODE
# IF YOU RUN FROM THE IDE YOU MIGHT HAVE ISSUES WITH THE ARGPARSE

#######################
# UTILITY FUNCTIONS
#######################

### Port Range Validation ###
def validate_ports(start_port, end_port):
    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
        raise ValueError("Ports must be in the range 0-65535.")
    if start_port > end_port:
        raise ValueError("Start port must be less than or equal to end port.")
    return start_port, end_port

### Service Detection ###
def detect_service(port):
    services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
        27017: "MongoDB"
    }
    return services.get(port, "Unknown Service")

#######################
# SCANNING FUNCTIONS
#######################

### Security Scanning & Port Detection ###
def scan_port(target, port, out, fmode, logfile=None):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((target, port))
            status = "Open"
            service = detect_service(port)
            if filter_results(port, status, service, fmode):
                out.append((port, status, service))
                print(f"Port {port}: {status} - {service}")
                if logfile:
                    log_results(logfile, f"Port {port}: {status} - {service}")
    except:
        if fmode in ["all", "closed"]:
            out.append((port, "Closed", ""))
            print(f"Port {port}: Closed")
            if logfile:
                log_results(logfile, f"Port {port}: Closed")

### Logging and Reporting ###
def log_results(file_name, message):
    with threading.Lock():
        with open(file_name, "a") as file:
            file.write(f"{datetime.now()} - {message}\n")

### Port Filtering & Output Customization ###
def filter_results(port, status, service, filter_mode):
    if filter_mode == "open" and status == "Open":
        return True
    elif filter_mode == "closed" and status == "Closed":
        return True
    elif filter_mode == "all":
        return True
    return False

#######################
# SCAN MODES
#######################

### Custom Port Range Scanning ###
def custom_range_scan(target, start, end, fmode, out, logfile=None):
    print(f"\nScanning target: {target}")
    print(f"Ports: {start}-{end}")
    
    with ThreadPoolExecutor(max_workers=50) as executor:  # needed alot of help with setting up threading properly still not 100% sure on if this is correct - used StackOverflow forum posts for help.
        port_range = range(start, end + 1)
        results_lock = threading.Lock()
        
        def scan_worker(port):
            local_out = []
            scan_port(target, port, local_out, fmode, logfile)
            if local_out:
                with results_lock:
                    out.extend(local_out)
        
        list(executor.map(scan_worker, port_range))

### Custom Ports List Scanning ###
def custom_port_list_scan(target, ports, fmode, out, logfile=None):
    print(f"\nScanning target: {target}")
    print(f"Custom Ports: {ports}")
    
    with ThreadPoolExecutor(max_workers=50) as executor: # needed alot of help with setting up threading properly still not 100% sure on if this is correct - used StackOverflow forum posts for help.
        results_lock = threading.Lock()
        
        def scan_worker(port):
            local_out = []
            scan_port(target, port, local_out, fmode, logfile)
            if local_out:
                with results_lock:
                    out.extend(local_out)
        
        list(executor.map(scan_worker, ports))

### Quick Scan Mode ###
def quick_scan(target, fmode, out, logfile=None):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    print(f"\nPerforming a quick scan for target: {target}")
    
    with ThreadPoolExecutor(max_workers=50) as executor: # needed alot of help with setting up threading properly still not 100% sure on if this is correct - used StackOverflow forum posts for help.
        results_lock = threading.Lock()
        
        def scan_worker(port):
            local_out = []
            scan_port(target, port, local_out, fmode, logfile)
            if local_out:
                with results_lock:
                    out.extend(local_out)
        
        list(executor.map(scan_worker, common_ports))

### Thorough Scan Mode ###
def thorough_scan(target, fmode, out, logfile=None):
    print(f"\nPerforming a thorough scan for target: {target}")
    
    # Increase chunk size for better performance
    chunk_size = 2500  # Increased from 1000
    
    with ThreadPoolExecutor(max_workers=50) as executor: # needed alot of help with setting up threading properly still not 100% sure on if this is correct - used StackOverflow forum posts for help.
        results_lock = threading.Lock()
        futures = []
        
        def scan_chunk(start, end):
            for port in range(start, end):
                local_out = []
                scan_port(target, port, local_out, fmode, logfile)
                if local_out:
                    with results_lock:
                        out.extend(local_out)
        
        # Submit chunks as separate tasks
        for start in range(0, 65536, chunk_size):
            end = min(start + chunk_size, 65536)
            futures.append(executor.submit(scan_chunk, start, end))
        
        # Wait for completion and handle exceptions
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error in scan chunk: {e}")

#######################
# ORG AND LOG FUNCTIONS
#######################

### Support for Multiple Scanning Targets & Output Customization ###
def scan_multiple_targets(targets, mode, fmode, logfile, csvfile, start=None, end=None, ports=None):
    results = []
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for target in targets:
        print(f"\nStarting scan for target: {target}")
        if mode == "quick":
            quick_scan(target, fmode, results, logfile)
        elif mode == "thorough":
            thorough_scan(target, fmode, results, logfile)
        elif mode == "custom_range" and start is not None and end is not None:
            custom_range_scan(target, start, end, fmode, results, logfile)
        elif mode == "custom_list" and ports:
            custom_port_list_scan(target, ports, fmode, results, logfile)

    # Write results to CSV
    if csvfile:
        with open(csvfile, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Scan Time", "Target", "Port", "Status", "Service"])
            for target in targets:
                for port, status, service in results:
                    writer.writerow([scan_time, target, port, status, service])

### IP Range Scanning ###
def resolve_targets(targets):
    resolved_targets = []
    for target in targets.split(','):
        target = target.strip()
        if not target:
            continue
        try:
            resolved_ip = socket.gethostbyname(target)
            resolved_targets.append(resolved_ip)
        except socket.gaierror:
            print(f"Error: Invalid target {target}")
    return resolved_targets

#######################
# USER INTERFACE
#######################

### User-friendly CLI ###
def get_user_input():
    print("\n=== Port Scanner ===")
    
    # Get targets
    while True:
        ips = input("\nTarget IP(s) or hostname(s) (comma-separated): ").strip()
        if ips:
            break
        print("Error: Enter at least one target")
    
    # Get scan mode
    print("\nSelect Scan Mode:")
    print("1. Quick (Common ports)")
    print("2. Thorough (All ports)")
    print("3. Custom Range")
    print("4. Custom Port List")
    
    while True:
        choice = input("\nEnter choice (1-4): ").strip()
        if choice in ['1', '2', '3', '4']:
            break
        print("Error: Please enter a number between 1-4")
    
    modes = {
        '1': 'quick',
        '2': 'thorough',
        '3': 'custom_range',
        '4': 'custom_list'
    }
    mode = modes[choice]
    
    # Initializeing port variables
    start = end = None
    ports = None
    
    # ask for port information based on mode
    if mode == 'custom_range':
        while True:
            try:
                start = int(input("\nEnter start port (0-65535): "))
                end = int(input("Enter end port (0-65535): "))
                validate_ports(start, end)
                break
            except ValueError as e:
                print(f"Error: {e}")
    
    elif mode == 'custom_list':
        while True:
            try:
                ports_input = input("\nEnter port numbers (comma-separated): ")
                ports = [int(p.strip()) for p in ports_input.split(',')]
                for p in ports:
                    if not 0 <= p <= 65535:
                        raise ValueError("Ports must be in range 0-65535")
                break
            except ValueError as e:
                print(f"Error: {e}")
    
    # ask user for filter mode
    print("\nSelect Filter Mode:")
    print("1. Show all ports")
    print("2. Show only open ports")
    print("3. Show only closed ports")
    
    while True:
        fchoice = input("\nEnter choice (1-3): ").strip()
        if fchoice in ['1', '2', '3']:
            break
        print("Error: Please enter a number between 1-3")
    
    filters = {
        '1': 'all',
        '2': 'open',
        '3': 'closed'
    }
    fmode = filters[fchoice]
    
    #ask user for what output they want
    print("\nOptional Outputs (press Enter to skip):")
    logfile = input("Enter log file name include file extension: ").strip() or None
    csvfile = input("Enter CSV file name include file extension: ").strip() or None
    
    return {
        'targets': ips,
        'scan_mode': mode,
        'filter_mode': fmode,
        'log_file': logfile,
        'csv_file': csvfile,
        'start_port': start,
        'end_port': end,
        'custom_ports': ports
    }

#######################
# PROGRAM ENTRY POINTS
#######################

### Command-line and Interactive Mode Handler ###
def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Port Scanner")
        parser.add_argument("--targets", required=True, help="Comma-separated IPs/hostnames")
        parser.add_argument("--mode", choices=["quick", "thorough", "custom_range", "custom_list"], 
                          required=True, help="Scan mode")
        parser.add_argument("--start", type=int, default=0, help="Start port")
        parser.add_argument("--end", type=int, default=65535, help="End port")
        parser.add_argument("--ports", help="Custom ports (comma-separated)")
        parser.add_argument("--filter", choices=["open", "closed", "all"], 
                          default="all", help="Port filter")
        parser.add_argument("--log", help="Log file")
        parser.add_argument("--csv", help="CSV file")

        args = parser.parse_args()
        targets = resolve_targets(args.targets)
        ports = [int(p) for p in args.ports.split(',')] if args.ports else None
        
        scan_multiple_targets(
            targets,
            args.mode,
            args.filter,
            args.log,
            args.csv,
            start=args.start,
            end=args.end,
            ports=ports
        )
    else:
        try:
            params = get_user_input()
            targets = resolve_targets(params['targets'])
            scan_multiple_targets(
                targets,
                params['scan_mode'],
                params['filter_mode'],
                params['log_file'],
                params['csv_file'],
                start=params['start_port'],
                end=params['end_port'],
                ports=params['custom_ports']
            )
        except KeyboardInterrupt:
            print("\nScan cancelled")
        except Exception as e:
            print(f"\nError: {e}")

# Script entry point
if __name__ == "__main__":
    main()
