Here’s an updated README file with the correct script name:

markdown
Copy code
# Python Port Scanner (PortScannerHZ.py)

A versatile Python-based port scanner that can scan a range of ports or specific ports on target machines, detect open/closed ports, and identify associated services. This tool can be used interactively via a user-friendly interface or through the command line.

## Features:
- **Multiple Scanning Modes**:
  - Quick Scan (common ports)
  - Thorough Scan (all ports)
  - Custom Range (user-defined port range)
  - Custom Port List (user-defined list of ports)
- **Port Filtering**: Filter the results to show only open, closed, or all ports.
- **Service Detection**: Detect common services running on open ports (e.g., FTP, HTTP, SSH, etc.).
- **Logging**: Log scan results to a log file.
- **CSV Export**: Save scan results in CSV format for analysis.
- **Multi-target Support**: Scan multiple IP addresses or hostnames in one go.
- **Threaded Scanning**: Speed up scans using multi-threading.

## Requirements:
- Python 3.x
- No additional dependencies are required, as the script only uses Python's standard libraries.

## Usage:

### Interactive Mode:
Run the script using Python3 and follow the prompts:

```bash
python3 PortScannerHZ.py

You will be prompted to enter:

Target IP(s) or hostnames (comma-separated)
Scan mode (quick, thorough, custom range, or custom list)
Filter mode (open, closed, or all)
Optional log file name
Optional CSV file name
Command-line Mode:
You can also run the script with command-line arguments:

python3 PortScannerHZ.py --targets [IP or IPs] --mode [quick/thorough/custom_range/custom_list] --filter [open/closed/all] --log [logfile] --csv [csvfile]

Arguments:

--targets: Comma-separated list of IPs or hostnames to scan.
--mode: Scan mode, one of quick, thorough, custom_range, or custom_list.
--start: Starting port (used for custom range scans).
--end: Ending port (used for custom range scans).
--ports: Comma-separated list of specific ports to scan (used for custom list scans).
--filter: Filter mode, one of open, closed, or all.
--log: Path to the log file where results will be saved.
--csv: Path to the CSV file where results will be saved.


Examples:


Quick Scan of common ports on a single IP:

python3 PortScannerHZ.py --targets 192.168.1.1 --mode quick --filter open --log scan_log.txt --csv scan_results.csv

Thorough Scan of all ports on a single IP:

python3 PortScannerHZ.py --targets 192.168.1.1 --mode thorough --filter all --log scan_log.txt --csv scan_results.csv

Custom Range Scan of ports 1000 to 2000 on a list of IPs:

python3 PortScannerHZ.py --targets 192.168.1.1,192.168.1.2 --mode custom_range --start 1000 --end 2000 --filter open --log scan_log.txt --csv scan_results.csv

Custom List Scan of specific ports on multiple IPs:

python3 PortScannerHZ.py --targets 192.168.1.1,192.168.1.2 --mode custom_list --ports 22,80,443 --filter open --log scan_log.txt --csv scan_results.csv

Notes:
Scans can take time depending on the number of targets and ports being scanned.
Be mindful of the legal implications and permissions before scanning networks or systems.
The script uses threading for faster scanning, but excessive use of threads on a large set of targets or ports may lead to resource exhaustion.

Author: Hassan Zaqout.

This version uses the script name `PortScannerHZ.py` and is tailored for your use case. Let me know if you need further edits!

