# Python Port Scanner

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



