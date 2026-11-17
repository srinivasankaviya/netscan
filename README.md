
# netscan

A simple multithreaded TCP port scanner and host discovery tool written in Python (standard library only, no extra installs).

## Features
- Multithreaded TCP port scanning
- Banner grabbing and service detection
- Basic known-vulnerable version matching
- JSON and HTML report output
- Subnet host discovery (`discover.py`)

## Requirements
- Python 3.8 or newer

## Usage

Scan a host and save reports:

    python3 netscan.py 127.0.0.1 -p 1-10000 -o report.json --html report.html

Scan specific ports:

    python3 netscan.py 192.168.1.10 -p 22,80,443

Find alive hosts in a network:

    python3 discover.py 192.168.1.0/24

## Options

| Option | Description |
|--------|-------------|
| `-p`, `--ports` | Ports to scan, e.g. `1-1024` or `22,80,443` |
| `-t`, `--threads` | Number of threads (default 100) |
| `--timeout` | Connection timeout in seconds (default 1.0) |
| `-o`, `--output` | Save JSON report |
| `--html` | Save HTML report |

## Validation
Results were compared with Nmap on a local test server (port 8080). Both tools detected the same open port.

## Roadmap
- CVE lookup using the OSV.dev / NVD APIs
- Service-specific probes
- UDP scanning

## Disclaimer
Use only on systems you own or have written permission to test. Unauthorized scanning may be illegal.# netscan
vulnerability scanner
