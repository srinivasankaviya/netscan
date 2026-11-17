#!/usr/bin/env python3
"""
netscan.py - Simple multithreaded TCP port scanner with banner grabbing.

Use ONLY on systems you own or have written permission to test.
"""
import argparse
import html
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

KNOWN_VULNERABLE = {
    "vsftpd 2.3.4": ("Backdoor command execution (CVE-2011-2523)", "CRITICAL"),
    "OpenSSH_4": ("Outdated OpenSSH, multiple known CVEs", "HIGH"),
    "Apache/2.2": ("End-of-life Apache 2.2", "HIGH"),
    "ProFTPD 1.3.3": ("Known vulnerabilities in ProFTPD 1.3.3", "HIGH"),
}

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-alt",
}

SEVERITY_COLORS = {
    "CRITICAL": "#b71c1c",
    "HIGH": "#e65100",
    "MEDIUM": "#f9a825",
    "LOW": "#2e7d32",
}


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def grab_banner(sock, port):
    try:
        if port in (80, 8080, 8000):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip().replace("\r\n", " | ")
    except (socket.timeout, OSError):
        return ""


def check_vulns(banner):
    findings = []
    for signature, (issue, severity) in KNOWN_VULNERABLE.items():
        if signature.lower() in banner.lower():
            findings.append({"issue": issue, "severity": severity})
    return findings


def scan_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = grab_banner(sock, port)
            return {
                "port": port,
                "service": COMMON_SERVICES.get(port, "unknown"),
                "banner": banner,
                "findings": check_vulns(banner),
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def generate_html(report, path):
    rows = ""
    for r in report["open_ports"]:
        if r["findings"]:
            issues = "".join(
                f'<span class="badge" style="background:'
                f'{SEVERITY_COLORS.get(f["severity"], "#555")}">'
                f'{html.escape(f["severity"])}</span> '
                f'{html.escape(f["issue"])}<br>'
                for f in r["findings"]
            )
        else:
            issues = '<span class="ok">No known issues</span>'
        rows += (
            f"<tr><td>{r['port']}</td>"
            f"<td>{html.escape(r['service'])}</td>"
            f"<td><code>{html.escape(r['banner'][:120])}</code></td>"
            f"<td>{issues}</td></tr>\n"
        )

    if not rows:
        rows = '<tr><td colspan="4">No open ports found.</td></tr>'

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report - {html.escape(report['target'])}</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#f4f6f8; margin:0; padding:24px; color:#222; }}
  .card {{ background:#fff; max-width:960px; margin:auto; padding:24px; border-radius:10px;
           box-shadow:0 2px 8px rgba(0,0,0,.1); }}
  h1 {{ margin-top:0; }}
  .meta {{ color:#555; margin-bottom:20px; line-height:1.6; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; padding:10px; border-bottom:1px solid #e0e0e0; vertical-align:top; }}
  th {{ background:#263238; color:#fff; }}
  code {{ font-size:12px; word-break:break-all; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:12px; font-weight:bold; }}
  .ok {{ color:#2e7d32; }}
  .wrap {{ overflow-x:auto; }}
</style>
</head>
<body>
<div class="card">
  <h1>Port Scan Report</h1>
  <div class="meta">
    <b>Target:</b> {html.escape(report['target'])} ({html.escape(report['ip'])})<br>
    <b>Scanned at:</b> {html.escape(report['scanned_at'])}<br>
    <b>Duration:</b> {report['duration_seconds']:.2f}s<br>
    <b>Open ports:</b> {len(report['open_ports'])}
  </div>
  <div class="wrap">
  <table>
    <tr><th>Port</th><th>Service</th><th>Banner</th><th>Findings</th></tr>
    {rows}
  </table>
  </div>
</div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)


def main():
    parser = argparse.ArgumentParser(description="Simple Python port scanner")
    parser.add_argument("target", help="IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="e.g. 1-1024 or 22,80,443 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("-o", "--output", help="save results to JSON file")
    parser.add_argument("--html", help="save an HTML report, e.g. report.html")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"Cannot resolve host: {args.target}")

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.target} ({ip}) - {len(ports)} ports")
    start = datetime.now()

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = [r for r in pool.map(
            lambda p: scan_port(ip, p, args.timeout), ports) if r]

    elapsed = (datetime.now() - start).total_seconds()

    print(f"\n{'PORT':<8}{'SERVICE':<12}BANNER")
    print("-" * 60)
    for r in results:
        print(f"{r['port']:<8}{r['service']:<12}{r['banner'][:60]}")
        for f in r["findings"]:
            print(f"   [!] {f['severity']}: {f['issue']}")

    print(f"\n[+] {len(results)} open ports found in {elapsed:.2f}s")

    report = {
        "target": args.target,
        "ip": ip,
        "scanned_at": start.isoformat(),
        "duration_seconds": elapsed,
        "open_ports": results,
    }

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] JSON report saved to {args.output}")

    if args.html:
        generate_html(report, args.html)
        print(f"[+] HTML report saved to {args.html}")


if __name__ == "__main__":
    main()


