
#!/usr/bin/env python3
"""
netscan.py - Multithreaded TCP port scanner with banner grabbing,
HTML/JSON reports and optional CVE lookup using the NVD API.

Use ONLY on systems you own or have written permission to test.

Examples:
  python3 netscan.py 127.0.0.1 -p 1-10000 --html report.html
  python3 netscan.py 192.168.1.10 -p 21,22,80 --cve --html report.html
"""
import argparse
import html
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ---------------------------------------------------------------- settings
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional, free from NVD
# NVD asks for about 1 request per 6 seconds without a key
MIN_INTERVAL = 0.7 if NVD_API_KEY else 6.5
_last_request = 0.0
_cve_cache = {}

# Small offline list, used even when --cve is not given
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
    "UNKNOWN": "#555555",
}

# How to recognise software in a banner, and its CPE names in the NVD database
PRODUCTS = [
    {"label": "OpenSSH", "regex": r"OpenSSH[_ ](\d+(?:\.\d+)+)(?:p(\d+))?",
     "cpes": [("openbsd", "openssh")],
     "update": lambda m: f"p{m.group(2)}" if m.group(2) else None},
    {"label": "Apache httpd", "regex": r"Apache/(\d+(?:\.\d+)+)",
     "cpes": [("apache", "http_server")]},
    {"label": "nginx", "regex": r"nginx/(\d+(?:\.\d+)+)",
     "cpes": [("nginx", "nginx"), ("f5", "nginx")]},
    {"label": "lighttpd", "regex": r"lighttpd/(\d+(?:\.\d+)+)",
     "cpes": [("lighttpd", "lighttpd")]},
    {"label": "Microsoft IIS", "regex": r"Microsoft-IIS/(\d+(?:\.\d+)+)",
     "cpes": [("microsoft", "internet_information_services")]},
    {"label": "vsftpd", "regex": r"vsftpd[ _](\d+(?:\.\d+)+)",
     "cpes": [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")]},
    {"label": "ProFTPD", "regex": r"ProFTPD[ _](\d+(?:\.\d+)+)([a-z]?)",
     "cpes": [("proftpd", "proftpd")],
     "update": lambda m: m.group(2) or None},
    {"label": "Python", "regex": r"Python/(\d+(?:\.\d+)+)",
     "cpes": [("python", "python")]},
]


# ---------------------------------------------------------------- scanning
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


# ------------------------------------------------------------- CVE lookup
def parse_banner(banner):
    """Find a known product and version inside a banner, or return None."""
    for p in PRODUCTS:
        m = re.search(p["regex"], banner, re.IGNORECASE)
        if m:
            update = p["update"](m) if "update" in p else None
            return {"label": p["label"], "version": m.group(1),
                    "update": update, "cpes": p["cpes"]}
    return None


def severity_from_score(score):
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def best_cvss(cve):
    """Return (score, severity) using the newest CVSS version available."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            m = entries[0]
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                sev = data.get("baseSeverity") or m.get("baseSeverity")
                return float(score), (sev or severity_from_score(score)).upper()
    return None, "UNKNOWN"


def short_description(cve, limit=110):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            text = " ".join(d.get("value", "").split())
            return text if len(text) <= limit else text[:limit - 3].rstrip() + "..."
    return ""


def fetch_json(url, headers=None, timeout=20):
    hdrs = {"User-Agent": "netscan-student-project"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_nvd(info, max_cves):
    """Ask NVD for CVEs matching a product/version. Never raises."""
    global _last_request
    merged = {}
    total = 0
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    for vendor, product in info["cpes"]:
        cpe = (f"cpe:2.3:a:{vendor}:{product}:{info['version']}:"
               f"{info['update'] or '*'}:*:*:*:*:*:*")
        if cpe in _cve_cache:
            data = _cve_cache[cpe]
        else:
            wait = MIN_INTERVAL - (time.time() - _last_request)
            if wait > 0:
                time.sleep(wait)
            query = urllib.parse.urlencode(
                {"virtualMatchString": cpe, "resultsPerPage": 200}, safe=":*")
            try:
                data = fetch_json(f"{NVD_URL}?{query}", headers)
            except urllib.error.HTTPError as e:
                _last_request = time.time()
                if e.code in (403, 429):
                    return {"findings": [], "total": 0,
                            "error": "NVD rate limit hit, wait a minute and retry"}
                return {"findings": [], "total": 0, "error": f"NVD returned HTTP {e.code}"}
            except (urllib.error.URLError, socket.timeout, OSError):
                return {"findings": [], "total": 0,
                        "error": "could not reach NVD (check internet connection)"}
            except ValueError:
                return {"findings": [], "total": 0, "error": "unexpected reply from NVD"}
            _last_request = time.time()
            _cve_cache[cpe] = data

        total += int(data.get("totalResults", 0))
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or cve_id in merged:
                continue
            score, sev = best_cvss(cve)
            merged[cve_id] = {
                "cve": cve_id,
                "score": score,
                "severity": sev,
                "summary": short_description(cve),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }

    ranked = sorted(merged.values(),
                    key=lambda f: f["score"] if f["score"] is not None else -1,
                    reverse=True)[:max_cves]
    for f in ranked:
        score = f"CVSS {f['score']}" if f["score"] is not None else "no score"
        f["issue"] = f"{f['cve']} ({score}): {f['summary']}"
    return {"findings": ranked, "total": len(merged) if merged else total, "error": None}


def enrich_with_cves(results, max_cves):
    for r in results:
        info = parse_banner(r["banner"])
        if not info:
            continue
        name = f"{info['label']} {info['version']}{info['update'] or ''}"
        r["detected"] = name
        print(f"[*] Looking up CVEs for {name} (port {r['port']}) ...")
        out = query_nvd(info, max_cves)
        if out["error"]:
            print(f"    [!] CVE lookup failed: {out['error']}")
            r["cve_error"] = out["error"]
            continue
        existing = " ".join(f["issue"] for f in r["findings"])
        new = [f for f in out["findings"] if f["cve"] not in existing]
        r["findings"].extend(new)
        r["cve_total"] = out["total"]
        print(f"    {out['total']} CVEs match, showing top {len(out['findings'])}")


# ----------------------------------------------------------------- report
def render_findings(r):
    parts = []
    for f in r["findings"]:
        color = SEVERITY_COLORS.get(f["severity"], "#555")
        badge = (f'<span class="badge" style="background:{color}">'
                 f'{html.escape(f["severity"])}</span> ')
        if f.get("cve"):
            score = f"CVSS {f['score']}" if f.get("score") is not None else "no score"
            link = (f'<a href="{html.escape(f["url"])}" target="_blank" '
                    f'rel="noopener">{html.escape(f["cve"])}</a>')
            parts.append(f'{badge}{link} ({html.escape(score)}): '
                         f'{html.escape(f["summary"])}<br>')
        else:
            parts.append(f'{badge}{html.escape(f["issue"])}<br>')
    shown = sum(1 for f in r["findings"] if f.get("cve"))
    extra = r.get("cve_total", 0) - shown
    if extra > 0:
        parts.append(f'<small>+ {extra} more CVEs on NVD</small><br>')
    if r.get("cve_error"):
        parts.append(f'<small>CVE lookup failed: {html.escape(r["cve_error"])}</small>')
    if not parts:
        return '<span class="ok">No known issues</span>'
    return "".join(parts)


def generate_html(report, path):
    rows = ""
    for r in report["open_ports"]:
        detected = (f'<br><small>{html.escape(r["detected"])}</small>'
                    if r.get("detected") else "")
        rows += (
            f"<tr><td>{r['port']}</td>"
            f"<td>{html.escape(r['service'])}{detected}</td>"
            f"<td><code>{html.escape(r['banner'][:120])}</code></td>"
            f"<td>{render_findings(r)}</td></tr>\n"
        )
    if not rows:
        rows = '<tr><td colspan="4">No open ports found.</td></tr>'

    note = ""
    if report.get("cve_lookup"):
        note = ('<p class="note">CVE matches come from the NVD database and are '
                'based on service banners. Banners can be changed and Linux '
                'distributions often back-port fixes, so treat these as '
                'potential findings to verify.</p>')

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report - {html.escape(report['target'])}</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#f4f6f8; margin:0; padding:24px; color:#222; }}
  .card {{ background:#fff; max-width:1000px; margin:auto; padding:24px; border-radius:10px;
           box-shadow:0 2px 8px rgba(0,0,0,.1); }}
  h1 {{ margin-top:0; }}
  .meta {{ color:#555; margin-bottom:20px; line-height:1.6; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ text-align:left; padding:10px; border-bottom:1px solid #e0e0e0; vertical-align:top; }}
  th {{ background:#263238; color:#fff; }}
  code {{ font-size:12px; word-break:break-all; }}
  a {{ color:#0a66c2; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:12px; font-weight:bold; }}
  .ok {{ color:#2e7d32; }}
  .note {{ color:#555; font-size:13px; margin-top:16px; }}
  .wrap {{ overflow-x:auto; }}
</style>
</head>
<body>
<div class="card">
  <h1>Scan Report</h1>
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
  {note}
</div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)


# ------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description="Python port scanner with CVE lookup")
    parser.add_argument("target", help="IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="e.g. 1-1024 or 22,80,443 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--cve", action="store_true",
                        help="look up CVEs on NVD for detected software (needs internet)")
    parser.add_argument("--max-cves", type=int, default=5,
                        help="max CVEs to show per service (default 5)")
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

    if args.cve and results:
        if not NVD_API_KEY:
            print("[i] No NVD API key set, so lookups run about 1 per 6 seconds.")
        enrich_with_cves(results, args.max_cves)

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
        "cve_lookup": args.cve,
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
