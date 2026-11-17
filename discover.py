#!/usr/bin/env python3
import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

PROBE_PORTS = [80, 443, 22, 445, 139, 3389, 8080]
MAX_HOSTS = 1024


def is_alive(ip, timeout):
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                return str(ip)
        except ConnectionRefusedError:
            return str(ip)
        except (socket.timeout, OSError):
            continue
    return None


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"


def main():
    parser = argparse.ArgumentParser(description="Simple host discovery")
    parser.add_argument("network", help="e.g. 192.168.1.0/24")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=0.5)
    args = parser.parse_args()

    try:
        net = ipaddress.ip_network(args.network, strict=False)
    except ValueError:
        sys.exit(f"Invalid network: {args.network}")

    hosts = list(net.hosts()) or [net.network_address]
    if len(hosts) > MAX_HOSTS:
        sys.exit(f"Network too big ({len(hosts)} hosts). Use /22 or smaller.")

    print(f"[*] Checking {len(hosts)} addresses in {net} ...")

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        alive = [h for h in pool.map(lambda ip: is_alive(ip, args.timeout), hosts) if h]

    print(f"\n{'IP ADDRESS':<18}HOSTNAME")
    print("-" * 45)
    for ip in alive:
        print(f"{ip:<18}{get_hostname(ip)}")

    print(f"\n[+] {len(alive)} alive hosts found")


if __name__ == "__main__":
    main()
