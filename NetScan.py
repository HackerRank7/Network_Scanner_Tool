#!/usr/bin/env python3

import argparse
import socket
import subprocess
import platform
import re
import sys
import time
import json
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"

if platform.system().lower() == "windows":
    try:
        import colorama
        colorama.init()
    except ImportError:
        pass


def found(text):
    print(f"{BLUE}{text}{RESET}")


def not_found(text):
    print(f"{RED}{text}{RESET}")


def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def grab_banner(sock):
    try:
        sock.settimeout(1.5)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner
    except Exception:
        return ""


def probe_http(target, port, use_ssl=False):
    try:
        import ssl as ssl_mod
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        if use_ssl:
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=target)
        req = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        data = s.recv(2048).decode(errors="ignore")
        s.close()
        m = re.search(r"Server:\s*(.+)", data)
        return m.group(1).strip() if m else ""
    except Exception:
        return ""


def scan_port(target, port, timeout=1.0):
    result = {"port": port, "open": False, "service": "", "banner": "", "version": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((target, port)) == 0:
            result["open"] = True
            try:
                result["service"] = socket.getservbyport(port)
            except Exception:
                result["service"] = "unknown"

            banner = grab_banner(sock)
            if not banner and port in (80, 8080):
                banner = probe_http(target, port, use_ssl=False)
            if not banner and port in (443, 8443):
                banner = probe_http(target, port, use_ssl=True)

            result["banner"] = banner
            result["version"] = extract_version(banner)
        sock.close()
    except Exception:
        pass
    return result


def extract_version(banner):
    if not banner:
        return ""
    m = re.search(r"([A-Za-z][A-Za-z0-9_\-]+)[/ ]v?(\d+[\.\d]*\d)", banner)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    return ""


def port_scan(target, ports, max_threads=100):
    open_ports = []
    print(f"\n[*] Scanning {len(ports)} ports on {target} ...")
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in ports}
        for future in as_completed(futures):
            res = future.result()
            if res["open"]:
                open_ports.append(res)
                tag = f"  [+] Port {res['port']:<5} OPEN  {res['service']:<10}"
                if res["banner"]:
                    tag += f"  banner: {res['banner'][:60]}"
                found(tag)
    open_ports.sort(key=lambda r: r["port"])
    return open_ports


def guess_os_by_ttl(target):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        cmd = ["ping", param, "1", target]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
        if not m:
            return "Unknown (no TTL in reply)"
        ttl = int(m.group(1))
        if ttl <= 64:
            return f"Likely Linux/Unix (TTL={ttl})"
        elif ttl <= 128:
            return f"Likely Windows (TTL={ttl})"
        else:
            return f"Likely network device/router (TTL={ttl})"
    except Exception as e:
        return f"Unknown (ping failed: {e})"


def lookup_vulnerabilities(keyword, max_results=5):
    if not keyword:
        return []
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    })
    url = f"{NVD_API}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "python-recon-tool"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    score = metrics[key][0]["cvssData"].get("baseScore", "N/A")
                    break
            results.append({"id": cve_id, "score": score, "desc": desc[:150]})
        return results
    except Exception as e:
        return [{"id": "ERROR", "score": "-", "desc": str(e)}]


def ask_target():
    while True:
        target = input("Enter target IP or hostname (e.g. 192.168.1.10 or scanme.nmap.org): ").strip()
        if target:
            return target
        print("  [!] This field cannot be empty, please try again.\n")


def ask_ports():
    print("\nWhich ports do you want to scan?")
    print("  1) Common ports (fast, ~21 well-known ports)")
    print("  2) All ports (1-65535, this will take a long time)")
    print("  3) Custom range (e.g. 1-1000)")
    print("  4) Custom list (e.g. 22,80,443)")
    while True:
        choice = input("Choose an option (1-4): ").strip()
        if choice == "1":
            return COMMON_PORTS
        elif choice == "2":
            return list(range(1, 65536))
        elif choice == "3":
            rng = input("  Enter range (e.g. 1-1000): ").strip()
            try:
                return parse_ports(rng)
            except Exception:
                print("  [!] Invalid format, please try again.\n")
        elif choice == "4":
            lst = input("  Enter ports separated by commas (e.g. 22,80,443): ").strip()
            try:
                return parse_ports(lst)
            except Exception:
                print("  [!] Invalid format, please try again.\n")
        else:
            print("  [!] Please enter only 1, 2, 3 or 4.\n")


def ask_vuln_check():
    choice = input("\nDo you also want to check for vulnerabilities (CVEs)? [Y/n]: ").strip().lower()
    return choice not in ("n", "no")


def run_interactive():
    print("=" * 60)
    print("           Network Recon Tool — Interactive Mode")
    print("  --> Only scan your own systems or authorized targets <--")
    print("=" * 60)
    target = ask_target()
    ports = ask_ports()
    do_vuln = ask_vuln_check()
    threads_in = input("\nThreads (press Enter for default 100): ").strip()
    threads = int(threads_in) if threads_in.isdigit() else 100
    run_scan(target, ports, do_vuln, threads)


def run_scan(target, ports, do_vuln=True, threads=100):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        not_found(f"[!] Could not resolve host: {target}")
        sys.exit(1)

    print("=" * 60)
    print(f"      Target            : {target} ({target_ip})")
    print("  --> Only scan systems you own or are authorized to test <--")
    print("=" * 60)

    start = time.time()
    open_ports = port_scan(target_ip, ports, max_threads=threads)
    elapsed = time.time() - start

    summary = f"\n[*] Scan complete in {elapsed:.2f}s. {len(open_ports)} open port(s) found."
    if open_ports:
        found(summary)
    else:
        not_found(summary)

    print("\n[*] OS fingerprint (heuristic, based on TTL):")
    print("   ", guess_os_by_ttl(target_ip))

    if not open_ports:
        return

    if do_vuln:
        print("\n[*] Checking known vulnerabilities (NVD) for detected services...")
        for res in open_ports:
            keyword = res["version"]
            if not keyword:
                print(f"\n  Port {res['port']} - {res['service'] or 'unknown'}")
                not_found("    [!] No specific version detected (only a generic banner was found, "
                           "e.g. 'gws' or empty). Skipping CVE lookup — searching with a generic "
                           "service name would return unrelated/misleading results.")
                continue
            print(f"\n  Port {res['port']} - {keyword}")
            vulns = lookup_vulnerabilities(keyword)
            if not vulns:
                not_found("    No CVE matches found.")
            for v in vulns:
                found(f"    {v['id']}  CVSS:{v['score']}  {v['desc']}")
            time.sleep(6)

    print("\n[*] Done. Review findings and patch/upgrade affected services as needed.")


def main():
    if len(sys.argv) == 1:
        run_interactive()
        return

    parser = argparse.ArgumentParser(description="Authorized network recon tool")
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="common",
                         help="Ports: 'common', 'all', '1-1000', or '22,80,443'")
    parser.add_argument("--no-vuln", action="store_true",
                         help="Skip NVD vulnerability lookup")
    parser.add_argument("--threads", type=int, default=100, help="Scan thread count")
    args = parser.parse_args()

    target = args.target or ask_target()

    if args.ports == "all":
        ports = list(range(1, 65536))
    elif args.ports == "common":
        ports = COMMON_PORTS
    else:
        ports = parse_ports(args.ports)

    run_scan(target, ports, do_vuln=not args.no_vuln, threads=args.threads)


if __name__ == "__main__":
    main()
