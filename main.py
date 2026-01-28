from tools import (
    colors,
    port_scan,
    host_discovery,
    traceroute,
    http_probe,
    dns_lookup,
    udp_scan,
    banner_grab,
    ssh_fingerprint,
    smb_probe,
    tls_probe,
    auto_scan,
)
import argparse
import sys
import time

print(colors.BRIGHT_RED + "    _   __     __  ____             __        ")
print(colors.BRIGHT_RED + r"   / | / /__  / /_/ __ \_________  / /_  ___  ")
print(colors.BRIGHT_RED + r"  /  |/ / _ \/ __/ /_/ / ___/ __ \/ __ \/ _ \ ")
print(colors.BRIGHT_RED + r" / /|  /  __/ /_/ ____/ /  / /_/ / /_/ /  __/ ")
print(colors.BRIGHT_RED + r"/_/ |_/\___/\__/_/   /_/   \____/_.___/\___/  ")
print(colors.BRIGHT_YELLOW + "              github.com/imattas\n" + colors.RESET)

def main():
    parser = argparse.ArgumentParser(
        add_help=True,
        usage=(
            "\nPort scanning: --scan <ip_address> [ports]\n"
            "Host discovery: --ping <ip_or_cidr>\n"
            "Traceroute: --trace <host>\n"
            "HTTP probe: --http <url_or_host>\n"
            "DNS lookup: --dns <host_or_ip>\n"
            "UDP scan: --udp <host_or_ip> [ports]\n"
            "Banner grab: --banner <host> [ports]\n"
            "SSH fingerprint: --ssh <host[:port]>\n"
            "SMB fingerprint: --smb <host[:port]>\n"
            "TLS cipher probe: --tls <host[:port]>\n"
            "Subnet auto-scan: --autoscan <ip_or_cidr> [ports]"
        ),
    )

    parser.add_argument("--scan", type=str, metavar="<IP Address>", help="Target IP for port scan")
    parser.add_argument("--ping", type=str, metavar="<IP/CIDR>", help="Ping host or CIDR for live hosts")
    parser.add_argument("--trace", type=str, metavar="<Host>", help="Traceroute to target host")
    parser.add_argument("--http", type=str, metavar="<URL or Host>", help="HTTP/HTTPS probe")
    parser.add_argument("--dns", type=str, metavar="<Host/IP>", help="DNS forward or reverse lookup")
    parser.add_argument("--udp", type=str, metavar="<Host/IP>", help="UDP port scan")
    parser.add_argument("--banner", type=str, metavar="<Host>", help="Grab service banners")
    parser.add_argument("--ssh", type=str, metavar="<Host[:port]>", help="SSH server fingerprint")
    parser.add_argument("--smb", type=str, metavar="<Host[:port]>", help="SMB dialect probe")
    parser.add_argument("--tls", type=str, metavar="<Host[:port]>", help="TLS cipher probe")
    parser.add_argument("--autoscan", type=str, metavar="<IP/CIDR>", help="Ping sweep + port scan")
    parser.add_argument(
        "ports",
        type=str,
        nargs="?",
        metavar="PORTS",
        help="Ports list for scan/udp/banner/autoscan. Examples: 22,80,443 or 1-1024.",
    )

    # If no args at all, just show usage and exit
    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit(0)

    args = parser.parse_args()

    def parse_ports(spec: str, default_ports, default_label: str):
        if spec is None or spec.strip() == "":
            return list(default_ports), default_label

        def parse_int(value: str) -> int:
            try:
                return int(value)
            except ValueError as exc:
                raise ValueError(f"Invalid port: {value}") from exc

        ports = set()
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                if part.count("-") != 1:
                    raise ValueError(f"Invalid port range: {part}")
                start_s, end_s = part.split("-", 1)
                if not start_s or not end_s:
                    raise ValueError(f"Invalid port range: {part}")
                start = parse_int(start_s)
                end = parse_int(end_s)
                if start > end:
                    raise ValueError(f"Invalid port range (start > end): {part}")
                for p in range(start, end + 1):
                    ports.add(p)
            else:
                ports.add(parse_int(part))

        for p in ports:
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range: {p}")

        return sorted(ports), spec

    # ---------- Port scanner ----------
    if args.ports and not (args.scan or args.udp or args.banner or args.autoscan):
        print("\n[!] Ports must follow a scan target. Use --scan/--udp/--banner/--autoscan <ip> [ports].")
        parser.print_usage()
        sys.exit(1)

    if args.scan:
        target = args.scan

        try:
            ports, ports_label = parse_ports(args.ports, range(1, 1025), "1-1024")
        except ValueError as exc:
            print(f"\n[!] {exc}")
            parser.print_usage()
            sys.exit(1)

        print(f"\nScanning {target} ports {ports_label} ...")

        start_time = time.time()
        open_ports = port_scan.scan_port_list(target, ports)
        end_time = time.time()

        print("\nPort Scan Results\n")
        if open_ports:
            for info in open_ports:
                print(info)
        else:
            print("No open ports found in the specified range.")

        print(f"\nScan completed in {end_time - start_time:.2f} seconds.")

    # ---------- Host discovery ----------
    if args.ping:
        try:
            live_hosts, method = host_discovery.discover_hosts(args.ping)
        except ValueError as exc:
            print(f"\n[!] {exc}")
            sys.exit(1)

        method_label = method.upper() if method else "UNKNOWN"
        print(f"\nHost Discovery Results ({method_label})\n")
        if live_hosts:
            for host in live_hosts:
                print(host)
        else:
            print("No live hosts found.")

        print(f"\n{len(live_hosts)} live host(s) detected.")

    # ---------- Traceroute ----------
    if args.trace:
        print(f"\nTraceroute to {args.trace}\n")
        lines, error = traceroute.run_traceroute(args.trace)
        if error:
            print(f"[!] {error}")
        elif lines:
            for line in lines:
                print(line)
        else:
            print("No traceroute output.")

    # ---------- HTTP probe ----------
    if args.http:
        print(f"\nHTTP Probe: {args.http}\n")
        try:
            info = http_probe.probe_http(args.http)
        except Exception as exc:
            print(f"[!] {exc}")
            sys.exit(1)

        print(f"Status: {info['status']} {info['reason']}")
        print(f"Server: {info['server'] or 'n/a'}")
        print(f"Content-Length: {info['content_length'] or 'n/a'}")
        print(f"Elapsed: {info['elapsed_ms']} ms")
        if info["scheme"] == "https":
            print(f"TLS Subject: {info['tls_subject'] or 'n/a'}")
            print(f"TLS Issuer: {info['tls_issuer'] or 'n/a'}")
            print(f"TLS Not After: {info['tls_not_after'] or 'n/a'}")

    # ---------- DNS lookup ----------
    if args.dns:
        print(f"\nDNS Lookup: {args.dns}\n")
        try:
            result = dns_lookup.lookup(args.dns)
        except ValueError as exc:
            print(f"[!] {exc}")
            sys.exit(1)

        if result["names"]:
            print("Names:")
            for name in result["names"]:
                print(f"  {name}")

        if result["addresses"]:
            print("Addresses:")
            for addr in result["addresses"]:
                print(f"  {addr}")

    # ---------- UDP scan ----------
    if args.udp:
        target = args.udp
        common_udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 623, 1900, 4500, 33434]

        try:
            ports, ports_label = parse_ports(args.ports, common_udp_ports, "common UDP ports")
        except ValueError as exc:
            print(f"\n[!] {exc}")
            parser.print_usage()
            sys.exit(1)

        print(f"\nUDP Scanning {target} ports {ports_label} ...")
        start_time = time.time()
        results = udp_scan.scan_udp_ports(target, ports)
        end_time = time.time()

        print("\nUDP Scan Results\n")
        if results:
            for info in results:
                print(info)
        else:
            print("No results.")

        print(f"\nScan completed in {end_time - start_time:.2f} seconds.")

    # ---------- Banner grab ----------
    if args.banner:
        common_tcp_ports = [
            21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995,
            1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 27017,
        ]
        try:
            ports, ports_label = parse_ports(args.ports, common_tcp_ports, "common TCP ports")
        except ValueError as exc:
            print(f"\n[!] {exc}")
            parser.print_usage()
            sys.exit(1)

        print(f"\nBanner Grab Results ({args.banner}) ports {ports_label}\n")
        results = banner_grab.scan_banners(args.banner, ports)
        if results:
            for line in results:
                print(line)
        else:
            print("No banners captured.")

    # ---------- SSH fingerprint ----------
    if args.ssh:
        print(f"\nSSH Fingerprint: {args.ssh}\n")
        try:
            info = ssh_fingerprint.get_ssh_banner(args.ssh)
        except Exception as exc:
            print(f"[!] {exc}")
            sys.exit(1)
        print(f"Host: {info['host']}:{info['port']}")
        print(f"Banner: {info['banner']}")

    # ---------- SMB probe ----------
    if args.smb:
        print(f"\nSMB Probe: {args.smb}\n")
        try:
            info = smb_probe.probe_smb(args.smb)
        except Exception as exc:
            print(f"[!] {exc}")
            sys.exit(1)

        if "error" in info:
            print(f"[!] {info['error']}")
        elif info.get("smb1") == "yes":
            print("SMB1: supported")
        else:
            print(f"SMB2: {info.get('smb2', 'unknown')}")
            print(f"Dialect: {info.get('dialect', 'unknown')}")
            print(f"Signing required: {info.get('signing_required', 'unknown')}")

    # ---------- TLS cipher probe ----------
    if args.tls:
        print(f"\nTLS Cipher Probe: {args.tls}\n")
        try:
            result = tls_probe.probe_tls_ciphers(args.tls)
        except Exception as exc:
            print(f"[!] {exc}")
            sys.exit(1)

        supported = result["supported"]
        if supported:
            for entry in supported:
                print(f"{entry['version']} | {entry['cipher']}")
        else:
            print("No ciphers confirmed with the default list.")

        if result["errors"]:
            print("\nNotes:")
            for err in result["errors"]:
                print(f"- {err}")

    # ---------- Subnet auto-scan ----------
    if args.autoscan:
        common_tcp_ports = [
            22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 3306, 5432, 6379, 8080, 8443
        ]
        try:
            ports, ports_label = parse_ports(args.ports, common_tcp_ports, "common TCP ports")
        except ValueError as exc:
            print(f"\n[!] {exc}")
            parser.print_usage()
            sys.exit(1)

        print(f"\nAuto-scan {args.autoscan} ports {ports_label} ...")
        start_time = time.time()
        results, method = auto_scan.scan_live_hosts(args.autoscan, ports)
        end_time = time.time()

        print(f"\nHost Discovery Method: {method.upper() if method else 'UNKNOWN'}\n")
        if results:
            for host, open_ports in results:
                print(f"{host}:")
                if open_ports:
                    for info in open_ports:
                        print(f"  {info}")
                else:
                    print("  No open ports found.")
        else:
            print("No live hosts found.")

        print(f"\nScan completed in {end_time - start_time:.2f} seconds.")


if __name__ == "__main__":
    main()
