# Netprobe

Lightweight, stdlib-only network probing toolkit with a single CLI entrypoint.

## Features

- TCP port scanning with basic service banners
- Host discovery (ICMP ping with TCP fallback)
- Traceroute (IPv4/IPv6) via raw sockets
- HTTP/HTTPS probe with TLS certificate details
- DNS forward/reverse lookup
- UDP scanning (open/filtered hints)
- Banner grabbing for common services
- SSH banner fingerprint
- SMB dialect probe (SMB1/SMB2 + signing)
- TLS cipher probe (curated list)
- Subnet auto-scan (ping sweep + port scan)

## Requirements

- Python 3.10+ (tested with 3.11)
- Linux or macOS recommended for traceroute (raw sockets)

> Traceroute needs raw socket access on Linux/macOS: run with `sudo` or grant
> `CAP_NET_RAW` to the Python binary.

## Usage

```bash
python main.py --help
```

### Port scanning

```bash
python main.py --scan 192.168.1.10
python main.py --scan 192.168.1.10 22,80,443
python main.py --scan 192.168.1.10 1-1024
```

### Host discovery (ping sweep)

```bash
python main.py --ping 192.168.1.0/24
```

### Traceroute (raw sockets required)

```bash
sudo python main.py --trace 8.8.8.8
sudo python main.py --trace 2001:4860:4860::8888
```

### HTTP/HTTPS probe

```bash
python main.py --http example.com
python main.py --http https://example.com
```

### DNS lookup

```bash
python main.py --dns example.com
python main.py --dns 8.8.8.8
```

### UDP scan

```bash
python main.py --udp 192.168.1.10
python main.py --udp 192.168.1.10 53,123,161
```

### Banner grab

```bash
python main.py --banner 192.168.1.10
python main.py --banner 192.168.1.10 22,80,443
```

### SSH fingerprint

```bash
python main.py --ssh example.com
python main.py --ssh example.com:2222
```

### SMB probe

```bash
python main.py --smb 192.168.1.20
python main.py --smb 192.168.1.20:445
```

### TLS cipher probe

```bash
python main.py --tls example.com
python main.py --tls example.com:443
```

### Subnet auto-scan

```bash
python main.py --autoscan 192.168.1.0/24
python main.py --autoscan 192.168.1.0/24 22,80,443
```

## Notes

- UDP scanning is best-effort; open/filtered results are normal.
- Some services do not send banners unless probed with protocol-specific data.
- TLS cipher probing uses a curated list for speed; expand if needed.

## Legal

Use only on systems you own or have explicit permission to test.
