# Network Traffic Analyzer

Network Traffic Analyzer is a small command-line tool for capturing and inspecting network traffic in real time. It is built with Python and Scapy, and is intended for learning, lab work, troubleshooting, and basic traffic visibility on a local machine.

This is not a replacement for a full IDS, packet forensic platform, or Wireshark. It focuses on readable terminal output and simple protocol statistics.

## Features

- Lists available network interfaces
- Captures packets from a selected interface
- Supports BPF filters such as `tcp`, `udp`, `port 53`, or `tcp and port 443`
- Identifies common protocols including DNS, HTTP, HTTPS/TLS, SSH, ARP, and ICMP
- Prints colorized live output in the terminal
- Saves captured output to a text file
- Optionally appends protocol statistics to saved output
- Supports both interactive use and command-line arguments

## Requirements

- Python 3.9 or newer
- Linux, macOS, or another system supported by Scapy
- Administrator/root permissions for live packet capture

## Installation

Using a virtual environment is recommended:

```bash
git clone https://github.com/mazanivan/network-traffic-analyzer.git
cd network-traffic-analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

Alternatively, install only the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

After installing with `pip install -e .`, run:

```bash
sudo -E nta
```

You can also run the script directly:

```bash
sudo -E python3 nta.py
```

The `sudo -E` option preserves the current environment. This is useful when the dependencies are installed inside a virtual environment, because plain `sudo python3 nta.py` may use a different Python environment.

## Command-Line Examples

List available interfaces:

```bash
sudo -E nta --list-interfaces
```

Capture 20 DNS packets on `wlan0`:

```bash
sudo -E nta -i wlan0 -c 20 -f "port 53"
```

Capture HTTPS/TLS traffic and save the output with statistics:

```bash
sudo -E nta -i wlan0 -c 50 -f "tcp port 443" -o captures/https.txt --stats
```

Use an interface number from `--list-interfaces`:

```bash
sudo -E nta -i 1 -c 10
```

## Filter Syntax

Filters use the same BPF syntax used by tools such as `tcpdump`.

Examples:

```text
tcp
udp
port 53
host 192.168.1.1
tcp and port 443
not port 22
```

## Example Output

```text
[19:49:15] HTTPS/TLS Client Hello (TCP PA) | 192.168.1.148:53228 -> 20.189.173.15:443 | Encrypted | size: 512 bytes
[19:49:16] DNS Query (UDP port 53) | 192.168.1.148 -> 192.168.1.1 | domain: example.com.
[19:49:17] ARP Request | Who has 192.168.1.1? Tell 192.168.1.148 | size: 42 bytes
```

A longer sample is available in `examples/sample-output.txt`.

## Notes

- Live packet capture usually requires root or administrator privileges.
- The saved output is plain text, not PCAP.
- Stop an unlimited capture with `Ctrl+C`.
- Protocol detection is based on packet layers, common ports, and lightweight TLS handshake checks. It is intentionally simple and may not identify every protocol correctly.

## Project Structure

- `nta.py` - main application
- `requirements.txt` - dependency list for direct installation
- `pyproject.toml` - package metadata and `nta` console command
- `examples/sample-output.txt` - sample text output

## Author

[@mazanivan](https://github.com/mazanivan)
