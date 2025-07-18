# Network Traffic Analyzer

A Python-based tool for real-time packet capture and network traffic analysis. Designed for educational use, cybersecurity practice, and portfolio demonstration. It supports multiple protocols, customizable filters, and user-friendly terminal output.

---

## Quick Installation

- [Quick Install for Linux/macOS](#quick-install-for-linuxmacos)

---

## Features

- Selectable network interface
- Packet filtering by protocol, port, or custom expression
- Real-time protocol recognition (TCP, UDP, ARP, DNS, TLS, etc.)
- Color-coded terminal output
- Clean, savable output (without color codes)
- Protocol statistics summary
- Interactive command-line interface

---

## Requirements

- Python 3.x
- Administrator/root privileges for packet capturing  
- Python packages:
  - Scapy – `pip install scapy`
  - Colorama – `pip install colorama`

---

## Installation

```bash
pip install scapy colorama
```

---

## Usage

Run the analyzer with root/administrator privileges:

```bash
sudo python3 nta.py
```

You will be guided through:
- Network interface selection
- Packet count limit
- Optional filtering
- Option to save output and protocol statistics

---

## Example Output

```
[19:49:15] DNS Query (UDP port 53) | fe80::878:9e47:8ad5:b0c0 -> ff02::fb | domain: LIFX White to Warm 667871._hap._tcp.local.
[19:49:15] HTTPS (TCP A) | 20.189.173.15:443 -> 192.168.1.148:53228 | size: 66 bytes
--------------------------------------------------STATS--------------------------------------------------
UDP: 5
STP: 11
ARP: 24
HTTPS: 7
UDP6: 2
OTHER: 1
```

---

## Project Structure

```
nta.py         # Main analyzer script
test/          # Example output files
build.sh       # Build script for Linux/macOS
```

---

## Building an Executable

### Quick Install for Linux/macOS

```bash
chmod +x build.sh
./build.sh
sudo ./nta
```

The build script will:
- Set up a virtual environment
- Install all dependencies
- Build a standalone executable using PyInstaller
- Clean up temporary build files

---

## Roadmap / TODO

- Export results to CSV and JSON
- Add unit tests
- Extend protocol support
- Develop a GUI version

---

## Contributing

Contributions, suggestions, and pull requests are welcome!

---

## License

This project is licensed under the MIT License.

---

## Author

mazanivan
This project is licensed under the MIT License.

---

## Author

mazanivan
This project is licensed under the MIT License.

---

## Author

mazanivan
