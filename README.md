# Network Traffic Analyzer

## Quick Installation

- [Quick Install for Windows](#quick-install-for-windows)
- [Quick Install for Linux/macOS](#quick-install-for-linuxmacos)

## Project Description
Network Traffic Analyzer is a Python tool for capturing and analyzing network packets in real time. It recognizes common protocols, displays statistics, and allows you to save clean output to a file. Designed for learning and portfolio demonstration.

## Features
- Select network interface
- Filter packets by protocol, port, or custom filter
- Protocol recognition (TCP, UDP, ARP, DNS, TLS, etc.)
- Color-coded terminal output
- Save output to file (without colors)
- Show protocol statistics
- User-friendly terminal prompts

## Requirements
- Python 3.x
- [Scapy](https://scapy.net/) (`pip install scapy`)
- [Colorama](https://pypi.org/project/colorama/) (`pip install colorama`)
- Administrator/root privileges for packet capture

## Installation
```bash
pip install scapy colorama
```

## Usage
Run the analyzer with root privileges:
```bash
sudo python3 nta.py
```
Follow the prompts to select interface, set packet count, and filter. You can save the output and statistics to a file.

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

## Project Structure
- `nta.py` — main analyzer script
- `test` — sample output file
- `build.sh` / `build.bat` — build scripts for creating standalone executables

## License
MIT License

## Author
Diego

## Contributing
Pull requests and suggestions are welcome.

## TODO / Planned Improvements
- Export to CSV/JSON
- Unit tests
- More protocol support
- GUI version

## Building an Executable

### Quick Install for Linux/macOS

If needed, make the script executable:
```bash
chmod +x build.sh
```
Run the build script:
```bash
./build.sh
```
Then run the compiled executable with root privileges:
```bash
sudo ./nta
```

### Quick Install for Windows

Run the build script as Administrator:
```cmd
build.bat
```
Then run the compiled executable as Administrator:
```cmd
nta.exe
```

The build scripts will:
- Create a virtual environment
- Install all dependencies
- Build a standalone executable using PyInstaller
- Clean up build files

**Note:**  
You can run the executable (`nta` or `nta.exe`) directly, without Python or pip. Always run it with administrator/root privileges for packet capture.

## Tips
- Always run the executable with administrator/root privileges for packet capture.
- The executable is portable and does not require Python or pip on the target machine.
- For development, you can still run the Python script directly.
Suppose you want to add a new feature, like exporting results to CSV, but you don't want to break the main code while working on it. You can:

1. **Create a new branch for the feature:**
   ```bash
   git checkout -b export-csv
   ```
2. **Work on your changes in this branch.**  
   You can make mistakes or experiment without affecting the main code.

3. **Commit your changes:**
   ```bash
   git add .
   git commit -m "Add CSV export feature"
   ```

4. **Switch back to the main branch and merge your feature:**
   ```bash
   git checkout master
   git merge export-csv
   ```

5. **Now the main branch has your new feature, and you can delete the feature branch:**
   ```bash
   git branch -d export-csv
   ```

**This way, you can:**
- Work on multiple features or bugfixes at the same time (each in its own branch)
- Keep the main code stable
- Only merge finished and tested features into the main branch

## Tips
- Always run the executable with administrator/root privileges for packet capture.
- The executable is portable and does not require Python or pip on the target machine.
- For development, you can still run the Python script directly.
