# Network Traffic Analyzer

A Python tool for real-time packet capture and network traffic analysis.  
Great for learning, cybersecurity practice, and portfolio projects.

---

## ✅ Features

- Choose your network interface
- Filter packets by protocol, port, or custom expression
- Live analysis of common protocols (TCP, UDP, ARP, DNS, TLS...)
- Color-coded terminal output
- Option to save clean output and statistics
- Protocol summary at the end

---

## 📦 Quick Setup

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/network-traffic-analyzer.git
cd network-traffic-analyzer
# Network Traffic Analyzer

A Python tool for real-time packet capture and network traffic analysis.  
Great for learning, cybersecurity practice, and portfolio projects.

➡️ [Jump to Installation Guide](#-quick-setup)

---

## ✅ Features

- Choose your network interface
- Filter packets by protocol, port, or custom expression
- Live analysis of common protocols (TCP, UDP, ARP, DNS, TLS...)
- Color-coded terminal output
- Option to save clean output and statistics
- Protocol summary at the end

---

## 📦 Quick Setup

### 1. Clone the repository

git clone https://github.com/<your-username>/network-traffic-analyzer.git  
cd network-traffic-analyzer

### 2. Install dependencies

If you're using Debian/Ubuntu with Python 3.12+:

pip install --break-system-packages -r requirements.txt

---

## ⚠️ Important

Scapy must be installed for the **same user who runs the script**.  
If you install it as a normal user but run the script with `sudo`, it won’t work.

✅ To avoid this issue, **use `sudo -E` when running the script**. This preserves your environment and Python packages:

sudo -E python3 nta.py

> ❌ Do not use just `sudo python3 nta.py` – it will likely result in:  
> `ModuleNotFoundError: No module named 'scapy'`

---

## ▶️ Usage

Run the analyzer with:

sudo -E python3 nta.py

You will be guided through:

- Network interface selection  
- Capture limits  
- Optional filtering  
- Option to save output and protocol statistics

---

## 📋 Example Output

[19:49:15] HTTPS (TCP A) | 20.189.173.15:443 -> 192.168.1.148:53228 | size: 66 bytes  
--------------------------------------------------STATS--------------------------------------------------  
UDP: 5  
ARP: 24  
HTTPS: 7

---

## 📁 Files

nta.py           # Main program  
requirements.txt # Dependencies  
README.md        # This file

---

## 🛠️ TODO

- Export to CSV/JSON  
- Add testing  
- GUI version

---

## 📄 License

MIT License

---

## 👤 Author

[@mazanivan](https://github.com/mazanivan)
