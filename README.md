# 📡 Project Name (Replace with your chosen name)

A lightweight, custom local network scanner built in Python using the Scapy library. This tool maps your local subnet via ARP scanning, instantly retrieving the IP addresses, MAC addresses, and vendor details of every device connected to your Wi-Fi network.

## ✨ Features
* **Fast ARP Scanning:** Leverages Address Resolution Protocol (ARP) requests for higher accuracy than standard ping sweeps.
* **Auto-Subnet Detection:** Automatically discovers your local IP range so you don't have to configure it manually.
* **Vendor Lookup:** Resolves MAC addresses to identify device manufacturers (e.g., Apple, Samsung, Intel).
* **Clean Console Output:** Displays active network nodes in a beautifully formatted table.

## 🚀 Quick Start

### 1. Prerequisites
This tool requires Python 3.x and administrator privileges (root/sudo) to manipulate network packets.

### 2. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com
cd your-repo-name
pip install -r requirements.txt
```

### 3. Usage
Run the script with administrative privileges:
```bash
# On Linux/macOS
sudo python scanner.py

# On Windows (Run command prompt as Administrator)
python scanner.py
```
