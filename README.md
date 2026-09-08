# WiFind

WiFind is a lightweight local network scanner written in Python. It uses Scapy to send ARP broadcast requests on your local subnet and shows the devices that reply with their IP address, MAC address, hostname, and best-effort vendor/manufacturer.

ARP scanning only works on your local broadcast network. Use this tool only on networks you own or are authorized to inspect.

## Features

- Automatically detects the active network interface and local subnet when possible.
- Accepts a manual CIDR range, such as `192.168.1.0/24`, when you want direct control.
- Broadcasts ARP requests and collects active responders.
- Merges live ARP results with the local operating system ARP cache.
- Resolves MAC vendors from Scapy's manufacturer database when available.
- Labels locally administered MAC addresses as private/randomized when a real vendor cannot be inferred.
- Optionally performs reverse DNS and Windows NetBIOS lookups for hostnames.
- Streams scan progress to the UI and appends devices as they are discovered.
- Persists local device history and user aliases under `%LOCALAPPDATA%\WiFind` on Windows or `.wifind/` during local development.
- Adds confidence, device type guesses, source labels, and network health metrics.
- Provides card and table inventory views with filters, sorting, and CSV export.
- Prints results in a clean console table.

## Requirements

- Python 3.10 or newer
- Administrator/root privileges
- Scapy
- Npcap on Windows

## Install

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

3. Windows only: install Npcap from https://npcap.com/#download if it is not already installed. During installation, enable "Install Npcap in WinPcap API-compatible Mode" if Scapy has trouble finding the packet capture driver.

## Run the Web UI

Start the UI from a terminal with administrator privileges. The web app binds to localhost by default.

On Windows, open PowerShell as Administrator:

```powershell
python .\web_app.py
```

On Linux or macOS:

```bash
sudo python3 web_app.py
```

Then open:

```text
http://127.0.0.1:8765
```

The UI auto-detects the default subnet and interface when possible. Press `Smart Scan` without changing anything for the normal workflow. Manual subnet/interface controls are under `Advanced settings`.

On Windows, WiFind resolves friendly adapter names such as `Wi-Fi` to the underlying Npcap device path before scanning. The app refuses to start without Administrator privileges because Scapy/Npcap needs elevated packet access.

To choose another port:

```bash
python web_app.py --port 8090
```

## Run the CLI

### Auto-detect the local subnet

Run the shell as Administrator on Windows:

```powershell
python .\scanner.py
```

Run with `sudo` on Linux or macOS:

```bash
sudo python3 scanner.py
```

### Scan a specific subnet

```bash
python scanner.py 192.168.1.0/24
```

On Linux or macOS with privileges:

```bash
sudo python3 scanner.py 192.168.1.0/24
```

### Select a network interface

```bash
python scanner.py 192.168.1.0/24 --interface "Wi-Fi"
```

Interface names vary by operating system. If auto-detection fails, check your OS network settings and pass the interface name manually.

### Faster scan without hostname lookups

```bash
python scanner.py --no-hostnames
```

## Releases

Put downloadable executables in **GitHub Releases**, not in the repository. `dist/` stays ignored so large build artifacts and machine-specific output do not pollute source control.

Recommended release assets:

- `WiFind-Setup.exe`: preferred user-facing installer.
- `WiFind.exe`: optional portable executable.

Use semantic versions:

- `v1.0.0-beta.1`: first pre-release before the stable installer is promoted.
- `v1.0.0`: first stable release.
- `v1.0.1`: bug fix only.
- `v1.1.0`: backward-compatible feature release.
- `v2.0.0`: breaking change.

Automated release flow:

1. Update version references if needed.
2. Create and push a Git tag such as `v1.0.0-beta.1` or `v1.0.0`.
3. GitHub Actions builds the Windows executable and installer.
4. The workflow uploads `WiFind.exe` and `WiFind-Setup.exe` to the matching GitHub Release.

Manual local builds are still useful for testing packaging changes before tagging.

Build a portable executable:

```powershell
.\packaging\windows\build_windows.ps1
```

Build a setup installer:

```powershell
.\packaging\windows\build_windows.ps1 -Installer
```

The portable executable is written to `dist\WiFind.exe`. The setup installer is written to `dist\installer\WiFind-Setup.exe` when Inno Setup is installed, or `dist\installer\WiFind-Setup-IExpress.exe` through the built-in Windows fallback.

Target devices still need Npcap installed because WiFind depends on a packet capture driver for ARP scanning: https://npcap.com/#download

Example commands for a release:

```powershell
git tag v1.0.0
git push origin v1.0.0
```

## Product Website

The static product website lives in `docs/`. It includes a product landing page and a download page that points to the latest release build.

## Options

## Dashboard

- `Smart Scan`: Runs adapter detection, local ARP-cache import, live ARP probing, hostname enrichment, and device classification.
- Summary metrics: Shows total devices, live ARP devices, cached-only devices, private MACs, unknown hostnames, and gateway candidates.
- Phase timeline: Shows the current scan stage while results stream in.
- Progress facts: Shows elapsed scan time and cache/live device counters.
- Cancel: Stops the current dashboard scan session.
- Device cards: Shows alias, hostname/IP/MAC, vendor, guessed type, confidence, source, notes, and seen count.
- Device details: Click a card or table row to inspect the full identity/debug record.
- Table view: Dense inventory view for sorting and exporting.
- Filter chips: Quickly narrow results to live, cached, unknown, private MAC, gateway, this device, or new devices.
- Aliases: Type a label into a device card and it is saved locally for future scans.
- History: WiFind stores first seen, last seen, seen count, aliases, and last known identity data locally.
- Previous scan comparison: Highlights new devices and counts devices missing since the last completed scan.
- Auto rescan: Optionally reruns Smart Scan on a fixed local interval.
- Notifications: Optional browser notifications can alert when a device appears that was not in the previous scan.

## UI Fields

- `Target subnet`: The IPv4 range to scan. For most home networks this is something like `192.168.1.0/24`, `192.168.0.0/24`, or `10.0.0.0/24`.
- `Interface`: The network adapter used to send ARP packets. On Windows, use the friendly adapter name such as `Wi-Fi`; WiFind resolves it to the Npcap interface internally.
- `Timeout`: How long the scanner waits for ARP replies. Increase this to `4` or `5` seconds on slower Wi-Fi.
- `Retries`: How many extra ARP attempts are sent. Increase this to `2` or `3` if some devices respond inconsistently.
- `Resolve hostnames`: Performs reverse DNS lookups. This can help identify devices, but may slow scans or return `Unknown`.
- `Notify on new devices`: Requests browser notification permission and alerts when a newly observed device appears.
- `Auto rescan`: Repeats Smart Scan using the current settings.
- `Rescan interval`: Controls how often auto rescan runs.
- `Filter results`: Filters the visible result table after a scan.
- `Sort`: Sorts devices by IP, confidence, type, vendor, or last seen.
- `Cards/Table`: Switches between inventory card view and dense table view.
- `Export CSV`: Downloads the current scan result as a CSV file.
- `Privileges`: Shows whether the backend server appears to be running elevated. On Windows it should say `Elevated` when PowerShell was opened as Administrator.
- `Source`: Shows whether the device came from a live ARP reply, the OS ARP cache, or both.

CLI options:

```text
usage: scanner.py [-h] [-i INTERFACE] [-t TIMEOUT] [-r RETRIES] [--no-hostnames] [--no-cache] [target]
```

- `target`: Optional CIDR range to scan, for example `192.168.1.0/24`.
- `-i, --interface`: Network interface to use.
- `-t, --timeout`: Seconds to wait for ARP replies. Default: `2.0`.
- `-r, --retries`: Number of ARP retry attempts. Default: `1`.
- `--no-hostnames`: Skip reverse DNS lookups for faster scans.
- `--no-cache`: Do not merge devices from the operating system ARP cache.

Web UI options:

```text
usage: web_app.py [-h] [--host HOST] [--port PORT] [--quiet]
```

- `--host`: Host to bind. Default: `127.0.0.1`.
- `--port`: Port to bind. Default: `8765`.
- `--quiet`: Disable request logging.

## Example Output

```text
Scanning 192.168.1.0/24 on interface Wi-Fi...
+---------------+-------------------+---------+------------------------+--------+
| IP Address    | MAC Address       | Vendor  | Device Name / Hostname | Source |
+---------------+-------------------+---------+------------------------+--------+
| 192.168.1.1   | AA:BB:CC:DD:EE:01 | Netgear | router.local           | arp    |
| 192.168.1.24  | AA:BB:CC:DD:EE:02 | Apple   | laptop.local           | arp    |
+---------------+-------------------+---------+------------------------+--------+

Found 2 device(s).
```

## Troubleshooting

- `Permission denied` or startup privilege error: re-run the terminal as Administrator on Windows or use `sudo` on Linux/macOS.
- `Could not determine the active network interface`: provide `--interface` and a manual subnet.
- Only your computer appears: stop the server and restart it from an Administrator/root terminal. If it still happens, verify the subnet is correct, increase `Timeout` and `Retries`, and check whether your router has Wi-Fi client isolation, AP isolation, guest network isolation, or VLAN separation enabled.
- No devices found: verify you are connected to Wi-Fi, use the correct subnet, and ensure local client isolation is not enabled on your router.
- Vendor is `Private/randomized MAC`: the device is using a locally administered MAC address, so the original manufacturer cannot be reliably inferred from the OUI.
- Vendor is `Unknown`: the device's OUI may not be in Scapy's local manufacturer database.
