# USAGE - airscope v0.3.9

## Prerequisites and Installation

### System Requirements

| Requirement | Linux | Windows | macOS |
|-------------|-------|---------|-------|
| Python | >= 3.11 | >= 3.11 (via WSL2) | >= 3.11 |
| USB adapter | Supported chipset | Same + WinUSB driver | Supported chipset |
| Dependencies | `libusb-1.0-0-dev`, `iw` | `pyusb` (bundles libusb) | `libusb` |

### Installation

#### Step 1: Clone the repository
```bash
git clone https://github.com/ToySldr/airscope_v2.git
cd airscope_v2
```

#### Step 2: Install dependencies

**Linux (Ubuntu/Kali/Debian)**:
```bash
sudo apt install python3 python3-venv libusb-1.0-0-dev iw
uv sync --group dev      # or: pip install -e .
```

**Windows**:
```powershell
# Option 1: One-click setup (installs WSL2 + usbipd-win)
.\scripts\vm\setup.bat

# Option 2: Manual
winget install dorssel.usbipd-win    # USB passthrough to WSL2
# Then inside WSL2, follow Linux steps above
```

**macOS**:
```bash
brew install uv libusb python@3.12
uv sync --group dev
```

#### Step 3: Verify setup
```bash
uv run python -m airscope.doctor   # Pre-flight check
```

---

## Running airscope

### Interactive Mode (TUI) - Most Common

```bash
uv run airscope
# or simply:
airscope
```

**First-run behavior**:
1. Checks setup (udev rules, libusb, adapter detection)
2. Shows splash screen with device list
3. Select adapter and press Enter/Space to start

### Headless Batch Mode (`--auto`)

For automated scanning and attacking without TUI:

```bash
uv run airscope --auto
```

**Options**:
| Flag | Description |
|------|-------------|
| `--scan-secs N` | Scan duration (default: 15 seconds) |
| `--targets "bssid,ssid"` | Filter to specific targets (comma-separated) |
| `--list` | List discovered APs with channel/signal/SSID info |
| `--session PATH` | Session log file path |
| `--wps-timeout N` | WPS attack timeout in seconds |
| `--pmkid-timeout N` | PMKID capture timeout |
| `--hs-timeout N` | Handshake capture timeout |
| `--sae-timeout N` | SAE handshake timeout |

**Example - Scan for 30 seconds, then attack strongest AP**:
```bash
uv run airscope --auto --scan-secs 30
```

**Example - List all discovered networks**:
```bash
uv run airscope --auto --list
```

### Web Dashboard Mode

Start HTTP server with web UI:

```bash
uv run airscope --web
# or specify host/port:
uv run airscope --web --host 0.0.0.0 --port 8080
```

**Options**:
| Flag | Description |
|------|-------------|
| `--host HOST` | Bind address (default: 127.0.0.1) |
| `--port PORT` | Port number (default: 8765) |
| `--demo` | Run with simulated data (no hardware needed) |
| `--no-browser` | Suppress automatic browser opening |

### Export Mode

Generate reports from captures:

```bash
uv run airscope --export csv -o ./reports/
uv run airscope --export netxml -o ./networks.xml
uv run airscope --export html -o ./dashboard/
uv run airscope --export all      # All formats to default directory
```

**Options**:
| Flag | Description |
|------|-------------|
| `-o DIR` | Output directory (default: `airscope_exports/`) |
| `--session PATH` | Batch session log for additional context |

---

## TUI Controls

### Splash Screen
- **Arrow keys**: Navigate device list
- **Enter/Space**: Select adapter and start session
- **Ctrl+P**: Preferences modal

### Scanner Screen (Main View)
- **Tab**: Switch to Focus screen (selected AP details)
- **F1/F2**: Filter by signal strength (weak/strong)
- **F3/F4**: Filter by encryption type
- **F5**: Sort by channel
- **F6**: Sort by signal
- **F7**: Sort by BSSID
- **P**: Toggle PBC (Push Button Configuration) mode
- **Ctrl+R**: Refresh display

### Focus Screen (Per-AP Details)
- **Arrow keys**: Navigate client list
- **Enter**: Execute selected attack
- **Esc**: Return to scanner screen

**Attack Buttons**:
| Button | Description |
|--------|-------------|
| PMKID | Capture PMKID for offline cracking (hashcat mode 16800) |
| Handshake | Deauth clients to capture full 4-way handshake (mode 22000) |
| WPS PIN | Enumerate 8-digit WPS PIN, calculate PSK |
| WPS PBC | Push button configuration attack |
| EvilTwin | Create fake AP with captive portal (Linux-only) |
| Deauth Broadcast | Deauthenticate all clients on current channel |

### Vault Screen
- **Arrow keys**: Navigate credential list
- **Enter**: View capture details
- **E**: Export selected capture
- **Validate All**: Re-check every indexed capture for a usable handshake/PMKID
- **Clean Empty**: Move confidently-empty handshake captures to a recoverable `quarantine-no-wpa/` folder (never deletes — see [RETENTION.md](RETENTION.md))
- Recovered PSKs are masked (`********`) with a per-row **Show/Hide** toggle

### Preferences Modal
- **Theme**: Select UI theme (default: airscope-noir)
- **Log level**: trace/debug/info/quiet (null = auto-detect)

---

## Configuration

### Config File: `config.toml`

Settings are normally changed in the **Preferences** modal (Ctrl+P), which writes a TOML file in your
OS user-config directory (Linux: `~/.config/airscope/config.toml`). You can also edit it directly:

```toml
theme = "airscope-noir"        # airscope-noir | airscope-noir-contrast | airscope-green-dark
captures_dir = "captures"      # where captures are written (relative paths resolve to absolute)
save_pcap = true               # also keep the raw .pcap alongside hashes
wordlist_path = ""             # cracking dictionary; blank = bundled RockYou
log_level = "info"             # trace | debug | info | quiet
scanner_sort = "signal"        # signal | channel | bssid
scanner_sort_reverse = true
scanner_sort_delay = 2.0       # seconds between live scanner re-sorts
silenced_bssids = []           # BSSIDs to skip
```

**Settings**:
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `theme` | string | `"airscope-noir"` | UI theme (`airscope-noir`, `airscope-noir-contrast`, `airscope-green-dark`) |
| `captures_dir` | string | `"captures"` | Capture output directory |
| `save_pcap` | bool | `true` | Keep the raw `.pcap` alongside extracted hashes |
| `wordlist_path` | string | `""` | Global cracking dictionary; blank = bundled RockYou |
| `log_level` | string | `"info"` | Log verbosity: trace/debug/info/quiet |
| `scanner_sort` | string | `"signal"` | Scanner sort column: signal/channel/bssid |
| `scanner_sort_reverse` | bool | `true` | Reverse the scanner sort |
| `scanner_sort_delay` | float | `2.0` | Seconds between live scanner re-sorts |
| `silenced_bssids` | list | `[]` | BSSIDs to skip |

### Environment Variables

On the validated Raspberry Pi 5 the **kernel-monitor backend is the default** for the Realtek
RTL8812AU (`0bda:8812`) and RTL8814AU (`0bda:8813`) and needs no configuration. The userspace PyUSB
path and the RTL8814AU USB handover below are **experimental/unsupported** opt-ins, never triggered
automatically.

| Variable | Purpose |
|----------|---------|
| `AIRSCOPE_LOG` | Override log level (trace/debug/info/quiet) |
| `AIRSCOPE_CAPTURE` | Capture backend: `kernel` (default, validated) or `pyusb` (legacy userspace — experimental/unsupported) |
| `AIRSCOPE_8814_USB_HANDOVER` | Set to `1` to opt into the RTL8814AU USB handover (experimental/unsupported; off by default) |
| `AIRSCOPE_IN_VM` | Internal: indicates re-exec in VM context |
| `AIRSCOPE_RTL8188` | RTL8188EU: "mainline" for mainline driver |
| `AIRSCOPE_RTL8812` | RTL8812AU: "mainline" for mainline driver |
| `AIRSCOPE_RTL8821` | RTL8821AU: "mainline" for mainline driver |

---

## Attack Workflows

### PMKID Capture (Recommended First)

**Use case**: Capture hashcat mode 16800 hashes without client interaction.

```bash
# Via TUI:
1. Select AP in scanner
2. Press Enter to focus
3. Click "PMKID" button

# Via CLI:
uv run airscope --auto --targets "bssid_of_target"
```

### Handshake Capture (WPA/WPA2)

**Use case**: Capture full 4-way handshake for offline cracking.

```bash
# TUI:
1. Focus on target AP
2. Click "Handshake" button
3. Wait for client deauth/reconnection

# CLI:
uv run airscope --auto --targets "ssid_or_bssid"
```

**Notes**:
- May require waiting for a client to reconnect
- Use PBC toggle if clients are connected but not reconnecting
- Result stored as hashcat mode 22000 format

### WPS Pin Attack

**Use case**: Test against WPS-enabled routers with default PIN.

```bash
# TUI:
1. Focus on target AP (must show "WPS" in encryption column)
2. Click "WPS PIN" button

# CLI:
uv run airscope --auto --targets "ssid_or_bssid"
```

**Note**: Only works if router has WPS enabled and uses default PIN.

### Evil Twin / Captive Portal

**Use case**: Simulate AP to capture credentials in real-time with MIC verification.

```bash
# TUI (Linux only):
1. Focus on target AP
2. Click "EvilTwin" button
3. Clients connecting will see captive portal login page
4. Credentials captured and verified against real network

# CLI:
# Web dashboard recommended for EvilTwin:
uv run airscope --web
```

**Platform notes**:
- **Linux**: Full functionality including captive portal
- **macOS Intel**: Full via Lima VM re-exec
- **macOS Apple Silicon**: Disabled (USB passthrough impossible)
- **Windows**: Via WSL2

### Deauthentication Attacks

**Use case**: Force clients to reconnect, enabling handshake capture.

```bash
# TUI:
1. Focus on target AP
2. Click "Deauth Broadcast" button

# CLI:
uv run airscope --auto --targets "ssid_or_bssid"
```

---

## Export Formats

### CSV (`aps.csv`)
```
BSSID,Channel,Signal,Encryption,SSID
aa:bb:cc:dd:ee:ff,6,-45,WPA2-PSK,MyNetwork
...
```

### netxml (`networks.netxml`)
Wireshark-compatible XML format for network analysis.

### Cracked PSKs (`cracked.txt`)
Hashcat format:
```
$SSID$:PMKID or handshake hash
```

### HTML Dashboard (`index.html`)
Interactive web interface showing all captured data.

---

## Common Failure Modes

| Error | Cause | Solution |
|-------|-------|----------|
| "No supported USB adapters found" | Adapter not detected or wrong chipset | Run `uv run python -m airscope.doctor --list-usb` to find your adapter's VID:PID |
| "USB permissions denied" | Missing udev rule (Linux) or WinUSB driver (Windows) | Run `uv run python -m airscope.doctor` for setup instructions |
| "Adapter lost mid-session" | Physical USB disconnection | Replug device and select it again in splash screen |
| "PMKID capture failed" | AP doesn't support PMKID or client not associated | Try Handshake attack instead, wait for client reconnection |

---

## Debugging

### Enable Verbose Logging

```bash
# Per-run:
AIRSCOPE_LOG=debug uv run airscope

# Or edit config.toml:
log_level = "trace"
```

### Log File Location

- **Linux/macOS**: `~/.airscope/airscope.log`
- **Windows**: `%APPDATA%\airscope\airscope.log`

### USB Device Enumeration

```bash
uv run python -m airscope.doctor --list-usb
```

Shows all connected USB devices with VID:PID and manufacturer/product strings.

---

## Platform-Specific Notes

### Linux

**First-run setup**:
1. Install udev rule for `/dev/bus/usb` access (via `pkexec`)
2. No kernel driver loading on the userspace path (pure userspace via libusb); the validated Raspberry Pi 5 uses a kernel-monitor backend — see DRIVER_INSTALL.md

### Windows

**Requirements**:
1. WSL2 with Ubuntu installed
2. USB device attached to host and shared to WSL2 via `usbipd`
3. Adapter must use WinUSB driver (not MUSB/Android)

**Setup**:
```powershell
# List USB devices:
usbipd wsl list

# Attach adapter:
usbipd wsl attach --busid <BUSID>

# Then run airscope in WSL2:
uv run airscope
```

### macOS

**Intel Macs**:
- Full features via Lima VM (EvilTwin requires Linux network interface)

**Apple Silicon**:
- USB passthrough to VMs is impossible (IOKit limitation)
- All attacks except EvilTwin captive portal work natively
- Portal disabled with clear message in UI

---

## Example Sessions

### Quick Scan and Capture

```bash
# 1. Scan for 15 seconds, see what's around
uv run airscope --auto --scan-secs 15 --list

# 2. Attack the strongest target
TARGET_BSSID=$(uv run airscope --auto --scan-secs 10 --list | grep -i "strongest" | cut -d' ' -f1)
uv run airscope --auto --targets "$TARGET_BSSID"
```

### Automated Batch Mode

```bash
# Run all attacks on all APs for 60 seconds, log to file
uv run airscope --auto \
  --scan-secs 60 \
  --session ./my_session.jsonl \
  --wps-timeout 120 \
  --pmkid-timeout 60 \
  --hs-timeout 300
```

### Web Dashboard Monitoring

```bash
# Start web server (no browser)
uv run airscope --web --host 0.0.0.0 --port 8765 --no-browser

# Access from another machine:
http://<your-ip>:8765
```

---

## Keyboard Shortcuts Summary

| Key | Context | Action |
|-----|---------|--------|
| `Ctrl+P` | Anywhere | Preferences modal |
| `Tab` | Scanner → Focus screen |
| `Esc` | Focus → Back to scanner |
| `F1-F7` | Scanner | Filter and sort controls |
| `P` | Scanner | Toggle PBC mode |
| `Enter` | Splash/Scanner/Focus | Select item / Execute attack |

---

## Support

- **Documentation**: See [docs/](./) directory
- **Issue tracker**: https://github.com/ToySldr/airscope_v2/issues
- **Supported hardware**: See [docs/SUPPORTED-HARDWARE.md](SUPPORTED-HARDWARE.md)
