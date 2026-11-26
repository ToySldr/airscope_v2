# AirScope v0.3.9 — clean-install validation procedure (separate Raspberry Pi 5)

**Purpose.** This session proved the 88XXau patch **compiles** reproducibly (via `make` and the DKMS
toolchain, in isolation). It did **not** validate a full **clean-system installation**. This procedure
validates that install end-to-end on a **separate, disposable Raspberry Pi 5** — never on the working
Pi, because `dkms install`, module loading, and reboots are disruptive.

> Do **not** run this on the working/production Pi. Use a second Pi (or a fresh SD card) you can wipe.
> Keep a recovery path ready (stock driver restore + a spare SD image).

## 0. Environment to record (fill in on the test Pi)
| Item | Expected / record |
|---|---|
| Model / OS | Raspberry Pi 5, Kali (aarch64) |
| Kernel | `uname -r` → record (patch validated against `6.12.34+rpt-rpi-2712`) |
| Adapters | Alfa AWUS036ACH (RTL8812AU `0bda:8812`) + Alfa AWUS1900 (RTL8814AU `0bda:8813`) |
| Power | Stable **mains** power (not battery); under-voltage alarm clear |
| Baseline | `release/v0.3.9` (fork branch tip) |

Report only **aggregate** results (counts) — no real SSIDs, BSSIDs, or captures.

## 1. Checkout + environment
```
git clone https://github.com/ToySldr/airscope_v2.git airscope && cd airscope && git checkout release/v0.3.9
uv sync --frozen            # or: uv sync
```
**Pass:** on `release/v0.3.9`; `uv sync` succeeds.

## 2. DKMS installation (patched 88XXau + stock 8814au)
Non-destructive pre-check first (builds in /tmp, installs nothing):
```
python3 drivers/rtl88xxau/verify-patch-build.py      # expect all CHK* True, MAKE_RC 0, KO_BUILT True
```
Install the patched 88XXau via **Option B** (authorization-gated; modifies installed drivers):
```
sudo drivers/rtl88xxau/install-patched-dkms.sh       # sha-check, stock backup, patch -p0, dkms build+install
sudo dkms install realtek-rtl8814au/5.8.5.1~…        # stock 8814au (or it auto-installs)
```
**Pass:** `dkms status` shows both packages `installed`; `modinfo 88XXau | grep filename` points at
`…/updates/dkms/88XXau.ko.xz`.

## 3. Correct driver binding
With both adapters plugged in:
```
lsusb | grep -iE '0bda:8812|0bda:8813'
# 8812AU interface should bind to 88XXau (patched); 8814AU to the dedicated 8814au:
for d in /sys/bus/usb/devices/*; do \
  [ -r "$d/idVendor" ] && echo "$(cat "$d/idVendor"):$(cat "$d/idProduct") -> $(basename "$(readlink -f "$d"/*:1.0/driver 2>/dev/null)")"; done | grep -iE '0bda:881[23]'
modinfo 88XXau | grep -i 'alias:.*p8813' && echo 'FAIL: 88XXau still claims 0bda:8813' || echo 'OK: 88XXau does not claim 8813'
```
**Pass:** `0bda:8812` → `rtl88XXau`; `0bda:8813` → `rtl8814au`; patched 88XXau has **no** `0bda:8813`
alias (it binds 8813 to the dedicated driver), 8812 alias present.

## 4. Module persistence after reboot
```
sudo reboot
# after reboot, with adapters attached:
uname -r                                             # same kernel
modinfo 88XXau | grep -E 'filename|version'          # still the patched .ko.xz
dkms status | grep rtl88xxau
```
**Pass:** after reboot the **patched** 88XXau is still the loaded module (Option B keeps it because the
DKMS *source* is patched; with Option A, confirm the pinned `.ko.xz` survived). If a kernel update ran,
confirm it did **not** silently rebuild an unpatched module (the documented AUTOINSTALL hazard).

## 5. Monitor-mode beacon reception (the patch actually works)
```
sudo env AIRSCOPE_CAPTURE=kernel <venv>/bin/airscope --auto --list --scan-secs 20
#   look for: rx wlan1 (0bda:8812): raw=… parsed=… beacons=N
```
**Pass:** `beacons = N` with **N > 0** on the 0bda:8812 adapter (the patch admits beacons). A stock
module yields 0 — that contrast is the proof the patched module is the one loaded.

## 6. Dual-adapter AirScope startup
Run the full TUI with both adapters (kernel backend, default):
```
sudo env AIRSCOPE_CAPTURE=kernel <venv>/bin/airscope
```
**Pass:** both adapters are discovered and selectable; both capture **simultaneously** on distinct
channels with **no USB detach**; APs/clients populate; captures save to the Vault; `wlan0` management
connectivity is untouched throughout; clean `q` exit restores managed mode. Automatic retention does
**not** fire (manual "Clean Empty" only).

## Acceptance
| Step | Criterion | Result |
|---|---|---|
| 1 | checkout + `uv sync` | ☐ |
| 2 | DKMS install; patched `88XXau.ko.xz` loaded | ☐ |
| 3 | 8812→88XXau, 8813→8814au; no 8813 alias on 88XXau | ☐ |
| 4 | patched module persists across reboot | ☐ |
| 5 | beacons > 0 on 0bda:8812 | ☐ |
| 6 | dual-adapter capture; wlan0 intact; clean exit | ☐ |

All six passing is the clean-system install validation that this session's compile-only evidence does
not cover. Record kernel version, `dkms status`, `modinfo` filename, and aggregate beacon counts in the
release record. On failure, restore the stock driver (`docs/DRIVER_INSTALL.md` → Rollback) and re-image
if needed.
