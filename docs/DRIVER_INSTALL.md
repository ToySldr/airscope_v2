# AirScope — Wi-Fi adapter drivers: install, verify, recovery (Raspberry Pi 5)

Target: Raspberry Pi 5 (aarch64), kernel `6.12.34+rpt-rpi-2712`. Both adapters capture through their
**bound kernel driver** (AirScope's default kernel-monitor backend); no out-of-tree PyUSB driver is
required for normal operation.

## Adapters & drivers
| Adapter | VID:PID | Kernel module (driver) | DKMS package | Patch |
|---|---|---|---|---|
| Alfa AWUS036ACH (RTL8812AU) | `0bda:8812` | `88XXau` (`rtl88XXau`) | `realtek-rtl88xxau` 5.6.4.2~git20250330 | **YES — monitor RX-filter + ID-table patch** |
| Alfa AWUS1900 (RTL8814AU) | `0bda:8813` | `8814au` (`rtl8814au`) | `realtek-rtl8814au` 5.8.5.1~git20250903 | none (stock; monitor works out of the box) |

The patch is version-controlled at **`drivers/rtl88xxau/airscope-88xxau-fixes.patch`** (applies with
`patch -p0` from the DKMS source root; sha256 `d2bb8984…3004241`). It makes five changes:

1. Opens `REG_RXFLTMAP0` to `0xFFFF` on monitor entry so the **8812AU receives beacons** (chip default
   `0x0000` drops mgmt subtype 8), in `hal/rtl8812a/rtl8812a_hal_init.c`.
2. **Saves and restores** the original `REG_RXFLTMAP0` (new `rxfltmap0_backup` field in
   `include/hal_data.h`) so managed mode is left exactly as found on monitor exit.
3. **Removes USB id `0bda:8813`** from the 88XXau device table (`os_dep/linux/usb_intf.c`) so the
   AWUS1900 binds to the dedicated, stable `8814au` driver rather than 88XXau.
4. **Preserves all RTL8812AU support** — only the single `0x8813` line is removed; all 34 `RTL8812`
   device entries (incl. the AWUS036ACH `0bda:8812`) and the other `RTL8814A` vendor IDs are untouched.
5. **Applies and compiles cleanly** against the source + kernel above (validated by
   `drivers/rtl88xxau/verify-patch-build.py`, which builds in a temp dir without installing).

## Dependencies
`dkms`, `build-essential`, `bc`, `linux-headers-$(uname -r)`. DKMS source trees live under `/usr/src/`
(`realtek-rtl88xxau-5.6.4.2~…`, `realtek-rtl8814au-5.8.5.1~…`).

## ⚠ Critical: the 88XXau monitor patch is NOT in the stock DKMS source
`dkms status` reports `realtek-rtl88xxau/… : installed (Differences between built and installed
modules)`. The **deployed** `88XXau.ko.xz` is manually patched so monitor mode admits beacons; the
**stock DKMS source is unpatched** and `AUTOINSTALL="yes"`. A kernel update therefore auto-rebuilds the
UNPATCHED module and overwrites the patch, after which the 8812AU monitor silently drops all beacons.
(Observed live on the already-deployed hand-patched module: `rx wlan1 (0bda:8812): … beacons>0`; the
stock module yields 0 — a runtime observation of the deployed module, not a clean-install proof.)

Preserved copy of the patched module (prebuilt carrier of the patch, for Option A):
`$HOME/airscope-driver-backup/88XXau.ko.xz.PATCHED-backup` (create it under your own home; this build's sha256 is `2c6067484ad6…`).

## Reproducible install that preserves the patch
**Option A — pin the prebuilt patched module (simplest; survives minor kernel bumps):**
1. Keep the preserved `.ko.xz` backup (above).
2. Stop DKMS from clobbering it on kernel updates: set `AUTOINSTALL="no"` in
   `/usr/src/realtek-rtl88xxau-…/dkms.conf` (or `sudo dkms remove realtek-rtl88xxau/5.6.4.2~… --all`).
3. After each kernel update, restore the patched module for the new kernel:
   ```
   sudo install -m 0644 "$HOME/airscope-driver-backup/88XXau.ko.xz.PATCHED-backup" \
        /lib/modules/$(uname -r)/updates/dkms/88XXau.ko.xz
   sudo depmod -a      # then replug the adapter
   ```
   Trade-off: the `.ko` is ABI-pinned; a major kernel jump may refuse to load it → use Option B.

**Option B — re-apply the version-controlled patch to the DKMS source (durable):**
1. First, validate without touching the running system:
   ```
   python3 drivers/rtl88xxau/verify-patch-build.py
   #   -> DRYRUN_RC 0, APPLY_RC 0, all CHK* True, MAKE_RC 0, KO_BUILT True
   ```
2. Apply + rebuild + install (protected; needs authorization, run as root):
   ```
   sudo drivers/rtl88xxau/install-patched-dkms.sh
   ```
   The script verifies the patch sha256, backs up the stock source to `…-….stock-backup`, applies
   `airscope-88xxau-fixes.patch` with `patch -p0` (idempotent), then `dkms remove` + `dkms install`.
   Because the DKMS **source** is now patched, later `AUTOINSTALL` kernel-update rebuilds produce the
   PATCHED module — no silent regression to stock.
3. Verify (below).

**8814au (no patch):** `sudo dkms install realtek-rtl8814au/5.8.5.1~…` (or it auto-installs). Stock.

## Isolated DKMS reproducibility test (optional, deeper — changes nothing)
`drivers/rtl88xxau/test-dkms-isolated.sh` exercises the **full DKMS toolchain** (not just `make`) in a
throwaway `--sourcetree`/`--dkmstree` under `/tmp` with a unique package name, as the normal user,
**build-only** (never `dkms install`). It never touches `/usr/src`, `/var/lib/dkms`, `/lib/modules`,
the loaded modules, or the real `realtek-rtl88xxau` package, and it auto-cleans. It builds the patch
in two independent trees (reproducibility) plus an unpatched stock build (contrast) and checks the
compiled module's USB device-id aliases. Verified result on `6.12.34+rpt-rpi-2712`:

| build | module | `0bda:8812` alias | `0bda:8813` alias |
|---|---|---|---|
| patched #1 | built ok | 2 (preserved) | 0 (removed) |
| patched #2 | built ok | 2 | 0 |
| unpatched stock | built ok | 2 | 1 (present) |

i.e. the DKMS-built patched module drops the AWUS1900 (`0bda:8813`) binding while keeping all 8812
support, reproducibly; the stock build still claims `0bda:8813`. Real `dkms status` was byte-for-byte
unchanged before and after, with no residue left behind.

> **Proven vs. not proven.** The checks above (`verify-patch-build.py` and `test-dkms-isolated.sh`)
> establish **patch-apply + compilation reproducibility** — via `make` and via the DKMS toolchain, in
> isolation. They do **not** validate a full clean-system **installation**: the real `dkms install`,
> loading the module into the running kernel, and survival across a reboot / kernel update have **not**
> been tested here and are **not** claimed as proven. Treat Option A/B below as an authorization-gated
> operator procedure to run and verify on the target system, not a pre-validated outcome.

## Verification commands
```
dkms status                                       # both packages: installed
modinfo 88XXau | grep -E 'filename|version'       # …/updates/dkms/88XXau.ko.xz
modinfo 8814au | grep -E 'filename|version'
# Functional proof the 8812AU monitor patch is live (beacons must be > 0):
sudo env AIRSCOPE_CAPTURE=kernel <venv>/bin/airscope --auto --list --scan-secs 20
#   -> look for: rx wlan1 (0bda:8812): raw=… parsed=… beacons=N   (N must be > 0)
```

## Rollback
- Restore stock (unpatched) 88XXau source + module:
  `sudo cp -a /usr/src/realtek-rtl88xxau-….stock-backup/. /usr/src/realtek-rtl88xxau-…/` then
  `sudo dkms remove … --all && sudo dkms install …` (monitor beacons stop — expected for stock).
- Re-pin the patched module: Option A step 3 (restore the preserved `.ko.xz` + `depmod -a` + replug).
- Remove any AirScope-installed udev/blacklist rules: run AirScope and quit (its exit path calls
  `release_all`), or `python -c "from airscope.setup.linux import release_all; release_all()"`.

## Normal-operation safety (verified)
AirScope's **default** capture backend is the kernel-monitor driver (`AF_PACKET` on the bound kernel
driver). During normal operation it **never** detaches the kernel driver, unloads a module, or resets
the USB device — it only sets monitor mode via `iw` and restores managed mode on exit. The PyUSB
backend (opt-in `AIRSCOPE_CAPTURE=pyusb`, experimental/unsupported) **refuses** to detach the
hang-prone `rtl88XXau` and fails closed with guidance. The built-in `wlan0` management interface is
never modified.

## Patch provenance (captured — reproducible)
The source diff is version-controlled at `drivers/rtl88xxau/airscope-88xxau-fixes.patch` (sha256
`d2bb8984…3004241`), generated against stock `realtek-rtl88xxau 5.6.4.2~git20250330.c3fb89a`. It has
been validated to apply (`patch -p0`) and compile to a loadable `88XXau.ko` against kernel
`6.12.34+rpt-rpi-2712` via `drivers/rtl88xxau/verify-patch-build.py` — a temp-dir build that does not
install or touch the running module. Option B's patch re-application and compile are therefore
reproducible on a fresh Pi5 or after a kernel update (the `dkms install` itself remains an
authorization-gated operator step — see "Proven vs. not proven"); Option A remains the quick
prebuilt-module path. See `drivers/rtl88xxau/README.md`.
