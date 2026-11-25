# RTL8812AU (88XXau) monitor-mode driver patch

Version-controlled source patch + reproducible install/verify tooling for the Alfa AWUS036ACH
(RTL8812AU, `0bda:8812`) used by AirScope's kernel-monitor capture backend on the Raspberry Pi 5.

| File | Purpose |
|---|---|
| `airscope-88xxau-fixes.patch` | The source patch (apply with `patch -p0` from the DKMS source root). |
| `verify-patch-build.py` | **Non-destructive** check: copies the stock source to a temp dir, applies the patch, asserts the 5 required changes, and compiles the module via `make`. Never installs or touches the running module. |
| `test-dkms-isolated.sh` | **Non-destructive** deeper check: builds the patch through the **full DKMS toolchain** in throwaway `/tmp` trees (unique pkg name, build-only, auto-cleaned), twice for reproducibility plus an unpatched contrast, and verifies the compiled module's USB aliases (`0bda:8812` kept, `0bda:8813` dropped). Touches no real package. |
| `install-patched-dkms.sh` | **Protected** reproducible install (Option B): patches the DKMS source in place and rebuilds via DKMS. Run only with explicit authorization, as root, in a maintenance window. |

## Base source
- DKMS package: `realtek-rtl88xxau` `5.6.4.2~git20250330.c3fb89a` (`/usr/src/realtek-rtl88xxau-5.6.4.2~git20250330.c3fb89a`)
- Kernel validated against: `6.12.34+rpt-rpi-2712` (aarch64)
- Patch sha256: `d2bb89844d76ad00da4a26cba12129e9329ce89178b4831989161955e3004241`

## What the patch changes (all five verified)
1. **Management-frame RX correction** — on monitor entry, open `REG_RXFLTMAP0` to `0xFFFF`
   (chip default `0x0000` drops beacons, mgmt subtype 8), in `hal/rtl8812a/rtl8812a_hal_init.c`.
2. **Save + restore** the original `REG_RXFLTMAP0` — a new `rxfltmap0_backup` field in
   `include/hal_data.h`, read on monitor entry and written back on monitor exit, so managed mode is
   left exactly as found.
3. **Remove RTL8814AU USB ID `0bda:8813`** from the 88XXau device-ID table (`os_dep/linux/usb_intf.c`)
   so the AWUS1900 binds to the dedicated, stable `8814au` driver instead of 88XXau.
4. **RTL8812AU support preserved** — only the single `0x8813` line is removed; all 34 `RTL8812`
   device-ID entries (the AWUS036ACH `0bda:8812` included) and the other `RTL8814A` vendor IDs are
   untouched. (The 8812AU device-table constant is `RTL8812`, with no trailing `A`; only 8814 is
   `RTL8814A`.)
5. **Compatible with the validated source + kernel** — applies cleanly with `patch -p0` and compiles
   to a loadable `88XXau.ko` against the kernel above (see `verify-patch-build.py`).

## Verify (safe — no changes to the running system)
```
python3 drivers/rtl88xxau/verify-patch-build.py
# expect: DRYRUN_RC 0, APPLY_RC 0, all CHK* True, MAKE_RC 0, KO_BUILT True
```

## Install (protected — requires authorization; modifies installed driver)
```
sudo drivers/rtl88xxau/install-patched-dkms.sh
```
See `docs/DRIVER_INSTALL.md` for Option A (pin the prebuilt module) vs Option B (this script),
verification, rollback, and the kernel-update hazard.
