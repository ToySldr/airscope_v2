# AirScope v0.3.9 — release notes (candidate)

Wi-Fi auditor TUI for the Raspberry Pi 5 (Kali, aarch64, kernel `6.12.34+rpt-rpi-2712`). This is a
conservative release candidate: the capture/monitor path is unchanged, and the new Vault/validation
work ships with its one destructive capability (automatic retention) **disabled**.

## What's in this release
- **Vault + capture validation:** read-only capture validation primitives, a Vault browser with
  per-capture and batch ("Validate All") validation, cracked-PSK SSID attribution, safe per-file and
  per-network deletion (guarded against out-of-directory and cross-network deletes), and index hygiene.
- **Cracking:** job-status panel, crack-worker lifecycle, subprocess hardening, and a global
  `wordlist_path` preference (config + preference UI + web fallback).
- **Shutdown safety:** ordered adapter teardown and kernel-ownership safety on exit (`setup/linux.py`,
  `ui/app.py`, `wlan/array.py`), restoring managed mode and leaving `wlan0` untouched.
- **Driver reproducibility:** the RTL8812AU (`88XXau`) monitor patch is version-controlled under
  `drivers/rtl88xxau/` with verify + isolated-DKMS-test + authorization-gated install tooling and docs.

## Capture retention — disabled by default (manual only)
Automatic capture retention is **off** in v0.3.9. The only cleanup path is the manual **"Clean Empty"**
button, which **moves** (never deletes) confidently-empty handshake captures to a quarantine folder and
is recoverable. Full behavior, quarantine location, the CSV audit report, and the recovery procedure
are in [`docs/RETENTION.md`](RETENTION.md). The logic is covered by `tests/test_inapp_retention.py`
(13 tests).

## Capture backend (supported vs experimental)
The **kernel-monitor backend is the supported capture architecture** and the default for the validated
Realtek adapters (`0bda:8812`, `0bda:8813`): it captures through the bound kernel driver with **no USB
detach**. The legacy **userspace PyUSB backend** (`AIRSCOPE_CAPTURE=pyusb`) and the **RTL8814AU USB
handover** (`AIRSCOPE_8814_USB_HANDOVER=1`) are **EXPERIMENTAL and UNSUPPORTED** in v0.3.9: explicit,
deliberate opt-in only, **never** triggered by normal startup or by a kernel-backend failure (verified
by `tests/test_no_auto_detach.py`), and with additional orchestration testing deferred to a future
development branch. Do not use them for production capture.

## Wi-Fi adapter drivers
Both adapters capture through their bound kernel driver (the default kernel-monitor backend); no
out-of-tree PyUSB driver is needed. The `88XXau` monitor patch (beacon RX + removing the AWUS1900
`0bda:8813` ID so it binds to the dedicated `8814au`) is **not** in the stock DKMS source, so a kernel
update can rebuild it unpatched — see [`docs/DRIVER_INSTALL.md`](DRIVER_INSTALL.md) for the hazard,
Option A/B install, verification, and rollback.

**Driver reproducibility — what is and isn't proven.** The patch's **compilation** is reproducible and
independently verified in isolation (`drivers/rtl88xxau/verify-patch-build.py` builds via `make`;
`drivers/rtl88xxau/test-dkms-isolated.sh` builds through the real DKMS toolchain in throwaway `/tmp`
trees). That is **build/compile reproducibility only.** A full **clean-system installation** — the
actual `dkms install`, module load, and reboot-survival on a fresh Pi — has **not** been validated and
is **not** claimed as proven; it remains the authorization-gated operator procedure in
`docs/DRIVER_INSTALL.md` (Option A/B).

## Test status
From a clean checkout (fresh worktree, env synced `--frozen --all-extras` from `uv.lock`, CPython
3.12.16 / pytest 9.0.3): **3137 passed, 0 failed** (1 skipped, 15 slow deselected, 11 xfailed), plus
**15 slow passed**. Note: `3137 = 3091 + 22 + 13 + 11`, where the **+22** are the pre-existing
`tests/web/test_api.py` tests that become collectable only with the optional `[web]` extra
(fastapi/httpx), the **+13** are the retention tests, and the **+11** are the no-auto-detach guard
tests (`tests/test_no_auto_detach.py`) — the +13 and +11 are the new coverage.

## Known-untested / deferred (intentional for v0.3.9)
- **Legacy RTL8814AU PyUSB backend + USB handover** (`AIRSCOPE_CAPTURE=pyusb`,
  `AIRSCOPE_8814_USB_HANDOVER`) — **experimental / unsupported** (see "Capture backend" above): off by
  default, untested at the orchestration level, deferred to a future development branch. Not needed —
  the kernel backend drives the 8814AU.
- Minor untested branches: preference wordlist validation, the web empty-wordlist fallback, the
  `WlanArray.close()` raise path, and the AP-mode `selected_binding_message` string.
- The driver patch is validated against the specific DKMS source + kernel above; a future kernel or
  source bump needs a one-command re-validation (`drivers/rtl88xxau/verify-patch-build.py`) before
  Option B is trusted again.

## Not done (by direction)
Nothing has been pushed or published; the branch is local-only. Tagging and release are deferred to the
maintainer.
