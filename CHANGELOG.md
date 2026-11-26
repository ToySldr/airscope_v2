# Changelog

## v0.3.9

First public snapshot of this fork's v0.3.9 line, published as a single curated
commit on top of the previous public `main`. The full per-commit development
history is preserved in the project's development branches and backups.

### Capture
- Kernel-driver monitor-mode capture backend (radiotap, no USB detach) — the
  **validated default on the Raspberry Pi 5** for the Realtek RTL8812AU
  (`0bda:8812`) and RTL8814AU (`0bda:8813`) adapters, capturing via `AF_PACKET`
  on the bound kernel driver.
- Per-adapter RX counters and real-netdev logging.
- The legacy userspace PyUSB path and the RTL8814AU USB handover are
  **experimental and opt-in only** (`AIRSCOPE_CAPTURE=pyusb`,
  `AIRSCOPE_8814_USB_HANDOVER=1`); the default path never auto-detaches a kernel
  driver and fails closed.

### Drivers
- Version-controlled 88XXau monitor-mode patch with reproducible DKMS
  build/verify tooling and an isolated DKMS reproducibility test.
- RTL8812AU / RTL8814AU install, verify and recovery documentation.

### Vault & cracking
- Vault validation/selection UI: BSSID-keyed selection, batch validation reports,
  responsive columns, and a cracking-status panel.
- Crack worker lifecycle and subprocess hardening; cracked-PSK SSID attribution,
  safe deletion, saved-credential masking, and capture-index hygiene.
- Global `wordlist_path` preference.

### Capture retention
- In-app, manual, non-destructive retention/quarantine with a recovery guide.
  Automatic retention remains disabled in v0.3.9.

### Safety
- Ordered adapter shutdown with kernel-ownership safety; never `modprobe -r` a
  shared kernel module during install; `requires_setup` returns False for
  kernel-backend adapters.
- USB-safety handover regression tests adapted to the current `UsbClaim` API.

### Docs & tests
- Documentation corrected for v0.3.9 (userspace vs kernel-monitor scoping,
  versions, links); separate-Pi clean-install validation procedure.
- Expanded regression suite, including kernel-restore shutdown safety,
  no-auto-detach and in-app retention guards.

### Not included in this snapshot
- The v0.3.8 research PDF (superseded; to be refreshed separately) and internal
  pre-publication engineering notes.
