# Documentation Index - airscope

This directory contains comprehensive documentation for the airscope Wi-Fi security auditing tool.

## Quick Start

1. **New to airscope?** Read [USAGE.md](./USAGE.md) first for installation and basic usage.
2. **Want to understand how it works?** See [CODEBASE_MAP.md](./CODEBASE_MAP.md) for architecture overview.
3. **Need detailed technical info?** Check [SUBSYSTEMS.md](./SUBSYSTEMS.md) for component breakdowns.

## Documentation Structure

### Core Documentation

| File | Purpose | When to Read |
|------|---------|--------------|
| [PROJECT_INVENTORY.md](./PROJECT_INVENTORY.md) | Project overview, structure, dependencies | First read - understand the project landscape |
| [CAPABILITIES.md](./CAPABILITIES.md) | Feature list, CLI flags, TUI controls | To learn what airscope can do and how to invoke it |
| [USAGE.md](./USAGE.md) | Installation, configuration, examples | Before running airscope for the first time |

### Technical Documentation

| File | Purpose | When to Read |
|------|---------|--------------|
| [CODEBASE_MAP.md](./CODEBASE_MAP.md) | Master architecture reference (entry points, modules, data flow) | Understanding how code is organized and flows |
| [SUBSYSTEMS.md](./SUBSYSTEMS.md) | Detailed breakdown of each major subsystem | When working on a specific component |

### Reference Documentation

| File | Purpose |
|------|---------|
| [SUPPORTED-HARDWARE.md](./SUPPORTED-HARDWARE.md) | List of supported USB Wi-Fi adapters and chipsets |
| [LINUX-PERMISSIONS.md](./LINUX-PERMISSIONS.md) | Linux setup: udev rules, permissions troubleshooting |
| [THEMES.md](./THEMES.md) | UI theme customization |
| [FIRMWARE.md](./FIRMWARE.md) | Firmware loading and management |

### Release Notes

| File | Purpose |
|------|---------|
| [SUMMARY.md](./SUMMARY.md) | Project status, statistics, feature matrix |

## Platform-Specific Guides

### Linux
- See [LINUX-PERMISSIONS.md](./LINUX-PERMISSIONS.md) for udev rule setup
- No kernel driver loading on the userspace path (pure userspace via libusb); the validated Raspberry Pi 5 uses a kernel-monitor backend — see DRIVER_INSTALL.md

### Windows
- Requires WSL2 with USB passthrough
- Adapter must use WinUSB driver (not MUSB/Android)
- See README.md in main repo for setup instructions

### macOS
- Intel: Full features via Lima VM for EvilTwin portal
- Apple Silicon: Native mode only (USB passthrough to VMs impossible)
- First run prompts for USB access permission

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) in the main repo for:
- Commit conventions (conventional-commits with scopes)
- PR requirements
- Code style guidelines

## Support

- **Issue tracker**: https://github.com/ToySldr/airscope_v2/issues
- **Supported hardware**: See [SUPPORTED-HARDWARE.md](./SUPPORTED-HARDWARE.md)

---

**Note**: The documentation in this directory is maintained by hand in this repository (there is no automatic doc generator). If you find a discrepancy with the source code, please file an issue with the specific file and line number.
