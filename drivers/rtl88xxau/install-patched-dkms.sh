#!/bin/bash
#
# Reproducible patched install of the RTL8812AU (88XXau) monitor driver for AirScope (Option B).
#
# Applies airscope-88xxau-fixes.patch to the STOCK realtek-rtl88xxau DKMS source in place and
# rebuilds + installs the module via DKMS. After this runs, the DKMS source itself is patched, so
# AUTOINSTALL kernel-update rebuilds produce the PATCHED module (no silent regression to stock).
#
# The patch does two things: (1) opens REG_RXFLTMAP0 in monitor mode so the 0bda:8812 adapter
# receives beacons (and restores it on exit), and (2) removes USB id 0bda:8813 from the 88XXau
# device table so the AWUS1900 binds to the dedicated, stable 8814au driver.
#
# PROTECTED OPERATION. This MODIFIES the installed kernel driver and the DKMS source tree. Run it
# ONLY with explicit authorization, as root, in a maintenance window (e.g. right after a kernel
# update). It is NOT invoked on the normal AirScope path.
#
# Safe pre-check that changes nothing: python3 drivers/rtl88xxau/verify-patch-build.py
#
set -euo pipefail

PKG="realtek-rtl88xxau"
VER="5.6.4.2~git20250330.c3fb89a"
SRC="/usr/src/${PKG}-${VER}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PATCH="${HERE}/airscope-88xxau-fixes.patch"
EXPECT_SHA="d2bb89844d76ad00da4a26cba12129e9329ce89178b4831989161955e3004241"

if [ "$(id -u)" -ne 0 ]; then echo "ERROR: run as root (sudo)"; exit 1; fi
if [ ! -f "$PATCH" ]; then echo "ERROR: patch not found: $PATCH"; exit 1; fi
if [ ! -d "$SRC" ]; then echo "ERROR: DKMS source not found: $SRC (adjust VER for your source)"; exit 1; fi

got_sha="$(sha256sum "$PATCH" | awk '{print $1}')"
if [ "$got_sha" != "$EXPECT_SHA" ]; then
    echo "ERROR: patch sha256 mismatch"
    echo "  expected $EXPECT_SHA"
    echo "  got      $got_sha"
    exit 1
fi

# Back up the pristine stock source once, so Option-A rollback stays possible.
if [ ! -d "${SRC}.stock-backup" ]; then
    cp -a "$SRC" "${SRC}.stock-backup"
    echo "stock source backed up -> ${SRC}.stock-backup"
fi

# Apply (idempotent): skip if the marker field is already present in the source.
if grep -q 'rxfltmap0_backup' "${SRC}/include/hal_data.h"; then
    echo "patch already present in ${SRC}; skipping apply"
else
    ( cd "$SRC" && patch -p0 --dry-run -i "$PATCH" ) || { echo "ERROR: dry-run failed"; exit 1; }
    ( cd "$SRC" && patch -p0 -i "$PATCH" )
    echo "patch applied to ${SRC}"
fi

KVER="$(uname -r)"
echo "rebuilding ${PKG}/${VER} for kernel ${KVER} ..."
dkms remove  "${PKG}/${VER}" --all || true
dkms install "${PKG}/${VER}" -k "$KVER"

echo "--- modinfo 88XXau ---"
modinfo 88XXau | grep -E 'filename|version' || true
echo "DONE."
echo "Verify functionally: run AirScope on the 0bda:8812 adapter and confirm 'beacons=N' with N>0."
