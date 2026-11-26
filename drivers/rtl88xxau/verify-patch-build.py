"""Non-destructive validation of airscope-88xxau-fixes.patch.

Copies the STOCK realtek-rtl88xxau DKMS source to a temp dir, dry-runs + applies the patch,
asserts the five required changes landed, and COMPILES the module. It NEVER touches /usr/src or
the running/installed module; it builds in a throwaway temp dir and does NOT install.

Run on the Pi5 (or any host with the DKMS source under /usr/src and matching kernel headers):
    python3 drivers/rtl88xxau/verify-patch-build.py
Exit status is non-zero if the patch fails to apply, a required change is missing, or the build
fails. The temp build dir is removed on success.
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PATCH = os.path.join(HERE, "airscope-88xxau-fixes.patch")

cands = sorted(glob.glob("/usr/src/realtek-rtl88xxau-*"))
if not cands:
    sys.exit("no realtek-rtl88xxau DKMS source under /usr/src")
SRC = cands[-1]
# Fail loudly if the on-disk source is not the version this patch was validated against,
# rather than silently targeting a different tree.
EXPECT_SRC = "realtek-rtl88xxau-5.6.4.2~git20250330.c3fb89a"
if os.path.basename(SRC) != EXPECT_SRC:
    sys.exit("source version mismatch: found %s, expected %s "
             "(the patch is validated only against that source)"
             % (os.path.basename(SRC), EXPECT_SRC))
if not os.path.isfile(PATCH):
    sys.exit("patch not found next to this script: %s" % PATCH)
print("SRC  ", SRC)
print("PATCH", PATCH)

BUILD = tempfile.mkdtemp(prefix="rtl88xxau-verify-")
ok = False
try:
    shutil.copytree(SRC, BUILD, symlinks=True, dirs_exist_ok=True)

    dry = subprocess.run(["patch", "-p0", "--dry-run", "-i", PATCH], cwd=BUILD,
                         capture_output=True, text=True)
    print("DRYRUN_RC", dry.returncode)
    if dry.returncode != 0:
        print(dry.stdout.strip())
        print(dry.stderr.strip()[-300:])
        raise SystemExit("patch dry-run FAILED")

    ap = subprocess.run(["patch", "-p0", "-i", PATCH], cwd=BUILD, capture_output=True, text=True)
    print("APPLY_RC", ap.returncode)
    if ap.returncode != 0:
        print(ap.stderr.strip()[-300:])
        raise SystemExit("patch apply FAILED")

    def _read(rel):
        return open(os.path.join(BUILD, rel), encoding="utf-8", errors="replace").read()

    hal = _read("include/hal_data.h")
    init = _read("hal/rtl8812a/rtl8812a_hal_init.c")
    usb = _read("os_dep/linux/usb_intf.c")
    checks = {
        "CHK1_rxfltmap0_open   ": "REG_RXFLTMAP0, 0xFFFF" in init,
        "CHK2a_backup_field    ": "rxfltmap0_backup" in hal,
        "CHK2b_save_on_entry   ": "rxfltmap0_backup = rtw_read16" in init,
        "CHK2c_restore_on_exit ": "REG_RXFLTMAP0, pHalData->rxfltmap0_backup" in init,
        "CHK3_8813_removed     ": "0x8813), .driver_info = RTL8814A" not in usb,
        # NB: the 8812AU device-table constant is RTL8812 (no trailing 'A'); only 8814 is RTL8814A.
        # Pin both the full set (34 in this source) and the Realtek 0bda:8812 (AWUS036ACH) line.
        "CHK4_8812_preserved   ": (usb.count(".driver_info = RTL8812") >= 34 and
                                   "USB_VENDER_ID_REALTEK, 0x8812)" in usb),
        "CHK5_other_8814_kept  ": usb.count(".driver_info = RTL8814A") > 0,
    }
    for k, v in checks.items():
        print(k, v)
    if not all(checks.values()):
        raise SystemExit("a required change is missing")

    kver = subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()
    mk = subprocess.run(["make", "-j4", "KVER=" + kver, "KSRC=/lib/modules/%s/build" % kver],
                        cwd=BUILD, capture_output=True, text=True)
    print("MAKE_RC", mk.returncode)
    print("MAKE_TAIL", "\n".join(mk.stdout.strip().splitlines()[-8:]))
    if mk.returncode != 0:
        print("MAKE_ERR", "\n".join(mk.stderr.strip().splitlines()[-20:]))
        raise SystemExit("compile FAILED")
    ko = os.path.join(BUILD, "88XXau.ko")
    built = os.path.isfile(ko)
    print("KO_BUILT", built, (os.path.getsize(ko) if built else 0))
    if not built:
        raise SystemExit("module did not build")
    ok = True
    print("RESULT OK: patch applies and compiles reproducibly (no changes to the running system)")
finally:
    shutil.rmtree(BUILD, ignore_errors=True)

sys.exit(0 if ok else 1)
