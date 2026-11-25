#!/bin/bash
#
# Isolated, reversible DKMS reproducibility test for the 88XXau monitor patch.
#
# Uses throwaway `dkms --sourcetree/--dkmstree` directories under /tmp and a unique package name,
# so it NEVER touches /usr/src, /var/lib/dkms, /lib/modules, loaded modules, or the real
# `realtek-rtl88xxau` package. It is BUILD-ONLY (never `dkms install`), runs as the normal user,
# and auto-cleans. No system driver is modified; nothing is loaded.
#
# It proves two things that `verify-patch-build.py` (raw `make`) does not:
#   1. the patched source builds through the actual DKMS toolchain (dkms.conf-driven), reproducibly
#      across two independent trees; and
#   2. the resulting module's USB device table matches the patch -- 0bda:8812 present, 0bda:8813
#      absent -- contrasted against an unpatched build where 0bda:8813 is still present.
#
# Usage (on the Pi5, or any host with the DKMS source + kernel headers):
#     drivers/rtl88xxau/test-dkms-isolated.sh
#
set -u
STOCK=/usr/src/realtek-rtl88xxau-5.6.4.2~git20250330.c3fb89a
HERE="$(cd "$(dirname "$0")" && pwd)"
PATCH="${HERE}/airscope-88xxau-fixes.patch"
VER="5.6.4.2~git20250330.c3fb89a"
KVER="$(uname -r)"

[ -d "$STOCK" ] || { echo "stock DKMS source not found: $STOCK"; exit 2; }
[ -f "$PATCH" ] || { echo "patch not found: $PATCH"; exit 2; }

DK () {  # run dkms against the throwaway trees; fall back to sudo -n only if a plain run can't
  if dkms "$@" >/dev/null 2>&1; then return 0; fi
  sudo -n dkms "$@" >/dev/null 2>&1
}

build_variant () {  # $1=tag  $2=apply_patch(yes|no)
  local TAG="$1" APPLY="$2"
  local NAME="airscope-88xxau-dkmstest-${TAG}-$$"
  local ROOT="/tmp/dkmstest-${TAG}-$$"
  local ST="$ROOT/src" DT="$ROOT/var"
  mkdir -p "$ST" "$DT"
  cp -a "$STOCK" "$ST/${NAME}-${VER}"
  sed -e "s/^PACKAGE_NAME=.*/PACKAGE_NAME=\"$NAME\"/" \
      -e "s/^AUTOINSTALL=.*/AUTOINSTALL=\"no\"/" \
      "$STOCK/dkms.conf" > "$ST/${NAME}-${VER}/dkms.conf"
  if [ "$APPLY" = yes ]; then
      ( cd "$ST/${NAME}-${VER}" && patch -p0 -i "$PATCH" >/dev/null ) \
          || { echo "[$TAG] patch apply FAILED"; rm -rf "$ROOT"; return 1; }
  fi
  DK --sourcetree "$ST" --dkmstree "$DT" add "${NAME}/${VER}"
  DK --sourcetree "$ST" --dkmstree "$DT" build "${NAME}/${VER}" -k "$KVER"
  local KO
  # Prefer the placed module dir; the module may be compressed (.ko.xz) on this system.
  KO="$(find "$DT/${NAME}/${VER}" -type f \( -name '88XXau.ko' -o -name '88XXau.ko.*' \) 2>/dev/null \
        | grep -E '/module/' | head -1)"
  [ -n "$KO" ] || KO="$(find "$DT/${NAME}/${VER}" -type f \( -name '88XXau.ko' -o -name '88XXau.ko.*' \) 2>/dev/null | head -1)"
  if [ -n "$KO" ] && [ -f "$KO" ]; then
      local a8812 a8813 sz
      sz=$(stat -c%s "$KO")
      a8812=$(modinfo "$KO" 2>/dev/null | grep -i '^alias:' | grep -ci 'p8812')
      a8813=$(modinfo "$KO" 2>/dev/null | grep -i '^alias:' | grep -ci 'p8813')
      echo "[$TAG] BUILT ok  size=${sz}  usb-alias: 8812=${a8812}  8813=${a8813}"
  else
      echo "[$TAG] BUILD FAILED (no 88XXau.ko)"
  fi
  DK --sourcetree "$ST" --dkmstree "$DT" remove "${NAME}/${VER}" --all
  rm -rf "$ROOT"
}

echo "KVER=$KVER  user=$(whoami)"
echo "=== real dkms status BEFORE ==="
dkms status | grep rtl88xxau

echo "=== PATCHED build #1 (expect: 8812>0, 8813=0) ==="
build_variant patched1 yes
echo "=== PATCHED build #2 (reproducibility: same result) ==="
build_variant patched2 yes
echo "=== UNPATCHED stock build (contrast: expect 8813>0) ==="
build_variant stock no

echo "=== real dkms status AFTER (must match BEFORE) ==="
dkms status | grep rtl88xxau
echo "=== real trees untouched (expect 'none') ==="
ls -d /usr/src/airscope-88xxau-dkmstest* 2>/dev/null || echo "none in /usr/src"
ls -d /var/lib/dkms/airscope-88xxau-dkmstest* 2>/dev/null || echo "none in /var/lib/dkms"
echo DKMS_TEST_DONE
