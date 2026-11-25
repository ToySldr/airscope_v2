# AirScope capture retention — manual cleanup, quarantine, and recovery (v0.3.9)

AirScope **never automatically deletes or relocates capture evidence.** In v0.3.9 the automatic
retention triggers are disabled; the only way captures are ever moved is an explicit, user-initiated
**"Clean Empty"** action in the Vault, and even that **moves** files to a quarantine folder rather
than deleting them. This document describes exactly what that does, where files go, and how to get
them back.

## What "Clean Empty" does
The Vault screen has a **Clean Empty** button (`#vault-clean-stale`). Pressing it runs
`airscope.persist.inapp_retention.quarantine_stale_wpa(...)` once, in a background thread, over the
currently indexed captures. For each capture it is deliberately conservative:

A capture is **moved to quarantine only if ALL of these hold:**
- it is a handshake-type capture (`hs` or `pmkid`);
- its extension is one of `.pcap .pcapng .cap .hc22000 .22000`;
- it lives **inside** the configured captures directory (symlinks and anything resolving outside are
  refused);
- it was last modified **more than 15 minutes ago** (`MIN_AGE = 900 s`);
- it is **not open** by any process (checked against `/proc/*/fd`);
- **no other AirScope process** is running;
- inspecting it reports **`no_records`** (no usable WPA handshake/PMKID), confirmed by a **second
  independent inspection**, with the file **unchanged** between the two checks (device, inode, size,
  and mtime all identical).

Anything else is **kept in place**:
- captures with an extractable handshake or saved hash markers → **KEEP**;
- unverified / unsupported / missing / inconclusive results → **KEEP**;
- any error during inspection → **KEEP** (fail-safe);
- recently written, open, symlinked, or out-of-directory files → **skipped**.

The move itself is a **hard-link-then-unlink**: AirScope creates a hard link to the file in the
quarantine folder, verifies the link points at the same inode, and only then removes the original
name. The file's data is never unlinked while it exists in only one place, so an interruption leaves
either the original or the quarantined copy intact — never neither. There is **no `rm`/`unlink` of
capture data** on this path.

On completion the Vault shows: `Retention: checked N | quarantined M | skipped K`, and a toast
`Moved M non-extractable files to quarantine` when `M > 0`.

**Audit report.** Whenever anything is quarantined (or an inspection raised an error), retention writes
a timestamped CSV to `<CAPTURES>/../exports/airscope_inapp_retention_<YYYYMMDD_HHMMSS_us>.csv`
recording, per capture: path, BSSIDs, size, validation status, the KEEP/QUARANTINE decision, and the
quarantine destination. When there is nothing to report, no file is written.

## Quarantine location
Given the configured captures directory `CAPTURES` (AirScope's `Config.captures_dir`), quarantined
files go to its **sibling** directory:

```
<CAPTURES>/../quarantine-no-wpa/<same relative path/name as under CAPTURES>
```

(The companion `exports/` sibling holds both the Vault's Export output **and** retention's per-run CSV
audit report described above.) AirScope refuses to run if the quarantine path would fall inside `CAPTURES`. Nothing is ever automatically
purged from `quarantine-no-wpa/` — it only ever grows when you press Clean Empty, and you manage it
by hand.

## Recovery procedure
Because quarantine is a move, **recovery is just moving the file back** — no undelete needed.

1. Find the file under the quarantine folder:
   ```
   ls -l "<CAPTURES>/../quarantine-no-wpa/"
   ```
2. Move it back into the captures directory (same relative path it had):
   ```
   mv "<CAPTURES>/../quarantine-no-wpa/<file>" "<CAPTURES>/<file>"
   ```
3. Re-index the Vault: reopen the Vault screen (or restart AirScope). The restored capture reappears
   in the index.

To discard quarantined files permanently, delete `quarantine-no-wpa/` (or individual files in it)
**yourself** — AirScope will not do it for you.

## Re-enabling automatic retention (not in v0.3.9)
The automatic triggers (on Vault open and after "Validate All") were removed for v0.3.9 and ship
disabled. The underlying `quarantine_stale_wpa` logic is the same code the manual button uses and is
covered by `tests/test_inapp_retention.py` (13 tests). If a future release re-enables automatic
runs, it should do so only behind an explicit, off-by-default setting, and the quarantine-and-recover
model above still applies — automatic runs would move, never delete.
