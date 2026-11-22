"""VaultView: the loot manager. A DataTable of APs (ESSID | captures | keys) beside a
VaultItemView detail pane; highlighting an AP loads its captures into the pane. All
filesystem access goes through app.vault, so this screen never touches disk directly and
works with no card plugged in.
"""
from __future__ import annotations
import asyncio
import csv
from dataclasses import dataclass, field
from collections import Counter
from datetime import datetime
from pathlib import Path

from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual import events, on
from textual.message import Message
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label

from airscope.models import CaptureType, PersistedCapture
from airscope.persist.vault_validation_batch import inspect_capture

from .vault_item import VaultItemView

_CAPTURE_TYPES = (CaptureType.HS, CaptureType.PMKID, CaptureType.SAE)
_KEY_TYPES = (CaptureType.WEP, CaptureType.WPS_PIN, CaptureType.WPS_PBC, CaptureType.CRACKED)


def _count_captures(caps: List[PersistedCapture]) -> int:
    """Total handshake/PMKID capture records for an AP (hashcat-22000 hashlines; raw
    .pcap companions carry 0, so an .hc22000 + .pcap of one capture counts once)."""
    return sum(c.record_count for c in caps if c.type in _CAPTURE_TYPES)


def _count_keys(caps: List[PersistedCapture]) -> int:
    """Recovered credentials for an AP: WEP keys + WPS PSKs (PIN/PBC) that hold a value."""
    return sum(1 for c in caps if c.type in _KEY_TYPES and c.value)


@dataclass
class SelectedValidation:
    total: int
    results: list[str] = field(default_factory=list)
    state: str = "Running"
    current: str = ""

    async def run(self, items):
        try:
            for name, capture in items:
                if self.state == "Cancelling":
                    break
                self.current = f"{name} / {Path(capture.path).name}"
                try:
                    result = await asyncio.to_thread(inspect_selected_file, capture)
                except Exception as exc:
                    result = f"Validation error ({type(exc).__name__})"
                self.results.append(f"{self.current}: {result}")
            self.state = "Cancelled" if self.state == "Cancelling" else "Complete"
        finally:
            self.current = ""


def inspect_selected_file(capture):
    from airscope.persist.capture_validation import HASH_SUFFIXES, validate_selected_capture

    path = Path(capture.path)
    if path.suffix.lower() in HASH_SUFFIXES:
        return validate_selected_capture(path, capture.bssid)
    # Reject corrupt packet headers before reporting the extractor's file-level results.
    metadata = validate_selected_capture(path, capture.bssid)
    if not metadata.startswith(("pcap |", "pcapng |")) or "inspection failed" in metadata.lower():
        return metadata
    result = inspect_capture(capture)
    if result["status"] == "extractable":
        return (f"Extractable WPA records in file: EAPOL {result['eapol_records']}, "
                f"PMKID {result['pmkid_records']} | {metadata}")
    if result["status"] == "no_records":
        return f"No extractable handshake data | {metadata}"
    return f"Validation error: {result['details']}"


class NetworkName(Text):
    """Fit the display name to the cell while keeping its credential marker visible."""

    def __rich_console__(self, console, options):
        marker = "  (RECOVERED)" if self.plain.endswith("  (RECOVERED)") else ""
        name = self.plain.removesuffix(marker)
        text = Text(name, no_wrap=True)
        text.truncate(max(1, options.max_width - len(marker)), overflow="ellipsis")
        text.append(marker)
        yield from text.__rich_console__(console, options)


class NetworkTable(DataTable):
    def on_resize(self, event: events.Resize) -> None:
        column = self.columns.get("essid")
        if column is None:
            return
        # Reserve the vertical scrollbar so names keep their width as rows are added.
        fixed = sum(c.get_render_width(self) for c in self.columns.values() if c is not column)
        width = max(4, self.content_size.width - self.styles.scrollbar_size_vertical
                    - fixed - 2 * self.cell_padding)
        if column.width != width:
            column.width = width
            self._update_dimensions(())
            self._clear_caches()

    class ToggleNetwork(Message):
        def __init__(self, bssid: str) -> None:
            super().__init__()
            self.bssid = bssid

    def on_click(self, event: events.Click) -> None:
        meta = event.style.meta
        row = meta.get("row", -1)
        if meta.get("column") == 0 and 0 <= row < self.row_count and not meta.get("out_of_bounds"):
            event.stop()
            event.prevent_default()
            self.post_message(self.ToggleNetwork(self.ordered_rows[row].key.value))


class VaultView(Screen):
    """The loot manager: an AP list beside a per-AP capture detail pane."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
        Binding("z", "export_zip", "Export Zip", show=True),
        Binding("o", "show_directory", "Show Directory", show=True),
        Binding("x", "export_all", "Export all", show=True),
        Binding("space", "toggle_network", "Select network", show=False),
        Binding("v", "dismiss_validation", "Dismiss validation"),
        Binding("a", "validate_all_captures", "Validate All", show=True),
    ]

    CSS = """
    VaultView #selected-actions { height: 3; }
    VaultView #selected-actions Button { min-width: 8; width: auto; }
    VaultView #selected-report { height: auto; max-height: 6; border: round $primary; padding: 0 1; }
    VaultView _CapturePanel .actions {
        layout: grid; grid-size: 3; grid-rows: 3; height: auto;
    }
    VaultView _CapturePanel .actions Button { width: 1fr; min-width: 6; }
    VaultView #vault-body { height: 1fr; }
    VaultView #vault-validate-row { height: auto; min-height: 3; align: left middle; }
    VaultView #vault-validation-status { width: 1fr; height: auto; margin-left: 1; }
    VaultView #vault-aps { width: 55%; height: 1fr; border: round $primary;
                           border-title-color: $primary; border-title-style: bold; }
    VaultView VaultItemView { overflow-y: auto; width: 45%; border: round $surface; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._aps: Dict[str, Tuple[Optional[str], List[PersistedCapture]]] = {}
        self._checked: set[str] = set()
        self._eligible: set[str] = set()
        self._selected_bssid: Optional[str] = None
        self._bulk_validating = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="vault-validate-row"):
            yield Button("Validate All", id="vault-validate-all")
            yield Label(getattr(self.app, "vault_validation_summary", "") or "Ready",
                        id="vault-validation-status", markup=False)
        with Horizontal(id="selected-actions"):
            yield Button("Select All", id="select-networks")
            yield Button("Clear Selection", id="clear-networks")
            yield Button("Validate Selected", id="validate-selected")
            yield Button("Cancel", id="cancel-selected", disabled=True)
        with VerticalScroll(id="selected-report") as report:
            report.border_title = "Selected network validation"
            yield Label("", id="selected-results", markup=False)
        yield Label("✓ N = extracted files | H N = saved hash files | 0 = no WPA records | ? = unverified", id="vault-legend")
        with Horizontal(id="vault-body"):
            yield NetworkTable(id="vault-aps", fixed_columns=1, show_row_labels=False)
            yield VaultItemView(id="vault-item")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#vault-aps", DataTable)
        table.cursor_type = "row"
        if not hasattr(self.app, "vault_checked_networks"):
            self.app.vault_checked_networks = set()
        self._checked = self.app.vault_checked_networks
        table.add_column("", key="checked", width=5)
        table.add_column("ESSID", key="essid", width=4)
        table.add_column("HS", key="handshakes", width=5)
        table.add_column("PW", key="passwords", width=3)
        self._reload_table()
        self._render_selected()
        self.set_interval(0.25, self._render_selected)

    def on_screen_resume(self) -> None:
        """Re-render from the cache each visit (campaigns fold their saves into app.vault)."""
        self._reload_table()

    # ----- data --------------------------------------------------------------

    def _group_aps(self) -> Dict[str, Tuple[Optional[str], List[PersistedCapture]]]:
        groups: Dict[str, Tuple[Optional[str], List[PersistedCapture]]] = {}
        for cap in self.app.vault.all_captures():
            ssid, caps = groups.setdefault(cap.bssid, (None, []))
            caps.append(cap)
            if cap.ssid and (ssid is None or cap.type == CaptureType.CRACKED):
                groups[cap.bssid] = (cap.ssid, caps)
        return groups

    @staticmethod
    def _read_latest_validation():
        """Read the latest saved batch report, ignoring stale or changed files.

        Results are evidence of extraction, not cryptographic handshake proof.
        Key by BSSID AND file path so records from different networks cannot mix.
        """
        from airscope.persist.config import Config
        directory = Path(Config.captures_dir).parent / "exports"
        reports = sorted(directory.glob("airscope_validation_*.csv"), reverse=True)
        if not reports:
            return None
        latest = reports[0]
        found = {}
        try:
            report_mtime = latest.stat().st_mtime
            with latest.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                if not {"bssid", "file_path", "size_bytes", "status"}.issubset(reader.fieldnames or []):
                    return None
                for entry in reader:
                    path_text = entry.get("file_path") or ""
                    bssid = (entry.get("bssid") or "").casefold()
                    if not path_text or not bssid:
                        continue
                    path = Path(path_text)
                    try:
                        stat = path.stat()
                        if (stat.st_size != int(entry.get("size_bytes") or 0)
                                or stat.st_mtime > report_mtime):
                            continue
                    except (OSError, ValueError):
                        # A missing file can retain its previously recorded missing status.
                        if entry.get("status") != "missing" or path.exists():
                            continue
                    found[(bssid, path_text)] = entry
        except (OSError, csv.Error, UnicodeError):
            return None
        return found

    @staticmethod
    def _vault_handshake_status_cell(caps, validation):
        """One compact per-network summary of distinct validated capture files.

        ✓ N = N packet-capture files yielded EAPOL/PMKID records.
        H N = N files had saved WPA hash-format markers only.
        0 = supported WPA files tested, none yielded usable records.
        ? = not validated, unreadable, or stale. Indexed count plus ? = untested.
        """
        candidate = {}
        for capture in caps:
            if capture.type not in _CAPTURE_TYPES:
                continue
            if Path(capture.path).suffix.casefold() not in {".pcap", ".pcapng", ".cap", ".hc22000", ".22000"}:
                continue
            candidate.setdefault(str(capture.path), capture)
        if not candidate:
            return ""
        if validation is None:
            count = _count_captures(caps)
            return f"{count}?" if count else "?"

        extracted = saved_markers = no_records = unknown = 0
        for path_text, capture in candidate.items():
            entry = validation.get(((capture.bssid or "").casefold(), path_text))
            if entry is None:
                unknown += 1
                continue
            try:
                records = int(entry.get("eapol_records") or 0) + int(entry.get("pmkid_records") or 0)
            except ValueError:
                records = 0
            status = entry.get("status")
            if status == "extractable" and records > 0:
                extracted += 1
            elif status == "saved_hash_markers" and records > 0:
                saved_markers += 1
            elif status == "no_records":
                no_records += 1
            else:
                unknown += 1

        if extracted:
            return f"✓ {extracted}" + (" ?" if unknown else "")
        if saved_markers:
            return f"H {saved_markers}" + (" ?" if unknown else "")
        if unknown:
            return "?"
        if no_records:
            return "0"
        return "?"

    def _reload_table(self) -> None:
        table = self.query_one("#vault-aps", DataTable)
        old_index = table.cursor_row
        table.clear()
        validation = self._read_latest_validation()
        self._aps = self._group_aps()
        from airscope.persist.capture_validation import HASH_SUFFIXES, PACKET_SUFFIXES
        self._eligible = {bssid for bssid, (_, caps) in self._aps.items()
                          if any(Path(cap.path).suffix.lower() in HASH_SUFFIXES | PACKET_SUFFIXES
                                 for cap in caps)}
        self._checked.intersection_update(self._eligible)
        ssid_counts: Dict[str, int] = {}
        for ssid, _ in self._aps.values():
            ssid_counts[ssid or ""] = ssid_counts.get(ssid or "", 0) + 1
        rows = sorted(self._aps.items(), key=lambda kv: ((kv[1][0] or "￿").lower(), kv[0]))
        for bssid, (ssid, caps) in rows:
            name = ssid or "‹hidden›"
            if ssid_counts.get(ssid or "", 0) > 1:
                name = f"{name} ({bssid})"
            if any(c.type == CaptureType.CRACKED and c.value for c in caps):
                name += "  (RECOVERED)"
            table.add_row(self._mark(bssid), NetworkName(name), self._vault_handshake_status_cell(caps, validation), self._fmt(_count_keys(caps)),
                          key=bssid)
        self._render_selected()
        self._update_title()
        if not self._aps:
            self._selected_bssid = None
            self.query_one("#vault-item", VaultItemView).load("", None, [], empty_vault=True)
            return
        keys = [bssid for bssid, _ in rows]
        if self._selected_bssid in self._aps:
            selected = self._selected_bssid
        else:
            index = old_index if isinstance(old_index, int) else 0
            selected = keys[min(max(index, 0), len(keys) - 1)]
        self._selected_bssid = selected
        self._load_widget(selected)  # Always rebuild the capture detail panel.
        table.move_cursor(row=keys.index(selected))

    @staticmethod
    def _fmt(n: int) -> str:
        return str(n) if n else ""

    def _update_title(self) -> None:
        self.query_one("#vault-aps", DataTable).border_title = f" Captured Results ({len(self._aps)} networks)"

    def _load_widget(self, bssid: str) -> None:
        widget = self.query_one("#vault-item", VaultItemView)
        entry = self._aps.get(bssid)
        if entry is not None:
            widget.load(bssid, entry[0], entry[1])
        else:
            widget.load("", None, [])

    # ----- events ------------------------------------------------------------

    @on(DataTable.RowHighlighted, "#vault-aps")
    def _ap_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value is not None:
            self._selected_bssid = event.row_key.value
            self._load_widget(event.row_key.value)

    @on(VaultItemView.CapturesChanged)
    def _captures_changed(self) -> None:
        self.app.vault.refresh()
        self._reload_table()

    # ----- actions -----------------------------------------------------------

    def _mark(self, bssid: str) -> Text:
        checked = bssid in self._checked
        return Text("[x]" if checked else "[ ]", style="bold" if checked else "", justify="center")

    def _set_checked(self, selected: set[str]) -> None:
        table = self.query_one("#vault-aps", DataTable)
        changed = self._checked ^ selected
        self._checked.clear()
        self._checked.update(selected)
        for key in changed:
            table.update_cell(key, "checked", self._mark(key))
        self._render_selected()

    @on(NetworkTable.ToggleNetwork)
    def _check_row(self, event: NetworkTable.ToggleNetwork) -> None:
        if event.bssid in self._eligible:
            self._set_checked(self._checked ^ {event.bssid})

    def action_toggle_network(self) -> None:
        table = self.query_one("#vault-aps", DataTable)
        if self.focused is table and table.is_valid_row_index(table.cursor_row):
            key = table.ordered_rows[table.cursor_row].key.value
            if key in self._eligible:
                self._set_checked(self._checked ^ {key})

    @on(Button.Pressed, "#select-networks")
    def _select_networks(self) -> None:
        self._set_checked(self._eligible)

    @on(Button.Pressed, "#clear-networks")
    def _clear_networks(self) -> None:
        self._set_checked(set())

    @on(Button.Pressed, "#validate-selected")
    def _validate_selected_networks(self) -> None:
        from airscope.persist.capture_validation import HASH_SUFFIXES, PACKET_SUFFIXES
        previous = getattr(self.app, "selected_validation", None)
        if previous and previous.state in {"Running", "Cancelling"}:
            return
        items = []
        seen = set()
        for bssid in sorted(self._checked):
            name, captures = self._aps[bssid]
            for capture in captures:
                key = (bssid, capture.path)
                if key not in seen and Path(capture.path).suffix.lower() in PACKET_SUFFIXES | HASH_SUFFIXES:
                    seen.add(key)
                    items.append((f"{name or 'Hidden'} ({bssid})", capture))
        if not items:
            self.notify("Select a network with an indexed packet capture or saved WPA records.")
            return
        batch = SelectedValidation(len(items))
        self.app.selected_validation = batch
        self.app.run_worker(batch.run(items), group="selected-validation")
        self._render_selected()

    @on(Button.Pressed, "#cancel-selected")
    def _cancel_selected(self) -> None:
        batch = getattr(self.app, "selected_validation", None)
        if batch and batch.state == "Running":
            batch.state = "Cancelling"
            self._render_selected()

    def _render_selected(self) -> None:
        batch = getattr(self.app, "selected_validation", None)
        self.query_one("#selected-report").display = batch is not None
        busy = bool(batch and batch.state in {"Running", "Cancelling"})
        self.query_one("#validate-selected", Button).disabled = busy or not self._checked
        self.query_one("#cancel-selected", Button).disabled = not batch or batch.state != "Running"
        if batch:
            label = self.query_one("#selected-results", Label)
            lines = [f"{batch.state} | {len(batch.results)}/{batch.total} files checked"]
            if batch.current:
                lines.append(batch.current)
            message = "\n".join(lines + batch.results)
            if label.content != message:
                label.update(message)

    @on(Button.Pressed, "#vault-validate-all")
    def _validate_all_clicked(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_validate_all_captures()

    def action_dismiss_validation(self) -> None:
        if not self._bulk_validating:
            self.app.vault_validation_summary = ""
            self.query_one("#vault-validation-status", Label).update("Ready")

    def action_validate_all_captures(self) -> None:
        """Check all indexed records without editing capture files."""
        if self._bulk_validating:
            self.notify("Validation already running", severity="warning")
            return
        captures = list(self.app.vault.all_captures())
        if not captures:
            self.app.vault_validation_summary = "Checked 0 files. No indexed captures."
            self.query_one("#vault-validation-status", Label).update(self.app.vault_validation_summary)
            return
        self.app.vault_validation_summary = ""
        self._bulk_validating = True
        self.query_one("#vault-validate-all", Button).disabled = True
        self.query_one("#vault-validation-status", Label).update(
            f"Starting validation of {len(captures)} records..."
        )
        self.run_worker(
            self._validate_all_async(captures),
            group="vault-bulk-validation",
            exclusive=True,
        )

    async def _validate_all_async(self, captures: List[PersistedCapture]) -> None:
        """Keep Textual responsive while checking files on a worker thread."""
        rows = []
        seen = {}
        counts = Counter()
        total = len({str(capture.path) for capture in captures})

        def summary():
            return (f"{len(seen)}/{total} files reviewed | Checked {len(seen) - counts['skipped']} | "
                    f"Validated {counts['extractable']} | Markers only {counts['saved_hash_markers']} | "
                    f"Incomplete/no records {counts['no_records']} | "
                    f"Failed {counts['missing'] + counts['unverified']} | Skipped {counts['skipped']}")

        label = self.query_one("#vault-validation-status", Label)
        try:
            for capture in captures:
                # The index may have multiple records referencing one physical file.
                # Check each physical file once but include every indexed record in CSV.
                path = str(capture.path)
                if path not in seen:
                    try:
                        seen[path] = await asyncio.to_thread(inspect_capture, capture)
                    except Exception as exc:
                        seen[path] = {"status": "unverified", "details": type(exc).__name__}
                    counts[seen[path]["status"]] += 1
                    label.update(summary())
                result = seen[path]
                row = {
                    "ssid": capture.ssid or "",
                    "bssid": capture.bssid or "",
                    "capture_type": getattr(capture.type, "value", str(capture.type)),
                    "file_path": path,
                    **result,
                }
                rows.append(row)

            from airscope.persist.config import Config
            directory = Path(Config.captures_dir).parent / "exports"
            directory.mkdir(parents=True, exist_ok=True)
            target = directory / (
                "airscope_validation_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv"
            )
            columns = [
                "ssid", "bssid", "capture_type", "file_path", "size_bytes",
                "status", "eapol_packets", "eapol_records", "pmkid_records",
                "other_wpa_records", "details",
            ]
            # Atomic report replacement; never touch existing capture data.
            tmp = target.with_suffix(".csv.tmp")
            try:
                with tmp.open("w", encoding="utf-8", newline="") as out:
                    writer = csv.DictWriter(out, fieldnames=columns)
                    writer.writeheader()
                    writer.writerows(rows)
                tmp.replace(target)
            finally:
                tmp.unlink(missing_ok=True)

            self.app.vault_validation_summary = f"Done | {summary()} | CSV saved"
            label.update(self.app.vault_validation_summary)
            self.notify(f"Vault validation report: {target}", timeout=15)
            self._reload_table()  # Show fresh validation indicators immediately.
        except Exception as exc:
            self.app.vault_validation_summary = f"{summary()} | Validation error: {type(exc).__name__}: {exc}"
            label.update(self.app.vault_validation_summary)
            self.notify(f"Validation failed: {exc}", severity="error")
        finally:
            self._bulk_validating = False
            try:
                self.query_one("#vault-validate-all", Button).disabled = False
            except Exception:
                pass

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_export_zip(self) -> None:
        try:
            out = self.app.vault.zip_captures(self.app.vault.all_captures())
        except OSError as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return
        if out is None:
            self.notify("Nothing to export", severity="warning")
            return
        self.notify(f"Exported to {out}")

    def action_show_directory(self) -> None:
        try:
            self.app.vault.open_directory()
        except OSError as exc:
            self.notify(f"Could not open captures dir: {exc}", severity="error")

    def action_export_all(self) -> None:
        """Write csv + netxml + cracked.txt + report.html beside captures/."""
        from pathlib import Path

        from airscope import exports
        from airscope.persist.config import Config
        try:
            array = self.app.array
            aps = exports.ap_snaps_from_array(array) if array is not None else []
        except Exception as exc:
            self.notify(f"Could not snapshot APs: {exc}", severity="error")
            return
        # Include saved Vault networks, not only live scanner results.
        known = {ap.bssid.lower(): ap for ap in aps if ap.bssid}

        for capture in self.app.vault.all_captures():
            bssid = (capture.bssid or "").strip()
            if not bssid:
                continue

            key = bssid.lower()

            if key not in known:
                ap = exports.ApSnap(
                    bssid=bssid,
                    ssid=capture.ssid,
                )
                known[key] = ap
                aps.append(ap)
            elif not known[key].ssid and capture.ssid:
                known[key].ssid = capture.ssid

        cracks = exports.cracks_from_vault(self.app.vault)
        keys = {c.bssid: c.psk for c in cracks}
        session = exports.latest_session_jsonl(Path.cwd())
        steps = exports.steps_from_jsonl(session) if session else []
        outdir = Path(Config.captures_dir).parent / "exports"
        try:
            exports.export_all(outdir, aps, cracks, steps, keys)
        except OSError as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return
        self.notify(f"Exported csv + netxml + cracked + html to {outdir}"
                    + (" (with batch log)" if session else ""))
