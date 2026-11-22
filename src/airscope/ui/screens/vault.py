"""VaultView: the loot manager. A DataTable of APs (ESSID | captures | keys) beside a
VaultItemView detail pane; highlighting an AP loads its captures into the pane. All
filesystem access goes through app.vault, so this screen never touches disk directly and
works with no card plugged in.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Label

from airscope.models import CaptureType, PersistedCapture

from .vault_item import VaultItemView, _CapturePanel

_CAPTURE_TYPES = (CaptureType.HS, CaptureType.PMKID, CaptureType.SAE)
_KEY_TYPES = (CaptureType.WEP, CaptureType.WPS_PIN, CaptureType.WPS_PBC, CaptureType.CRACKED)


def _count_captures(caps: List[PersistedCapture]) -> int:
    """Total handshake/PMKID capture records for an AP (hashcat-22000 hashlines; raw
    .pcap companions carry 0, so an .hc22000 + .pcap of one capture counts once)."""
    return sum(c.record_count for c in caps if c.type in _CAPTURE_TYPES)


def _count_keys(caps: List[PersistedCapture]) -> int:
    """Recovered credentials for an AP: WEP keys + WPS PSKs (PIN/PBC) that hold a value."""
    return sum(1 for c in caps if c.type in _KEY_TYPES and c.value)


class VaultView(Screen):
    """The loot manager: an AP list beside a per-AP capture detail pane."""

    BINDINGS = [
        Binding("d", "dismiss_job_status", "Dismiss status"),
        Binding("escape", "go_back", "Back", show=True),
        Binding("z", "export_zip", "Export Zip", show=True),
        Binding("o", "show_directory", "Show Directory", show=True),
        Binding("x", "export_all", "Export all", show=True),
    ]

    CSS = """
    VaultView #vault-status-panel {
        width: 1fr; height: auto; max-height: 6; border: round $accent; padding: 0 1;
        margin: 0 1; background: $panel; border-title-color: $accent;
    }
    VaultView #vault-status-panel.recovered { border: round $success; }
    VaultView #vault-status-panel.failed { border: round $error; }
    VaultView #vault-body { height: 1fr; }
    VaultView #vault-aps { width: 40%; height: 1fr; border: round $primary;
                           border-title-color: $primary; border-title-style: bold; }
    VaultView VaultItemView { width: 60%; border: round $surface; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._rendered_recovery = None
        self._aps: Dict[str, Tuple[Optional[str], List[PersistedCapture]]] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="vault-body"):
            yield DataTable(id="vault-aps")
            yield VaultItemView(id="vault-item")
        with VerticalScroll(id="vault-status-panel") as panel:
            panel.border_title = "Cracking Status"
            yield Label("IDLE - No active cracking job.", id="vault-job-status", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#vault-aps", DataTable)
        table.cursor_type = "row"
        table.add_columns("ESSID", "Handshakes", "Passwords")
        self._reload_table()

        self._render_job_status()
        self.set_interval(0.25, self._render_job_status)

    def _render_job_status(self) -> None:
        status = self.app.vault_job_status
        label = self.query_one("#vault-job-status", Label)
        panel = self.query_one("#vault-status-panel")
        panel.set_class(bool(status and status.phase == "RECOVERED"), "recovered")
        panel.set_class(bool(status and status.phase in {"FAILED", "FAILED TO SAVE"}), "failed")
        message = "IDLE - No active cracking job."
        if status is not None:
            if status.phase == "RECOVERED" and status is not self._rendered_recovery:
                self._rendered_recovery = status
                self._reload_table()
            message = status.display()
        if label.content != message:
            label.update(message)

    def action_dismiss_job_status(self) -> None:
        status = self.app.vault_job_status
        if status is not None and status.ended is not None:
            self.app.vault_job_status = None
            self._render_job_status()

    def on_screen_resume(self) -> None:
        """Re-render from the cache each visit (campaigns fold their saves into app.vault)."""
        for panel in self.query(_CapturePanel):
            panel.hide_password()
        self._reload_table()

    # ----- data --------------------------------------------------------------

    def _group_aps(self) -> Dict[str, Tuple[Optional[str], List[PersistedCapture]]]:
        groups: Dict[str, Tuple[Optional[str], List[PersistedCapture]]] = {}
        for cap in self.app.vault.all_captures():
            ssid, caps = groups.setdefault(cap.bssid, (None, []))
            caps.append(cap)
            if ssid is None and cap.ssid:
                groups[cap.bssid] = (cap.ssid, caps)
        return groups

    def _reload_table(self) -> None:
        table = self.query_one("#vault-aps", DataTable)
        table.clear()
        self._aps = self._group_aps()
        ssid_counts: Dict[str, int] = {}
        for ssid, _ in self._aps.values():
            ssid_counts[ssid or ""] = ssid_counts.get(ssid or "", 0) + 1
        rows = sorted(self._aps.items(), key=lambda kv: ((kv[1][0] or "￿").lower(), kv[0]))
        for bssid, (ssid, caps) in rows:
            name = ssid or "‹hidden›"
            if ssid_counts.get(ssid or "", 0) > 1:
                name = f"{name} ({bssid})"
            table.add_row(name, self._fmt(_count_captures(caps)), self._fmt(_count_keys(caps)),
                          key=bssid)
        self._update_title()
        if not self._aps:
            self.query_one("#vault-item", VaultItemView).load("", None, [], empty_vault=True)

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
            self._load_widget(event.row_key.value)

    @on(VaultItemView.CapturesChanged)
    def _captures_changed(self) -> None:
        self._reload_table()

    # ----- actions -----------------------------------------------------------

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
