"""VaultItemView: the detail pane for one AP's saved captures. Given an AP's
PersistedCapture list it renders a per-kind panel (Handshake/PMKID, WEP, WPS PIN,
WPS PBC). Credential panels show one row per field (hex/ASCII, PSK/PIN) each with its
own Copy; capture panels show a summary + a Copy of the hashcat hashline. Delete and
(for legacy split .hc22000 files) Consolidate live in the panel too. All filesystem
work goes through app.vault.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional

from rich.markup import escape
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalGroup
from textual.events import Event
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.worker import Worker, WorkerState
from textual.widgets import Button, Input, Label, Select

from airscope.ui.job_status import VaultJobStatus
from airscope.models import CaptureType, PersistedCapture
from airscope.crack import external as crack_ext
from airscope.persist.common import bssid_to_dashed
from airscope.persist.capture_validation import PACKET_SUFFIXES, validate_selected_capture

_crack_log = logging.getLogger("airscope.vault.crack")

# (title, kinds) per panel, in display order. HS and PMKID share one panel.
_PANELS: list[tuple[str, tuple[CaptureType, ...]]] = [
    ("Captured Handshakes & PMKIDs", (CaptureType.HS, CaptureType.PMKID)),
    ("WEP Key", (CaptureType.WEP,)),
    ("WPS PIN", (CaptureType.WPS_PIN,)),
    ("WPS Push-Button", (CaptureType.WPS_PBC,)),
    ("Recovered Password", (CaptureType.CRACKED,)),
    ("SAE (WPA3)", (CaptureType.SAE,)),
]

# Per credential kind: the (row label, field key) rows to show, each with its own Copy.
_FIELDS: dict[CaptureType, list[tuple[str, str]]] = {
    CaptureType.WEP: [("WEP Key (hex)", "hex"), ("WEP Key (ASCII)", "ascii")],
    CaptureType.WPS_PIN: [("PSK", "psk"), ("PIN", "pin")],
    CaptureType.WPS_PBC: [("PSK", "psk")],
    CaptureType.CRACKED: [("PSK", "psk")],
}


def _hex_to_ascii(hex_key: Optional[str]) -> str:
    """Printable ASCII rendering of a hex WEP key, or "" if non-printable/invalid."""
    if not hex_key:
        return ""
    try:
        raw = bytes.fromhex(hex_key)
    except ValueError:
        return ""
    return raw.decode("ascii") if all(32 <= b < 127 for b in raw) else ""


def _field_value(cap: PersistedCapture, key: str) -> str:
    """The copyable text for one field of a capture (empty string if absent)."""
    if key == "hex":
        return cap.value or ""
    if key == "ascii":
        return _hex_to_ascii(cap.value)
    if key == "psk":
        return cap.value or ""
    if key == "pin":
        return cap.pin or ""
    return ""


class ConfirmModal(ModalScreen[bool]):
    """Yes/No confirmation; focus defaults to No."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    ConfirmModal { align: center middle; }
    ConfirmModal #dialog {
        width: 54; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    ConfirmModal #prompt { margin-bottom: 1; }
    ConfirmModal Horizontal { align: right middle; height: auto; }
    ConfirmModal Button { margin-left: 1; }
    """

    def __init__(self, prompt: str) -> None:
        super().__init__()
        self._prompt = prompt

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(Text.from_markup(self._prompt), id="prompt")
            with Horizontal():
                yield Button(Text("No"), "default", id="no")
                yield Button(Text("Yes"), "error", id="yes")

    @on(Button.Pressed, "#yes")
    def _yes(self, event: Event) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def _no(self, event: Event) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


class ConsolidateModal(ModalScreen[bool]):
    """Confirm merging legacy per-capture .hc22000 files into one file per AP."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    ConsolidateModal { align: center middle; }
    ConsolidateModal #dialog {
        width: 54; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    ConsolidateModal #prompt { margin-bottom: 1; }
    ConsolidateModal Horizontal { align: right middle; height: auto; }
    ConsolidateModal Button { margin-left: 1; }
    """

    def __init__(self, legacy_count: int, target_count: int) -> None:
        super().__init__()
        self.legacy_count = legacy_count
        self.target_count = target_count

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("[bold]Consolidate .hc22000 Captures[/]", id="title")
            dupes = self.legacy_count - self.target_count
            msg = Text.from_markup(
                f"\nYou have [bold orange1]{self.legacy_count}[/] separate .hc22000 files from "
                f"[bold green]{self.target_count}[/] APs.\n\n"
                f"Do you want to condense these into single files per AP?\n\n"
                f"    [bold green]{self.target_count} files will be created/updated[/]\n"
                f"    [bold red]{dupes} duplicate files will be removed[/]"
            )
            yield Label(msg, id="prompt")
            with Horizontal():
                yield Button(Text("Yes"), "primary", id="confirm")
                yield Button(Text("No"), "default", id="cancel")

    @on(Button.Pressed, "#confirm")
    def _confirm(self, event: Event) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#cancel")
    def _cancel(self, event: Event) -> None:
        self.dismiss(False)


class CrackModal(ModalScreen[Optional[str]]):
    """Pick a wordlist for one capture; dismisses with the path, or None."""

    DEFAULT_CSS = """
    CrackModal { align: center middle; }
    CrackModal #crack-dialog {
        width: 64; height: auto;
        border: thick $primary; background: $surface; padding: 1 2;
    }
    CrackModal #crack-tool { margin-top: 1; }
    CrackModal #crack-wordlist { margin-top: 1; }
    CrackModal #crack-error { color: $error; height: auto; margin-top: 1; }
    CrackModal Horizontal { align: right middle; height: auto; margin-top: 1; }
    CrackModal Button { margin-left: 1; }
    """

    def __init__(self, filename: str, tool_line: str, default_wordlist: str,
                 can_start: bool = True) -> None:
        super().__init__()
        self._filename = filename
        self._tool_line = tool_line
        self._default_wordlist = default_wordlist
        self._can_start = can_start

    def compose(self) -> ComposeResult:
        with Vertical(id="crack-dialog"):
            yield Label("[bold]🔍 Crack Password[/]")
            yield Label(Text.from_markup(f"[dim]{escape(self._filename)}[/dim]"))
            yield Label(Text.from_markup(self._tool_line), id="crack-tool")
            yield Label("Wordlist:", id="crack-wordlist-label")
            yield Input(placeholder="/usr/share/wordlists/rockyou.txt",
                        value=self._default_wordlist, id="crack-wordlist")
            yield Label("", id="crack-error")
            with Horizontal():
                yield Button("Cancel", id="crack-cancel")
                yield Button("Start", "primary", id="crack-start", disabled=not self._can_start)

    @on(Button.Pressed, "#crack-cancel")
    def _cancel(self, event: Event) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#crack-start")
    def _start(self, event: Event) -> None:
        path = self.query_one("#crack-wordlist", Input).value.strip()
        if not path or not Path(path).is_file():
            self.query_one("#crack-error", Label).update("Wordlist file not found - check the path and try again.")
            return
        self.dismiss(path)

    def action_cancel(self) -> None:
        self.dismiss(False)


class _CapturePanel(VerticalGroup):
    """One kind-group of an AP's captures: file dropdown, per-field rows (or a
    capture summary), Copy/Delete, and Consolidate for legacy files."""

    DEFAULT_CSS = """
    _CapturePanel { height: auto; border: round $primary; padding: 0 1; margin-bottom: 1; }
    _CapturePanel .detail { height: auto; margin: 0 0 1 0; }
    _CapturePanel .modified { height: 1; margin-bottom: 1; }
    _CapturePanel .field { height: 1; align: left middle; }
    _CapturePanel .fval { width: 1fr; height: 1; }
    _CapturePanel .field Button { width: auto; height: 1; min-width: 8; border: none; }
    _CapturePanel .actions { height: auto; align: left middle; }
    _CapturePanel .actions Button { margin-right: 1; }
    _CapturePanel .crack-progress { height: auto; color: $text-muted; margin-top: 1; }
    """

    def __init__(self, title: str, captures: List[PersistedCapture],
                 show_consolidate: bool = False) -> None:
        super().__init__()
        self._title = title
        self._by_path: Dict[str, PersistedCapture] = {}
        for cap in sorted(captures, key=lambda c: c.timestamp, reverse=True):
            self._by_path.setdefault(cap.path, cap)   # unique files, newest first
        self._files = list(self._by_path.values())
        self._show_consolidate = show_consolidate
        self._crackable = bool({c.type for c in self._files} & {CaptureType.HS, CaptureType.PMKID})
        self._status = None
        self._crack_worker = None
        self._crack_pending: Optional[tuple] = None
        self._crack_tool = ""
        self._password_visible = False
        self._validation_request = 0

    def compose(self) -> ComposeResult:
        self.border_title = f"{self._title} ({len(self._files)})"
        newest = self._files[0]
        yield Select([(Path(c.path).name, c.path) for c in self._files],
                     value=newest.path, allow_blank=False, classes="file")
        fields = _FIELDS.get(newest.type, [])
        if fields:
            yield Label(self._modified_text(newest), classes="modified")
            for flabel, fkey in fields:
                with Horizontal(classes="field"):
                    yield Label(self._field_text(newest, flabel, fkey), classes=f"fval fval-{fkey}")
                    if fkey == "psk":
                        yield Button("Show", classes="toggle-password")
                    yield Button("Copy", classes=f"copy copy-{fkey}")
        else:
            yield Label(Text.from_markup(self._detail_markup(newest)), classes="detail")
        with Horizontal(classes="actions"):
            if not fields:
                yield Button("Copy", classes="copy copy-payload",
                             disabled=Path(newest.path).suffix.lower() in PACKET_SUFFIXES)
            if self._crackable:
                yield Button("Validate", classes="validate")
                yield Button("Crack", classes="crack")
            yield Button("Delete", "error", classes="delete")
            if self._show_consolidate and self.app.vault.legacy_hc_file_count():
                yield Button("Consolidate", "warning", classes="consolidate")
        if self._crackable:
            yield Label("", classes="validation-progress")
            yield Label("", classes="crack-progress")

    # ----- rendering -----

    def _selected(self) -> Optional[PersistedCapture]:
        return self._by_path.get(self.query_one(Select).value)

    @staticmethod
    def _modified_text(cap: PersistedCapture) -> Text:
        when = datetime.fromtimestamp(cap.timestamp).strftime("%Y-%m-%d %H:%M")
        return Text.from_markup(f"[dim]Modified:[/dim] {when}")

    def _field_text(self, cap: PersistedCapture, flabel: str, fkey: str) -> Text:
        val = _field_value(cap, fkey)
        shown = escape(val) if val else "[dim](none)[/dim]"
        if val and fkey == "psk" and not self._password_visible:
            shown = "********"
        return Text.from_markup(f"[dim]{escape(flabel)}:[/dim] {shown}")

    def _detail_markup(self, cap: PersistedCapture) -> str:
        when = datetime.fromtimestamp(cap.timestamp).strftime("%Y-%m-%d %H:%M")
        if cap.type == CaptureType.SAE:
            pairs = f"{cap.record_count} SAE pair" + ("s" if cap.record_count != 1 else "")
            detail = (f"[dim]{pairs} (Dragonfly commit+confirm)[/dim]\n"
                      f"[dim]Convert: hcxpcapngtool -o out.hc22000 {escape(Path(cap.path).name)}[/dim]\n"
                      f"[dim]Crack: hashcat -m 22000 out.hc22000 wordlist[/dim]")
        elif Path(cap.path).suffix.lower() in PACKET_SUFFIXES:
            detail = "[dim]Raw packet capture[/dim]"
        else:
            detail = self._hc_summary(cap)
        return f"[dim]Modified:[/dim] {when}\n{detail}"

    def _hc_summary(self, cap: PersistedCapture) -> str:
        text = self.app.vault.capture_payload(cap)
        hs = sum(1 for ln in text.splitlines() if ln.startswith("WPA*02*"))
        pmkid = sum(1 for ln in text.splitlines() if ln.startswith("WPA*01*"))
        parts = []
        if hs:
            parts.append(f"{hs} handshake" + ("s" if hs != 1 else ""))
        if pmkid:
            parts.append(f"{pmkid} PMKID" + ("s" if pmkid != 1 else ""))
        return "[dim]" + (", ".join(parts) or "hashcat 22000 file") + "[/dim]"

    # ----- events -----

    def hide_password(self) -> None:
        if self._password_visible:
            self._set_password_visible(False)

    def _set_password_visible(self, visible: bool) -> None:
        self._password_visible = visible
        cap = self._selected()
        if cap is not None:
            self.query_one(".fval-psk", Label).update(self._field_text(cap, "PSK", "psk"))
            self.query_one(".toggle-password", Button).label = "Hide" if visible else "Show"

    @on(Button.Pressed, ".toggle-password")
    def _toggle_password(self, event: Button.Pressed) -> None:
        event.stop()
        self._set_password_visible(not self._password_visible)

    @on(Select.Changed)
    def _file_changed(self, event: Select.Changed) -> None:
        self.hide_password()
        self._validation_request += 1
        if self._crackable:
            self.query_one(".validation-progress", Label).update("")
        cap = self._by_path.get(event.value)
        if cap is None:
            return
        fields = _FIELDS.get(cap.type, [])
        if fields:
            self.query_one(".modified", Label).update(self._modified_text(cap))
            for flabel, fkey in fields:
                self.query_one(f".fval-{fkey}", Label).update(self._field_text(cap, flabel, fkey))
        else:
            self.query_one(".detail", Label).update(Text.from_markup(self._detail_markup(cap)))
            self.query_one(".copy-payload", Button).disabled = (
                Path(cap.path).suffix.lower() in PACKET_SUFFIXES
            )

    @on(Button.Pressed, ".validate")
    def _validate_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        selected = self._selected()
        if selected is None:
            return
        self.query_one(".validation-progress", Label).update("Inspecting capture...")
        self._validation_request += 1
        self.run_worker(self._validate_selected(selected, self._validation_request),
                        group="capture-validation", exclusive=True)

    async def _validate_selected(self, selected: PersistedCapture, request: int) -> None:
        try:
            result = await asyncio.to_thread(
                validate_selected_capture, Path(selected.path), selected.bssid
            )
        except Exception as exc:
            result = f"Validation error: {type(exc).__name__}: {exc}"
        if request != self._validation_request:
            return
        try:
            self.query_one(".validation-progress", Label).update(Text(result))
        except Exception:
            pass  # The user may have navigated away while validation ran.

    @on(Button.Pressed, ".copy")
    def _copy(self, event: Button.Pressed) -> None:
        event.stop()
        cap = self._selected()
        if cap is None:
            return
        classes = event.button.classes
        if "copy-payload" in classes:
            text = self.app.vault.capture_payload(cap)
        else:
            key = next((c[len("copy-"):] for c in classes if c.startswith("copy-")), "")
            text = _field_value(cap, key)
        if not text:
            self.notify("Nothing to copy for this entry", severity="warning")
            return
        self.app.copy_to_clipboard(text)
        self.notify("Copied to clipboard")

    @on(Button.Pressed, ".delete")
    def _delete(self, event: Button.Pressed) -> None:
        event.stop()
        cap = self._selected()
        if cap is None:
            self.notify("Select a capture file first", severity="warning")
            return
        name = Path(cap.path).name
        def after(confirmed: bool | None) -> None:
            if not confirmed:
                return
            try:
                self.app.vault.delete_capture(cap)
            except (OSError, ValueError) as exc:
                self.notify(f"DELETE FAILED: {name}: {exc}", severity="error", timeout=15)
                self.post_message(VaultItemView.CapturesChanged())
                return
            self.notify(f"Deleted and verified: {name}", title="File removed", timeout=12)
            self.post_message(VaultItemView.CapturesChanged())
        self.app.push_screen(ConfirmModal(
            f"Permanently delete this file?\n[bold]{escape(name)}[/]\n"
            "This cannot be undone."), after)


    @on(Button.Pressed, ".consolidate")
    def _consolidate(self, event: Button.Pressed) -> None:
        event.stop()
        vault = self.app.vault
        count = vault.legacy_hc_file_count()
        if not count:
            return
        unique = vault.legacy_hc_unique_count()

        def after(confirmed: bool | None) -> None:
            if not confirmed:
                return
            migrated, deleted = vault.consolidate_legacy_hc_files()
            self.notify(f"Consolidated {deleted} files into {migrated} AP files.",
                        title="Captures Consolidated")
            self.post_message(VaultItemView.CapturesChanged())

        self.app.push_screen(ConsolidateModal(count, unique), after)

    # ----- dictionary crack (hashcat preferred, aircrack-ng fallback) --------

    def _crack_note(self, text: str, phase: str = "FAILED") -> None:
        """Progress/result line under the actions row (best-effort: pane may close)."""
        if self._status is not None and self._status.ended is None:
            self._status.update(phase, text)
            if self._status.ended is not None and self.app.vault_job_status is self._status:
                self.app.notify(self._status.display(), title="Vault job",
                                severity="error" if phase in {"FAILED", "FAILED TO SAVE"} else "information")
        if not self.is_mounted:
            return
        try:
            self.query_one(".crack-progress", Label).update(text)
        except Exception:
            pass

    @on(Button.Pressed, ".crack")
    def _crack_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        _crack_log.debug("Crack button pressed panel=%#x", id(self))
        if self._crack_worker is not None and self._crack_worker.is_running:
            _crack_log.debug("Crack worker cancel requested by button panel=%#x", id(self))
            self._crack_worker.cancel()
            return
        newest = self._selected()
        if newest is None:
            self._crack_note("Select a capture first.")
            return
        path = Path(newest.path)
        is_packet = path.suffix.lower() in (".cap", ".pcap", ".pcapng")
        records = [] if is_packet else crack_ext.hash_lines(path)
        tools = crack_ext.detect_tools()
        if tools.hashcat and (records or is_packet):
            pending = ("hashcat", tools.hashcat, newest.path, None, newest)
            detail = ("Tool: hashcat · mode 22000 · convert selected capture"
                      if is_packet else
                      f"Tool: hashcat · mode 22000 · {len(records)} hashline(s)")
        else:
            dashed = bssid_to_dashed(newest.bssid)
            pcap = (path if is_packet else crack_ext.sibling_pcap(path, dashed)) if tools.aircrack else None
            if pcap is None:
                if not tools.hashcat and not tools.aircrack:
                    self._crack_note("No cracker installed. Install one, then retry: "
                                     + crack_ext.install_hint())
                elif not records:
                    self._crack_note("No WPA handshake/PMKID hash lines in this file.")
                else:
                    self._crack_note("hashcat not found and no .pcap sibling for aircrack-ng.")
                return
            pending = ("aircrack", tools.aircrack, newest.path, str(pcap), newest)
            detail = f"Tool: aircrack-ng · {pcap.name}"
        default = str(crack_ext.find_wordlist() or "")  # shared dictionary default
        self._crack_pending = pending
        self.app.push_screen(
            CrackModal(Path(newest.path).name, detail, default, can_start=True),
            self._crack_modal_closed)

    def _crack_modal_closed(self, wordlist: Optional[str]) -> None:
        """Wordlist picked (None = cancelled): launch the crack worker."""
        if not wordlist or self._crack_pending is None:
            return
        if (self._crack_worker is not None and
                self._crack_worker.state in (WorkerState.PENDING, WorkerState.RUNNING)):
            _crack_log.debug("Ignoring duplicate Crack modal result panel=%#x", id(self))
            return
        tool, _, _, _, _ = self._crack_pending
        self._crack_tool = tool
        self._status = VaultJobStatus(Path(self._crack_pending[2]).name, tool)
        self.app.vault_job_status = self._status
        self._crack_note(f"Starting {tool}…", "QUEUED")
        self._crack_worker = self.app.run_worker(self._run_crack(wordlist), group="vault-crack")
        _crack_log.debug("Crack worker created panel=%#x worker=%#x group=%s",
                         id(self), id(self._crack_worker), self._crack_worker.group)

    def on_unmount(self) -> None:
        _crack_log.debug("Capture panel unmount panel=%#x worker=%s",
                         id(self), self._crack_worker is not None)

    @on(Worker.StateChanged)
    def _crack_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker is self._crack_worker or event.worker.group == "vault-crack":
            _crack_log.debug("Crack worker %s panel=%#x worker=%#x",
                             event.state.name, id(self), id(event.worker))

    def _crack_tick(self, prog) -> None:
        """One parsed status line from the child: refresh the progress line."""
        if prog.total:
            pct = 100.0 * prog.fraction
            text = f"Cracking ({self._crack_tool}): {prog.tested:,}/{prog.total:,} ({pct:.0f}%)"
        else:
            text = f"Cracking ({self._crack_tool}): {prog.tested:,} tried"
        if prog.speed:
            text += f" · {prog.speed}"
        text += " - press Crack to stop"
        self._crack_note(text, "RUNNING")

    async def _run_crack(self, wordlist: str) -> None:
        """Drive the child to completion, then attach any recovered PSK to VAULT."""
        pending = self._crack_pending
        assert pending is not None
        tool, binary, hash_path, pcap, newest = pending
        hashfile = Path(hash_path)
        kind = "HS" if newest.type == CaptureType.HS else "PMKID"
        psk: Optional[str] = None
        tmp_hashfile: Optional[Path] = None
        workspace = None
        actual_ssid = newest.ssid
        try:
            if tool == "hashcat":
                workspace = TemporaryDirectory(prefix="airscope-crack-")
                work = Path(workspace.name)
                source_path = hashfile
                if hashfile.suffix.lower() in (".cap", ".pcap", ".pcapng"):
                    source_path = work / "converted.hc22000"
                    self._crack_note("Reading packet capture", "CONVERTING")
                    code, _ = await crack_ext.run_capture_output([
                        "hcxpcapngtool", "-o", str(source_path), str(hashfile)
                    ])
                    if code != 0:
                        self._status.exit_code = code
                        self._crack_note(f"Capture conversion failed (exit {code}).")
                        return

                target_ap = "".join(
                    c for c in newest.bssid.lower() if c in "0123456789abcdef"
                )
                if len(target_ap) != 12:
                    self._crack_note("Invalid selected AP BSSID.")
                    return

                matched = []
                observed_ssids = set()
                for line in crack_ext.hash_lines(source_path):
                    parts = line.split("*")
                    if (len(parts) < 6 or parts[1] not in ("01", "02")
                            or parts[3].lower() != target_ap):
                        continue
                    try:
                        on_air = bytes.fromhex(parts[5]).decode("utf-8")
                    except (ValueError, UnicodeDecodeError):
                        continue
                    matched.append(line)
                    observed_ssids.add(on_air)

                records = list(dict.fromkeys(matched))
                if not records:
                    self._crack_note("No WPA records matching the selected AP in this capture.")
                    return
                if len(observed_ssids) != 1:
                    self._crack_note("Ambiguous SSIDs for selected AP; refusing result association.")
                    return
                actual_ssid = observed_ssids.pop()
                tmp_hashfile = work / "target.hc22000"
                tmp_hashfile.write_text("\n".join(records) + "\n", encoding="utf-8")
                pot = work / "target.pot"
                cmd = crack_ext.build_hashcat_cmd(binary, tmp_hashfile, Path(wordlist), pot)
                self._crack_note("Processing", "RUNNING")
                run = await crack_ext.run_crack(
                    cmd, tool, on_progress=self._crack_tick
                )
                self._status.exit_code = run.exit_code
                if run.exit_code not in (0, 1):
                    self._crack_note(f"Hashcat failed (exit {run.exit_code}).")
                    return

                show_code, show = await crack_ext.run_capture_output(
                    crack_ext.build_hashcat_show(binary, tmp_hashfile, pot)
                )
                if show_code not in (0, 1):
                    self._status.exit_code = show_code
                    self._crack_note(f"Hashcat --show failed (exit {show_code}).")
                    return

                psk = crack_ext.parse_hashcat_show(
                    show, records, actual_ssid
                )
                if not psk and run.exit_code == 0:
                    self._crack_note(
                        "Hashcat reports a recovered key, but Airscope "
                        "could not parse its --show output."
                    )
                    return
            else:
                with TemporaryDirectory(prefix="airscope-job-") as directory:
                    keyfile = Path(directory) / ".airscope-aircrack.key"
                    cmd = crack_ext.build_aircrack_cmd(
                        binary, Path(str(pcap)), Path(wordlist), keyfile
                    )
                    self._crack_note("Processing", "RUNNING")
                    run = await crack_ext.run_crack(cmd, tool, on_progress=self._crack_tick)
                    self._status.exit_code = run.exit_code
                    psk = crack_ext.parse_aircrack_key(run.output, keyfile)
            if psk:
                try:
                    saved = self.app.vault.save_cracked_psk(newest.bssid, actual_ssid, psk, tool)
                except OSError:
                    saved = None
                if saved is None:
                    self._crack_note("Vault could not verify the saved credential.", "FAILED TO SAVE")
                    return
                self._crack_note("Saved and verified in Vault.", "RECOVERED")
                self.post_message(VaultItemView.CapturesChanged())
            else:
                self._crack_note("Finished - no match found in wordlist.", "NO MATCH")
        except asyncio.CancelledError:
            self._crack_note("Stopped.", "CANCELLED")
            raise
        except Exception as exc:
            self._crack_note(f"Crack failed: {type(exc).__name__}")
        finally:
            if tmp_hashfile is not None:
                try:
                    tmp_hashfile.unlink(missing_ok=True)
                except OSError:
                    pass
            if workspace is not None:
                workspace.cleanup()
            self._crack_worker = None


class VaultItemView(Vertical):
    """Detail pane for one AP: a title chip and a panel per capture kind present."""

    class CapturesChanged(Message):
        """A capture was deleted or consolidated; the parent should refresh."""

    DEFAULT_CSS = """
    VaultItemView { height: 1fr; padding: 0 1; }
    VaultItemView #vault-item-title { height: auto; margin-bottom: 1; }
    VaultItemView #vault-delete-network { width: auto; margin-bottom: 1; }
    VaultItemView #vault-item-empty { color: $text-muted; }
    """

    # (bssid, ssid, captures); setting it rebuilds the panels for the new AP.
    _state: reactive[tuple] = reactive(("", None, ()), recompose=True)

    EMPTY_VAULT_MSG = "No captured handshakes yet - go to Scanner, pick a network, and capture."
    EMPTY_SELECT_MSG = "Select a network to view its captured handshakes and passwords"

    def load(self, bssid: str, ssid: Optional[str], captures: List[PersistedCapture],
             *, empty_vault: bool = False) -> None:
        """Show one AP's captures (empty bssid clears the pane)."""
        empty_message_changed = not bssid and empty_vault != getattr(self, "_empty_vault", False)
        self._empty_vault = empty_vault
        state = (bssid, ssid, tuple(captures))
        if state != self._state:
            self._state = state
        elif empty_message_changed:
            self.refresh(recompose=True)
        else:
            _crack_log.debug("Vault detail unchanged; preserving mounted capture panels")

    def compose(self) -> ComposeResult:
        bssid, ssid, captures = self._state
        if not bssid:
            msg = self.EMPTY_VAULT_MSG if getattr(self, "_empty_vault", False) else self.EMPTY_SELECT_MSG
            yield Label(msg, id="vault-item-empty")
            return
        yield Label(Text.from_markup(self._title_markup(bssid, ssid)), id="vault-item-title")
        yield Button("Delete All Network Captures", "error", id="vault-delete-network")
        for title, kinds in _PANELS:
            group = [c for c in captures if c.type in kinds]
            if group:
                yield _CapturePanel(title, list(group), show_consolidate=CaptureType.HS in kinds)

    @on(Button.Pressed, "#vault-delete-network")
    def _delete_network_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        bssid, ssid, _ = self._state
        if not bssid:
            return
        files = self.app.vault.network_capture_paths(bssid)
        if not files:
            self.notify("No indexed capture files remain", severity="warning")
            return
        name = ssid or "(hidden network)"
        prompt = (f"Permanently delete [bold]{len(files)} file(s)[/] for network\n"
                  f"[bold]{escape(name)}[/]\nBSSID: {escape(bssid)}\n\n"
                  "This includes all indexed captures for this BSSID and cannot be undone.")
        def after(confirmed: bool | None) -> None:
            if not confirmed:
                return
            try:
                removed = self.app.vault.delete_network_captures(bssid)
            except (OSError, ValueError) as exc:
                self.notify(f"NETWORK DELETE FAILED: {exc}", severity="error", timeout=18)
                self.post_message(VaultItemView.CapturesChanged())
                return
            self.notify(f"Removed {removed} capture file(s) for {name}",
                        title="Network captures deleted", timeout=15)
            self.post_message(VaultItemView.CapturesChanged())
        self.app.push_screen(ConfirmModal(prompt), after)

    def _title_markup(self, bssid: str, ssid: Optional[str]) -> str:
        name = ssid or "‹hidden›"
        return f"[black bold on cyan] {escape(name)} [/]\n[dim]{escape(bssid)}[/dim]"
