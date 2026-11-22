"""Presentation state for the most recently started Vault job."""
from dataclasses import dataclass, field
from time import monotonic
import logging

log = logging.getLogger("airscope.vault.status")
TERMINAL = {"RECOVERED", "FAILED TO SAVE", "COMPLETED", "NO MATCH", "FAILED", "CANCELLED"}


@dataclass
class VaultJobStatus:
    filename: str
    tool: str
    phase: str = "QUEUED"
    detail: str = ""
    started: float = field(default_factory=monotonic)
    ended: float | None = None
    exit_code: int | None = None

    def update(self, phase, detail=""):
        if self.ended is not None:
            return
        changed = self.phase != phase
        self.phase, self.detail = phase, detail
        if phase in TERMINAL:
            self.ended = monotonic()
        if changed or phase == "QUEUED":
            log.info("Vault job %s tool=%s file=%r exit=%s %s",
                     phase, self.tool, self.filename, self.exit_code,
                     detail if phase in {"FAILED", "FAILED TO SAVE"} else "")

    def display(self):
        seconds = int((self.ended or monotonic()) - self.started)
        return (f"{self.phase}   {self.tool}   {seconds // 60}:{seconds % 60:02d} elapsed\n"
                f"{self.filename}   {self.detail}")
