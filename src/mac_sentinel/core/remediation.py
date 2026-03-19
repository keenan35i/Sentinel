from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, List


PROTECTED_PREFIXES = ('/System/', '/usr/', '/bin/', '/sbin/', '/Library/Apple/')


class RemediationService:
    def open_related_location(self, finding: Dict) -> List[str]:
        actions = []
        path = finding.get("matched_path", "")
        if path and Path(path).exists():
            target = Path(path)
            if target.is_dir():
                subprocess.Popen(["open", str(target)])
                actions.append(f"Opened folder: {target}")
            else:
                subprocess.Popen(["open", "-R", str(target)])
                actions.append(f"Revealed file in Finder: {target}")
            return actions

        command = (finding.get("process_cmdline", "") or "").strip()
        executable = command.split(" ", 1)[0] if command.startswith("/") else ""
        if executable and Path(executable).exists():
            subprocess.Popen(["open", "-R", executable])
            actions.append(f"Revealed executable in Finder: {executable}")
        else:
            actions.append("No file or folder was attached to this finding.")
        return actions

    def remediate(self, finding: Dict) -> List[str]:
        actions = []

        pid = finding.get("matched_pid")
        if pid:
            try:
                os.kill(int(pid), signal.SIGTERM)
                actions.append(f"Sent SIGTERM to PID {pid}.")
                time.sleep(0.4)
                try:
                    os.kill(int(pid), 0)
                    os.kill(int(pid), signal.SIGKILL)
                    actions.append(f"Sent SIGKILL to PID {pid}.")
                except OSError:
                    pass
            except Exception as exc:
                actions.append(f"Could not stop PID {pid}: {exc}")

        label = finding.get("launchd_label")
        if label:
            try:
                subprocess.run(["launchctl", "remove", label], capture_output=True, text=True, timeout=8)
                actions.append(f"Attempted launchctl remove for {label}.")
            except Exception as exc:
                actions.append(f"Could not remove launchd label {label}: {exc}")

        path = finding.get("matched_path", "")
        if path and Path(path).exists():
            normalized = str(Path(path).resolve())
            if normalized.startswith(PROTECTED_PREFIXES):
                actions.append(f"Skipped destructive action for protected system path: {normalized}")
            else:
                try:
                    trashed = self._move_to_trash(path)
                    actions.append(f"Moved to Trash: {trashed}")
                except Exception as exc:
                    actions.append(f"Could not move to Trash {path}: {exc}")

        if not actions:
            actions.append("Nothing actionable was attached to this finding.")
        return actions

    def _move_to_trash(self, path: str) -> str:
        source = Path(path)
        trash = Path.home() / ".Trash"
        trash.mkdir(parents=True, exist_ok=True)
        destination = trash / source.name
        if destination.exists():
            stem = source.stem
            suffix = source.suffix
            for index in range(1, 1000):
                candidate = trash / f"{stem}_{index}{suffix}"
                if not candidate.exists():
                    destination = candidate
                    break
        shutil.move(str(source), str(destination))
        return str(destination)
