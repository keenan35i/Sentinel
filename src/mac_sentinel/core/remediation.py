from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..config import settings


PROTECTED_PREFIXES = ('/System/', '/usr/', '/bin/', '/sbin/', '/Library/Apple/')


class RemediationService:
    def __init__(self, quarantine_dir: Optional[Path] = None):
        self.quarantine_dir = Path(quarantine_dir or settings.quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def open_related_location(self, finding: Dict) -> List[str]:
        actions = []
        path = finding.get('matched_path', '')
        if path and Path(path).exists():
            target = Path(path)
            if target.is_dir():
                subprocess.Popen(['open', str(target)])
                actions.append(f'Opened folder: {target}')
            else:
                subprocess.Popen(['open', '-R', str(target)])
                actions.append(f'Revealed file in Finder: {target}')
            return actions

        executable = self.extract_executable_path(finding)
        if executable and Path(executable).exists():
            subprocess.Popen(['open', '-R', executable])
            actions.append(f'Revealed executable in Finder: {executable}')
        else:
            actions.append('No file or folder was attached to this finding.')
        return actions

    def remediate(self, finding: Dict) -> List[str]:
        actions = []

        pid = finding.get('matched_pid')
        if pid:
            actions.extend(self.terminate_pid(int(pid)))

        label = finding.get('launchd_label')
        if label:
            actions.extend(self.unload_launchd_label(str(label)))

        path = finding.get('matched_path', '')
        if path and Path(path).exists():
            normalized = str(Path(path).resolve())
            if self.is_protected_path(normalized):
                actions.append(f'Skipped destructive action for protected system path: {normalized}')
            else:
                try:
                    trashed = self._move_to_trash(path)
                    actions.append(f'Moved to Trash: {trashed}')
                except Exception as exc:
                    actions.append(f'Could not move to Trash {path}: {exc}')

        if not actions:
            actions.append('Nothing actionable was attached to this finding.')
        return actions

    def active_respond(self, finding: Dict) -> List[str]:
        actions: List[str] = []
        pid = finding.get('matched_pid')
        if pid:
            actions.extend(self.terminate_pid(int(pid)))

        label = finding.get('launchd_label')
        if label:
            actions.extend(self.unload_launchd_label(str(label)))

        target_path = finding.get('matched_path') or self.extract_executable_path(finding)
        if target_path and Path(target_path).exists():
            try:
                quarantined = self.quarantine_path(target_path)
                actions.append(f'Quarantined locally: {quarantined}')
            except Exception as exc:
                actions.append(f'Could not quarantine {target_path}: {exc}')

        if not actions:
            actions.append('No automatic action was applied.')
        return actions

    def terminate_pid(self, pid: int) -> List[str]:
        actions: List[str] = []
        try:
            os.kill(int(pid), signal.SIGTERM)
            actions.append(f'Sent SIGTERM to PID {pid}.')
            time.sleep(0.35)
            try:
                os.kill(int(pid), 0)
                os.kill(int(pid), signal.SIGKILL)
                actions.append(f'Sent SIGKILL to PID {pid}.')
            except OSError:
                pass
        except Exception as exc:
            actions.append(f'Could not stop PID {pid}: {exc}')
        return actions

    def unload_launchd_label(self, label: str) -> List[str]:
        actions: List[str] = []
        try:
            subprocess.run(['launchctl', 'remove', label], capture_output=True, text=True, timeout=8)
            actions.append(f'Attempted launchctl remove for {label}.')
        except Exception as exc:
            actions.append(f'Could not remove launchd label {label}: {exc}')
        return actions

    def extract_executable_path(self, finding: Dict) -> str:
        command = str(finding.get('process_cmdline', '') or '').strip()
        if not command:
            return ''
        first = command.split(' ', 1)[0].strip().strip('"\'')
        return first if first.startswith('/') else ''

    def quarantine_path(self, path: str) -> str:
        source = Path(path)
        if not source.exists():
            raise FileNotFoundError(path)
        normalized = str(source.resolve())
        if self.is_protected_path(normalized):
            raise PermissionError(f'Refusing to quarantine protected system path: {normalized}')
        destination = self._unique_quarantine_destination(source)
        shutil.move(str(source), str(destination))
        return str(destination)

    def is_protected_path(self, path: str) -> bool:
        normalized = str(Path(path).resolve())
        return normalized.startswith(PROTECTED_PREFIXES)

    def _unique_quarantine_destination(self, source: Path) -> Path:
        stamp = time.strftime('%Y%m%d_%H%M%S')
        destination = self.quarantine_dir / f'{stamp}_{source.name}'
        if not destination.exists():
            return destination
        stem = destination.stem
        suffix = destination.suffix
        for index in range(1, 1000):
            candidate = self.quarantine_dir / f'{stem}_{index}{suffix}'
            if not candidate.exists():
                return candidate
        raise RuntimeError('Could not allocate a unique quarantine path.')

    def _move_to_trash(self, path: str) -> str:
        source = Path(path)
        trash = Path.home() / '.Trash'
        trash.mkdir(parents=True, exist_ok=True)
        destination = trash / source.name
        if destination.exists():
            stem = source.stem
            suffix = source.suffix
            for index in range(1, 1000):
                candidate = trash / f'{stem}_{index}{suffix}'
                if not candidate.exists():
                    destination = candidate
                    break
        shutil.move(str(source), str(destination))
        return str(destination)
