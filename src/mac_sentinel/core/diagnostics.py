from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from ..config import settings


class DiagnosticsService:
    def __init__(self, collector=None, intelligence=None):
        self.collector = collector
        self.intelligence = intelligence
        self._command_names = ["ps", "launchctl", "lsof", "open", "osascript", "codesign", "spctl", "xattr", "security", "profiles"]
        self._permission_paths = [
            ("Mail", "~/Library/Mail"),
            ("Messages", "~/Library/Messages"),
            ("Safari", "~/Library/Safari"),
            ("User LaunchAgents", "~/Library/LaunchAgents"),
            ("System LaunchDaemons", "/Library/LaunchDaemons"),
            ("TCC Database", "~/Library/Application Support/com.apple.TCC/TCC.db"),
        ]

    def get_report(self) -> Dict:
        system_name = platform.system()
        is_macos = system_name == "Darwin"
        commands = {}
        for name in self._command_names:
            path = shutil.which(name)
            commands[name] = {
                "available": bool(path),
                "path": path or "",
            }

        permission_checks: List[Dict] = []
        for label, raw_path in self._permission_paths:
            expanded = Path(os.path.expanduser(raw_path))
            exists = expanded.exists()
            readable = os.access(expanded, os.R_OK) if exists else False
            permission_checks.append({
                "name": label,
                "path": str(expanded),
                "exists": exists,
                "readable": readable,
            })

        recommendations = [
            "Run the app natively on macOS rather than inside Docker when you want real host visibility.",
            "Grant Full Disk Access to the packaged Mac Sentinel app if protected folders are not readable. During development, grant access to the terminal app only if you are launching from the command line.",
            "Use the diagnostics panel to confirm commands like ps, launchctl, lsof, codesign, and xattr are available before trusting a zero-findings scan.",
            "Imported intelligence artifacts, STIX indicator files, and Apple threat-notification files are analyzed locally only. Mac Sentinel does not upload them to third-party services.",
        ]
        notes = [
            "macOS does not let a normal app silently self-grant Full Disk Access. Mac Sentinel can open the settings pane, but you still need to approve access manually for the specific app bundle you use.",
            "Zero findings does not always mean zero activity. It can also mean the current ruleset did not match, the machine is clean, or permissions were limited.",
        ]
        advanced_checks = self.intelligence.diagnostics_summary() if self.intelligence else {}
        return {
            "app_name": settings.app_name,
            "platform": platform.platform(),
            "is_macos": is_macos,
            "python_executable": sys.executable,
            "python_version": sys.version.split()[0],
            "commands": commands,
            "permission_checks": permission_checks,
            "recommendations": recommendations,
            "notes": notes,
            "advanced_checks": advanced_checks,
        }

    def open_full_disk_access_settings(self) -> List[str]:
        if platform.system() != "Darwin":
            return ["Full Disk Access shortcut is only available on macOS."]

        actions: List[str] = []
        commands = [
            ["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"],
            ["open", "/System/Library/PreferencePanes/Security.prefPane"],
        ]
        for command in commands:
            try:
                subprocess.Popen(command)
                actions.append(f"Opened: {' '.join(command)}")
                break
            except Exception:
                continue
        if not actions:
            actions.append("Could not open Full Disk Access settings automatically. Open System Settings > Privacy & Security > Full Disk Access manually.")
        return actions
