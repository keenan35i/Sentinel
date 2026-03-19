from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from ..models import Finding

TEXT_EXTENSIONS = {
    '.txt', '.log', '.json', '.stix2', '.xml', '.plist', '.md', '.html', '.htm', '.eml',
    '.ips', '.crash', '.conf', '.cfg', '.yaml', '.yml', '.sql', '.csv', '.tsv', '.js', '.py'
}

BACKUP_MARKERS = {'Manifest.db', 'Info.plist', 'Status.plist'}
SYSDIAG_MARKERS = {'Shutdown.log'}
APPLE_NOTIFICATION_PATTERNS = (
    re.compile(r'apple\s+threat\s+notification', re.I),
    re.compile(r'mercenary\s+spyware', re.I),
    re.compile(r'targeted\s+by\s+mercenary\s+spyware', re.I),
)

SYSDIAG_CONTEXT_PATTERNS = (
    re.compile(r'MessagesBlastDoorService', re.I),
    re.compile(r'imagent', re.I),
    re.compile(r'identityservicesd', re.I),
)

STIX_LITERAL_PATTERN = re.compile(r"'([^']{3,200})'")


@dataclass
class StixIndicatorSet:
    source_path: str
    name: str
    literals: List[str]
    raw_indicator_count: int


class LocalArtifactIntelligenceService:
    """Analyze user-selected local artifacts without sending data off-machine."""

    def __init__(self, state_store):
        self.state_store = state_store
        self._stix_sets: List[StixIndicatorSet] = []

    def import_paths(self, paths: Sequence[str]) -> Dict:
        cleaned = [os.path.expanduser(path) for path in paths if path]
        findings: List[Finding] = []
        artifacts: List[Dict] = []
        notes: List[str] = []

        self.state_store.append_intelligence_log(f'Starting local artifact intake for {len(cleaned)} path(s).', phase='start')

        for raw_path in cleaned:
            path = Path(raw_path)
            if not path.exists():
                self.state_store.append_intelligence_log(f'Skipped missing artifact path: {raw_path}', level='warning', phase='skip')
                continue

            kind = self._detect_kind(path)
            artifact = {
                'path': str(path),
                'kind': kind,
                'name': path.name or str(path),
                'size_bytes': path.stat().st_size if path.is_file() else 0,
            }
            artifacts.append(artifact)
            self.state_store.append_intelligence_log(f'Analyzing {kind} artifact: {path}', phase='analyze')

            if kind == 'stix':
                stix_set = self._load_stix_file(path)
                if stix_set:
                    self._stix_sets.append(stix_set)
                    notes.append(f'Loaded {stix_set.raw_indicator_count} STIX indicator(s) from {path.name}.')
                    self.state_store.append_intelligence_log(
                        f'Loaded {stix_set.raw_indicator_count} STIX indicator(s) from {path.name}.',
                        phase='stix',
                    )
                continue

            findings.extend(self._analyze_path(path, kind))

        findings.extend(self._correlate_intel_findings(findings))
        deduped = self._dedupe_findings(findings)
        summary = self.summary(artifacts=artifacts, findings=deduped)
        self.state_store.set_intelligence_snapshot(artifacts, [item.to_dict() for item in deduped], summary)
        return {
            'ok': True,
            'imported_count': len(artifacts),
            'finding_count': len(deduped),
            'artifacts': artifacts,
            'findings': [item.to_dict() for item in deduped],
            'notes': notes,
        }

    def summary(self, artifacts: Sequence[Dict] | None = None, findings: Sequence[Finding] | None = None) -> Dict:
        artifacts = list(artifacts) if artifacts is not None else self.state_store.intelligence_artifacts()
        findings_payload = [item.to_dict() if isinstance(item, Finding) else dict(item) for item in (findings if findings is not None else self.state_store.intelligence_findings())]
        by_kind: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for item in artifacts:
            by_kind[item.get('kind', 'unknown')] = by_kind.get(item.get('kind', 'unknown'), 0) + 1
        for item in findings_payload:
            by_severity[item.get('threat_level', 'unknown')] = by_severity.get(item.get('threat_level', 'unknown'), 0) + 1
        return {
            'artifact_count': len(artifacts),
            'finding_count': len(findings_payload),
            'artifacts_by_kind': by_kind,
            'findings_by_severity': by_severity,
            'loaded_stix_sets': len(self._stix_sets),
            'local_only': True,
        }

    def clear(self) -> None:
        self._stix_sets = []
        self.state_store.clear_intelligence()

    def _analyze_path(self, path: Path, kind: str) -> List[Finding]:
        findings: List[Finding] = []
        if path.is_file():
            findings.extend(self._apple_notification_findings(path))
            findings.extend(self._stix_match_findings(path, root_label=kind))
            if path.name == 'Shutdown.log':
                findings.extend(self._sysdiagnose_shutdown_findings(path))
            return findings

        if kind == 'backup':
            findings.extend(self._backup_presence_findings(path))
        if kind == 'sysdiagnose':
            findings.extend(self._sysdiagnose_dir_findings(path))

        findings.extend(self._directory_stix_match_findings(path, kind))
        return findings

    def _detect_kind(self, path: Path) -> str:
        if path.is_file() and path.suffix.lower() in {'.stix2', '.stix', '.json'}:
            try:
                payload = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                payload = None
            if isinstance(payload, dict) and payload.get('type') == 'bundle':
                return 'stix'
        if path.is_file() and path.suffix.lower() in {'.txt', '.html', '.htm', '.eml'}:
            text = self._safe_read_text(path)
            if self._looks_like_apple_notification(text):
                return 'apple-notification'
        if path.is_dir():
            entries = {child.name for child in path.iterdir()} if path.exists() else set()
            if BACKUP_MARKERS.issubset(entries):
                return 'backup'
            if self._directory_contains(path, SYSDIAG_MARKERS):
                return 'sysdiagnose'
            return 'directory'
        if path.name == 'Shutdown.log':
            return 'sysdiagnose-log'
        return 'file'

    def _load_stix_file(self, path: Path) -> StixIndicatorSet | None:
        try:
            payload = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            return None
        objects = payload.get('objects', []) if isinstance(payload, dict) else []
        literals: Set[str] = set()
        indicator_count = 0
        for obj in objects:
            if not isinstance(obj, dict) or obj.get('type') != 'indicator':
                continue
            indicator_count += 1
            pattern = str(obj.get('pattern', ''))
            for literal in STIX_LITERAL_PATTERN.findall(pattern):
                cleaned = literal.strip()
                if len(cleaned) >= 4:
                    literals.add(cleaned)
        return StixIndicatorSet(
            source_path=str(path),
            name=path.name,
            literals=sorted(literals),
            raw_indicator_count=indicator_count,
        )

    def _apple_notification_findings(self, path: Path) -> List[Finding]:
        text = self._safe_read_text(path)
        if not self._looks_like_apple_notification(text):
            return []
        return [Finding(
            rule_id='imported_apple_threat_notification',
            title='Imported Apple threat notification references mercenary spyware',
            family='High-Confidence External Signal',
            threat_level='high',
            author_or_actor='Apple',
            description=(
                'A locally imported artifact appears to contain an Apple threat notification about mercenary spyware targeting. '
                'This should be treated as a high-confidence external signal and investigated alongside host, backup, or sysdiagnose evidence.'
            ),
            evidence_type='artifact-text',
            source='intel',
            matched_path=str(path),
            matched_regex='Apple threat notification / mercenary spyware',
            confidence='high',
        )]

    def _backup_presence_findings(self, path: Path) -> List[Finding]:
        return [Finding(
            rule_id='ios_backup_imported',
            title='Imported iPhone or iPad backup for local forensic review',
            family='Forensic Intake',
            threat_level='low',
            author_or_actor='Mac Sentinel local intake',
            description='A local mobile backup was imported for offline review. This is context only until indicator or artifact matches are found.',
            evidence_type='artifact-container',
            source='intel',
            matched_path=str(path),
            matched_regex='Manifest.db / Info.plist / Status.plist',
            confidence='context',
        )]

    def _sysdiagnose_dir_findings(self, path: Path) -> List[Finding]:
        findings = [Finding(
            rule_id='ios_sysdiagnose_imported',
            title='Imported sysdiagnose-style directory for local forensic review',
            family='Forensic Intake',
            threat_level='low',
            author_or_actor='Mac Sentinel local intake',
            description='A local sysdiagnose-style artifact directory was imported for offline review. This is context only until stronger matches are found.',
            evidence_type='artifact-container',
            source='intel',
            matched_path=str(path),
            matched_regex='Shutdown.log present',
            confidence='context',
        )]
        shutdown = self._find_named_file(path, 'Shutdown.log')
        if shutdown:
            findings.extend(self._sysdiagnose_shutdown_findings(shutdown))
        return findings

    def _sysdiagnose_shutdown_findings(self, path: Path) -> List[Finding]:
        text = self._safe_read_text(path, max_bytes=2 * 1024 * 1024)
        hits = [pattern.pattern for pattern in SYSDIAG_CONTEXT_PATTERNS if pattern.search(text)]
        if not hits:
            return []
        return [Finding(
            rule_id='sysdiagnose_shutdown_exploit_surface_context',
            title='Imported sysdiagnose log references Messages / IDS exploit-surface processes',
            family='Exploit Surface Context',
            threat_level='low',
            author_or_actor='Forensic context only',
            description=(
                'The imported Shutdown.log contains references to Messages or IDS-related processes such as MessagesBlastDoorService or imagent. '
                'This is not proof of compromise by itself, but it is useful context when paired with threat notifications or IOC matches.'
            ),
            evidence_type='artifact-text',
            source='intel',
            matched_path=str(path),
            matched_regex='; '.join(hits),
            confidence='context',
        )]

    def _directory_stix_match_findings(self, root: Path, kind: str) -> List[Finding]:
        findings: List[Finding] = []
        for candidate in self._iter_text_files(root):
            findings.extend(self._stix_match_findings(candidate, root_label=kind))
            if len(findings) >= 50:
                break
        return findings

    def _stix_match_findings(self, path: Path, root_label: str) -> List[Finding]:
        findings: List[Finding] = []
        if not self._stix_sets:
            return findings
        text = self._safe_read_text(path)
        if not text:
            return findings
        lowered_text = text.lower()
        lowered_path = str(path).lower()
        for stix_set in self._stix_sets:
            matched_literals = []
            for literal in stix_set.literals:
                lowered_literal = literal.lower()
                if lowered_literal in lowered_text or lowered_literal in lowered_path:
                    matched_literals.append(literal)
                if len(matched_literals) >= 3:
                    break
            if matched_literals:
                severity = 'high' if root_label in {'backup', 'sysdiagnose', 'sysdiagnose-log'} else 'mid'
                findings.append(Finding(
                    rule_id='stix_indicator_match_in_imported_artifact',
                    title='Imported artifact matched a locally loaded STIX indicator',
                    family='Indicator Match',
                    threat_level=severity,
                    author_or_actor=f'STIX source: {stix_set.name}',
                    description=(
                        f'The imported artifact {path} matched one or more literals extracted from the STIX indicator set {stix_set.name}. '
                        'This is a stronger signal than broad host keyword scans because it is scoped to user-selected forensic artifacts and explicit indicator feeds.'
                    ),
                    evidence_type='stix-match',
                    source='intel',
                    matched_path=str(path),
                    matched_regex=', '.join(matched_literals),
                    confidence='high' if severity == 'high' else 'signal',
                ))
        return findings

    def _correlate_intel_findings(self, findings: Sequence[Finding]) -> List[Finding]:
        has_apple_notification = any(item.rule_id == 'imported_apple_threat_notification' for item in findings)
        has_stix = any(item.rule_id == 'stix_indicator_match_in_imported_artifact' for item in findings)
        has_sysdiagnose_context = any(item.rule_id == 'sysdiagnose_shutdown_exploit_surface_context' for item in findings)
        correlated: List[Finding] = []
        if has_apple_notification and has_stix:
            correlated.append(Finding(
                rule_id='correlated_apple_notification_plus_stix',
                title='Apple threat notification and STIX match observed together',
                family='Correlation / High-Confidence Review Priority',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description='An imported Apple threat notification and a locally matched STIX indicator were observed together. This combination should be treated as a high-priority investigation case.',
                evidence_type='correlation',
                source='intel',
                matched_regex='apple notification + stix',
                confidence='high',
            ))
        if has_sysdiagnose_context and has_stix:
            correlated.append(Finding(
                rule_id='correlated_sysdiagnose_plus_stix',
                title='Sysdiagnose context and STIX match observed together',
                family='Correlation / Elevated Review Priority',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description='Imported sysdiagnose context and a local STIX match were observed together. This is stronger than either signal alone and deserves manual review.',
                evidence_type='correlation',
                source='intel',
                matched_regex='sysdiagnose + stix',
                confidence='correlated',
            ))
        return correlated

    def _dedupe_findings(self, findings: Sequence[Finding]) -> List[Finding]:
        seen: Set[Tuple[str, str, str]] = set()
        unique: List[Finding] = []
        for item in findings:
            key = (item.rule_id, item.matched_path, item.matched_regex)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    def _safe_read_text(self, path: Path, max_bytes: int = 1024 * 1024) -> str:
        try:
            if path.stat().st_size > max_bytes:
                return ''
            return path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return ''

    def _looks_like_apple_notification(self, text: str) -> bool:
        return all(pattern.search(text or '') for pattern in APPLE_NOTIFICATION_PATTERNS[:2]) or APPLE_NOTIFICATION_PATTERNS[2].search(text or '') is not None

    def _directory_contains(self, root: Path, names: Iterable[str]) -> bool:
        wanted = set(names)
        try:
            for current_root, _, files in os.walk(root):
                if wanted.intersection(files):
                    return True
        except Exception:
            return False
        return False

    def _find_named_file(self, root: Path, name: str) -> Path | None:
        try:
            for current_root, _, files in os.walk(root):
                if name in files:
                    return Path(current_root) / name
        except Exception:
            return None
        return None

    def _iter_text_files(self, root: Path) -> Iterable[Path]:
        try:
            for current_root, dirs, files in os.walk(root):
                dirs[:] = [item for item in dirs if item not in {'node_modules', '.git', '.venv', '__pycache__'}]
                for name in files:
                    candidate = Path(current_root) / name
                    if candidate.suffix.lower() in TEXT_EXTENSIONS or candidate.name in BACKUP_MARKERS or candidate.name in SYSDIAG_MARKERS:
                        yield candidate
        except Exception:
            return
