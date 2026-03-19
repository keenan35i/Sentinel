from __future__ import annotations

import json
import os
import tempfile
import uuid
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config import settings
from ..models import Finding
from .local_storage import LocalStorage

PROFILE_PAYLOAD_LABELS = {
    'com.apple.TCC.configuration-profile-policy': 'PPPC / Privacy grants',
    'com.apple.security.root': 'Trusted root certificate',
    'com.apple.vpn.managed': 'Managed VPN',
    'com.apple.dnsProxy.managed': 'DNS proxy',
    'com.apple.webcontent-filter': 'Web content filter',
    'com.apple.system-extension-policy': 'System extension policy',
    'com.apple.extensiblesso': 'Extensible SSO',
    'com.apple.webClip.managed': 'Managed web clip',
    'com.apple.servicemanagement': 'Service management',
    'com.apple.syspolicy.kernel-extension-policy': 'Kernel extension policy',
}

PROFILE_SENSITIVE_TERMS = (
    'Accessibility',
    'AppleEvents',
    'SystemPolicyAllFiles',
    'System Policy All Files',
    'DesktopFolder',
    'DocumentsFolder',
    'DownloadsFolder',
    'ScreenCapture',
    'ListenEvent',
    'PostEvent',
    'Microphone',
    'Camera',
)

HIGH_RISK_TCC_SERVICES = {
    'kTCCServiceAccessibility': 'Accessibility',
    'kTCCServiceAppleEvents': 'AppleEvents',
    'kTCCServiceSystemPolicyAllFiles': 'Full Disk Access',
    'kTCCServiceScreenCapture': 'Screen Recording',
    'kTCCServiceListenEvent': 'Input Monitoring',
    'kTCCServicePostEvent': 'Synthetic Input',
    'kTCCServiceSystemPolicyDesktopFolder': 'Desktop Folder',
    'kTCCServiceSystemPolicyDocumentsFolder': 'Documents Folder',
    'kTCCServiceSystemPolicyDownloadsFolder': 'Downloads Folder',
}

RECENT_SPYWARE_CONTEXT_PROCESSES = {
    'messagesblastdoorservice': 3,
    'imagent': 3,
    'identityservicesd': 4,
}

SUSPICIOUS_CLIENT_MARKERS = (
    '/Users/',
    '/private/tmp/',
    '/tmp/',
    '/var/folders/',
    '/Library/Application Support/',
    '/Caches/',
    '/Downloads/',
    '/Desktop/',
)

BENIGN_CLIENT_PREFIXES = (
    '/System/',
    '/Library/Apple/',
    '/usr/bin/',
    '/usr/sbin/',
    '/bin/',
    '/sbin/',
    '/Applications/',
    '/Library/Application Support/Google/',
)

BROWSER_HIGH_RISK_PERMISSIONS = {
    'nativeMessaging',
    'management',
    'debugger',
    'webRequestBlocking',
    'enterprise.deviceAttributes',
    'enterprise.platformKeys',
}

BROWSER_HIGH_RISK_HOST_PATTERNS = (
    '<all_urls>',
    'http://*/*',
    'https://*/*',
)

PERSISTENCE_USER_WRITABLE_MARKERS = (
    '/Users/',
    '/private/tmp/',
    '/tmp/',
    '/var/folders/',
    '/Library/Application Support/',
    '/Downloads/',
    '/Desktop/',
)


class HostIntelligenceService:
    """Collect conservative higher-signal host checks and local forensic context.

    This service intentionally prefers structured host state over broad keyword hits. Most
    findings remain contextual unless multiple signals corroborate each other.
    """

    def __init__(self, collector, storage: Optional[LocalStorage] = None):
        self.collector = collector
        if storage is None:
            if os.getenv('PYTEST_CURRENT_TEST'):
                test_db = Path(tempfile.mkdtemp(prefix='mac_sentinel_intel_')) / f'{uuid.uuid4().hex}.db'
                storage = LocalStorage(test_db)
            else:
                storage = LocalStorage(settings.local_db_path)
        self.storage = storage
        self._last_diff_summary: Dict = {}

    def collect_findings(self, source: str = 'scan') -> List[Finding]:
        profile_findings = self._profile_findings(source)
        tcc_findings = self._tcc_findings(source)
        crash_findings = self._crash_context_findings(source)
        download_findings = self._downloaded_candidate_findings(source)
        trust_findings = self._trust_settings_findings(source)
        persistence_findings = self._persistence_findings(source)
        browser_findings = self._browser_extension_findings(source)
        provenance_findings = self._bundle_provenance_findings(source)
        baseline_findings = self._baseline_diff_findings(source)

        findings: List[Finding] = []
        findings.extend(profile_findings)
        findings.extend(tcc_findings)
        findings.extend(crash_findings)
        findings.extend(download_findings)
        findings.extend(trust_findings)
        findings.extend(persistence_findings)
        findings.extend(browser_findings)
        findings.extend(provenance_findings)
        findings.extend(baseline_findings)
        findings.extend(self._correlated_findings(
            source=source,
            profile_findings=profile_findings,
            tcc_findings=tcc_findings,
            download_findings=download_findings,
            trust_findings=trust_findings,
            persistence_findings=persistence_findings,
            provenance_findings=provenance_findings,
        ))
        return findings

    def diagnostics_summary(self) -> Dict:
        profiles = self._collect_installed_profiles()
        profile_risk = []
        for item in profiles:
            risky_payloads = self._profile_risky_payloads(item)
            if risky_payloads:
                profile_risk.append({
                    'identifier': item.get('identifier', ''),
                    'display_name': item.get('display_name', ''),
                    'payloads': risky_payloads,
                    'removal_disallowed': bool(item.get('removal_disallowed', False)),
                })

        tcc_entries = self._collect_tcc_entries()
        suspicious_tcc = []
        readable_db_paths = sorted({entry.get('db_path', '') for entry in tcc_entries if entry.get('db_path')})
        for entry in tcc_entries:
            if self._is_suspicious_tcc_entry(entry):
                suspicious_tcc.append({
                    'service': HIGH_RISK_TCC_SERVICES.get(entry.get('service', ''), entry.get('service', 'Unknown')),
                    'client': entry.get('client', ''),
                    'db_path': entry.get('db_path', ''),
                })

        crash_reports = self._collect_diagnostic_reports(days=7)
        crash_counter = Counter(report.get('process', '') for report in crash_reports if report.get('process'))

        downloaded_candidates = self._collect_downloaded_candidates(days=30)
        suspicious_downloads = []
        for candidate in downloaded_candidates:
            metadata = self._collect_file_security_metadata(candidate.get('path', ''))
            if self._is_suspicious_download_candidate(candidate, metadata):
                suspicious_downloads.append({
                    'path': candidate.get('path', ''),
                    'origin_url': metadata.get('origin_url', ''),
                    'has_quarantine': metadata.get('has_quarantine', False),
                    'team_id': metadata.get('team_id', ''),
                    'accepted': metadata.get('spctl_accepted', False),
                    'notarized': metadata.get('notarized', False),
                })

        trust_settings = self._collect_user_trust_settings()
        persistence = self._collect_persistence_candidates()
        browser_extensions = self._collect_browser_extensions()
        provenance_issues = self._collect_provenance_issues()

        return {
            'profile_inventory': {
                'installed_profiles': len(profiles),
                'profiles_with_sensitive_payloads': len(profile_risk),
                'examples': profile_risk[:5],
            },
            'tcc_audit': {
                'readable_databases': readable_db_paths,
                'suspicious_grants': len(suspicious_tcc),
                'examples': suspicious_tcc[:5],
            },
            'diagnostic_crashes': {
                'recent_target_process_counts': dict(sorted(crash_counter.items())),
                'recent_report_count': len(crash_reports),
            },
            'download_security': {
                'recent_candidates': len(downloaded_candidates),
                'suspicious_candidates': len(suspicious_downloads),
                'examples': suspicious_downloads[:5],
            },
            'trust_settings': {
                'admin_has_custom_settings': bool(trust_settings.get('admin_has_custom_settings', False)),
                'user_has_custom_settings': bool(trust_settings.get('user_has_custom_settings', False)),
            },
            'persistence_review': {
                'candidate_count': len(persistence),
                'examples': persistence[:5],
            },
            'browser_extension_review': {
                'extension_count': len(browser_extensions),
                'high_risk_examples': [item for item in browser_extensions if self._is_high_risk_extension(item)][:5],
            },
            'provenance_review': {
                'issue_count': len(provenance_issues),
                'examples': provenance_issues[:5],
            },
            'baseline_diffs': self._last_diff_summary,
            'notes': [
                'Mercenary spyware-style detections are intentionally conservative. Installed profiles, TCC grants, trust changes, persistence, browser extension abuse, and downloaded unsigned apps are treated as context unless corroborated by multiple signals.',
                'For higher-confidence mercenary spyware triage, import Apple threat notifications or analyze iPhone backups and sysdiagnose artifacts with local IOC workflows such as STIX-compatible MVT analysis.',
            ],
        }

    def _profile_findings(self, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for profile in self._collect_installed_profiles():
            risky_payloads = self._profile_risky_payloads(profile)
            if not risky_payloads:
                continue

            severity = 'low'
            reasons = []
            payload_types = set(profile.get('payload_types', []))
            payload_text = profile.get('payload_text', '')
            matched_terms = [term for term in PROFILE_SENSITIVE_TERMS if term.lower() in payload_text.lower()]
            if 'com.apple.TCC.configuration-profile-policy' in payload_types and matched_terms:
                severity = 'mid'
                reasons.append(f'PPPC grants: {", ".join(sorted(set(matched_terms)))}')
            if profile.get('removal_disallowed'):
                severity = 'mid'
                reasons.append('profile removal is disallowed')
            if len(risky_payloads) >= 2:
                severity = 'mid'
                reasons.append('multiple high-control payload types present')

            identifier = profile.get('identifier') or 'unknown-profile'
            name = profile.get('display_name') or identifier
            organization = profile.get('organization') or 'Unknown organization'
            payload_summary = ', '.join(risky_payloads)
            description = (
                f'Installed configuration profile {name!r} from {organization} includes sensitive control payloads: '
                f'{payload_summary}. This is not proof of spyware by itself because enterprise MDM uses the same '
                'payload families, but it deserves review when paired with unusual TCC grants, trust changes, or threat notifications.'
            )
            if reasons:
                description += ' Context: ' + '; '.join(reasons) + '.'

            findings.append(Finding(
                rule_id='installed_profile_sensitive_payloads',
                title='Installed configuration profile grants sensitive device control',
                family='Profile Abuse / Device Management',
                threat_level=severity,
                author_or_actor='Could be enterprise admin activity, could be attack prep',
                description=description,
                evidence_type='profile',
                source=source,
                matched_path=f'profile://{identifier}',
                matched_regex='; '.join(risky_payloads),
                confidence='context',
            ))
        return findings

    def _profile_risky_payloads(self, profile: Dict) -> List[str]:
        risky = []
        for payload_type in profile.get('payload_types', []):
            label = PROFILE_PAYLOAD_LABELS.get(payload_type)
            if label:
                risky.append(label)
        return sorted(set(risky))

    def _tcc_findings(self, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for entry in self._collect_tcc_entries():
            if not self._is_suspicious_tcc_entry(entry):
                continue

            service = HIGH_RISK_TCC_SERVICES.get(entry.get('service', ''), entry.get('service', 'Unknown TCC service'))
            client = entry.get('client', '')
            title = f'Suspicious TCC grant for {service}'
            description = (
                f'TCC database {entry.get("db_path", "") or "(unknown)"} grants {service} to a user-writable or staging-path client: {client}. '
                'This is a stronger signal than keyword hits because it reflects an actual privacy grant. '
                'Review whether the binary is expected on this Mac and whether the grant was user-approved.'
            )
            severity = 'high' if entry.get('service') in {
                'kTCCServiceAccessibility', 'kTCCServiceSystemPolicyAllFiles', 'kTCCServiceListenEvent', 'kTCCServicePostEvent'
            } else 'mid'
            findings.append(Finding(
                rule_id='tcc_suspicious_user_writable_grant',
                title=title,
                family='Privacy Bypass / Post-Exploitation',
                threat_level=severity,
                author_or_actor='Generic post-exploitation behavior',
                description=description,
                evidence_type='tcc',
                source=source,
                matched_path=client,
                matched_regex=entry.get('service', ''),
                confidence='signal',
            ))
        return findings

    def _is_suspicious_tcc_entry(self, entry: Dict) -> bool:
        if not entry.get('allowed'):
            return False
        service = entry.get('service', '')
        if service not in HIGH_RISK_TCC_SERVICES:
            return False
        client = entry.get('client', '')
        if client and str(client).startswith('/'):
            return self._is_suspicious_client_path(str(client))
        return False

    def _is_suspicious_client_path(self, client: str) -> bool:
        normalized = os.path.normpath(client)
        if normalized.startswith(BENIGN_CLIENT_PREFIXES):
            return False
        return any(marker in normalized for marker in SUSPICIOUS_CLIENT_MARKERS)

    def _crash_context_findings(self, source: str) -> List[Finding]:
        reports = self._collect_diagnostic_reports(days=7)
        counts = Counter(report.get('process', '').lower() for report in reports if report.get('process'))
        findings: List[Finding] = []
        for process_name, threshold in RECENT_SPYWARE_CONTEXT_PROCESSES.items():
            count = counts.get(process_name, 0)
            if count < threshold:
                continue
            findings.append(Finding(
                rule_id='recent_messaging_crash_burst_context',
                title='Recent crash burst in Messages / IDS attack-surface process',
                family='Exploit Surface Context',
                threat_level='low',
                author_or_actor='Forensic context only',
                description=(
                    f'Recent diagnostic reports show {count} crash report(s) for {process_name} in the last 7 days. '
                    'This can happen for benign reasons and is not proof of compromise by itself, but it can be useful forensic context '
                    'when paired with Apple threat notifications, suspicious profile changes, or iPhone backup/sysdiagnose artifacts.'
                ),
                evidence_type='diagnostic-report',
                source=source,
                matched_path=', '.join(report.get('path', '') for report in reports if report.get('process', '').lower() == process_name)[:1200],
                matched_regex=process_name,
                confidence='context',
            ))
        return findings

    def _downloaded_candidate_findings(self, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for candidate in self._collect_downloaded_candidates(days=30):
            metadata = self._collect_file_security_metadata(candidate.get('path', ''))
            if not self._is_suspicious_download_candidate(candidate, metadata):
                continue
            findings.append(Finding(
                rule_id='quarantined_unsigned_downloaded_executable',
                title='Recently downloaded executable lacks normal trust signals',
                family='Delivery / Initial Access',
                threat_level='low',
                author_or_actor='Could be a developer build, could be a malicious lure',
                description=(
                    f"Downloaded item {candidate.get('path', '')} is executable or app-like, still carries quarantine metadata, and lacks a normal accepted signature assessment. "
                    'This is not a spyware verdict, but it is worth reviewing if the app was not intentionally downloaded or if it later appears in persistence or TCC findings.'
                ),
                evidence_type='security-metadata',
                source=source,
                matched_path=candidate.get('path', ''),
                matched_regex=metadata.get('spctl_assessment') or metadata.get('signature_type') or metadata.get('quarantine', ''),
                confidence='context',
            ))
        return findings

    def _is_suspicious_download_candidate(self, candidate: Dict, metadata: Dict) -> bool:
        path = candidate.get('path', '')
        lowered = path.lower()
        if '/applications/' in lowered:
            return False
        if not metadata.get('has_quarantine'):
            return False
        if metadata.get('spctl_accepted') and metadata.get('notarized'):
            return False
        signature_type = (metadata.get('signature_type') or '').lower()
        authority = (metadata.get('codesign_authority') or '').lower()
        return signature_type in {'unsigned', 'adhoc'} or not authority or not metadata.get('notarized')

    def _trust_settings_findings(self, source: str) -> List[Finding]:
        trust = self._collect_user_trust_settings()
        findings: List[Finding] = []
        if trust.get('admin_has_custom_settings') or trust.get('user_has_custom_settings'):
            findings.append(Finding(
                rule_id='custom_trust_settings_present',
                title='Custom certificate trust settings are present on this Mac',
                family='Trust Store Abuse / TLS Interception Context',
                threat_level='low',
                author_or_actor='Could be enterprise administration, could be interception setup',
                description=(
                    'The local trust settings store contains custom entries. This can be legitimate in enterprise environments, '
                    'but it is worth correlating with installed profiles, proxy/VPN payloads, or suspicious certificate installation commands.'
                ),
                evidence_type='trust-settings',
                source=source,
                matched_regex='custom trust settings',
                confidence='context',
            ))
        return findings

    def _persistence_findings(self, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for item in self._collect_persistence_candidates():
            path_value = item.get('path', '')
            if not self._is_user_writable_persistence_path(path_value):
                continue
            title = 'Persistence entry points to a user-writable or staging path'
            description = (
                f"Persistence item {item.get('name') or item.get('identifier') or 'unknown'} points to {path_value}. "
                'Persistence from user-writable locations is not automatically malicious, but it raises review priority because staged malware commonly lands there.'
            )
            findings.append(Finding(
                rule_id='user_writable_persistence_target',
                title=title,
                family='Persistence',
                threat_level='mid',
                author_or_actor='Generic persistence pattern',
                description=description,
                evidence_type='persistence',
                source=source,
                matched_path=path_value,
                matched_regex=item.get('type', '') or item.get('identifier', ''),
                confidence='signal',
            ))
        return findings

    def _browser_extension_findings(self, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for extension in self._collect_browser_extensions():
            if not self._is_high_risk_extension(extension):
                continue
            evidence = []
            if extension.get('has_native_messaging'):
                evidence.append('nativeMessaging')
            if extension.get('is_unpacked'):
                evidence.append('unpacked/no update URL')
            if any(pattern in extension.get('host_permissions', []) for pattern in BROWSER_HIGH_RISK_HOST_PATTERNS):
                evidence.append('broad host permissions')
            if any(permission in BROWSER_HIGH_RISK_PERMISSIONS for permission in extension.get('permissions', [])):
                evidence.append('high-risk browser permissions')
            findings.append(Finding(
                rule_id='browser_extension_high_risk_capabilities',
                title='Browser extension has elevated automation or interception capability',
                family='Browser Extension Abuse',
                threat_level='low',
                author_or_actor='Could be enterprise tooling, developer tooling, or malicious extension',
                description=(
                    f"Extension {extension.get('name', extension.get('extension_id', 'unknown'))} in {extension.get('browser', 'browser')} "
                    f"requests unusual capability combinations ({', '.join(evidence)}). Review whether it is intentionally installed and whether the requested permissions make sense."
                ),
                evidence_type='browser-extension',
                source=source,
                matched_path=extension.get('manifest_path', ''),
                matched_regex=', '.join(evidence),
                confidence='context',
            ))
        return findings

    def _is_high_risk_extension(self, extension: Dict) -> bool:
        permissions = set(extension.get('permissions', []) or [])
        host_permissions = set(extension.get('host_permissions', []) or [])
        has_power = bool(permissions & BROWSER_HIGH_RISK_PERMISSIONS)
        broad_hosts = any(pattern in host_permissions for pattern in BROWSER_HIGH_RISK_HOST_PATTERNS)
        return extension.get('has_native_messaging') or (has_power and broad_hosts) or (extension.get('is_unpacked') and broad_hosts)

    def _bundle_provenance_findings(self, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for issue in self._collect_provenance_issues():
            findings.append(Finding(
                rule_id=issue.get('rule_id', 'bundle_provenance_issue'),
                title=issue.get('title', 'Downloaded app provenance issue'),
                family='Provenance / Code Signing',
                threat_level=issue.get('threat_level', 'low'),
                author_or_actor='Could be a local build, could be a tampered bundle',
                description=issue.get('description', 'Downloaded app bundle contains trust or provenance anomalies.'),
                evidence_type='provenance',
                source=source,
                matched_path=issue.get('path', ''),
                matched_regex=issue.get('evidence', ''),
                confidence=issue.get('confidence', 'context'),
            ))
        return findings

    def _collect_provenance_issues(self) -> List[Dict]:
        issues: List[Dict] = []
        for candidate in self._collect_downloaded_candidates(days=30):
            path_value = candidate.get('path', '')
            if not path_value.endswith('.app'):
                continue
            metadata = self._collect_file_security_metadata(path_value)
            if metadata.get('has_quarantine') and (not metadata.get('spctl_accepted') or not metadata.get('notarized')):
                issues.append({
                    'rule_id': 'downloaded_app_not_notarized',
                    'title': 'Recently downloaded app is not accepted or not notarized',
                    'threat_level': 'mid' if not metadata.get('spctl_accepted') else 'low',
                    'path': path_value,
                    'evidence': metadata.get('spctl_assessment') or metadata.get('origin_url') or metadata.get('signature_type', ''),
                    'description': (
                        f'App bundle {path_value} still carries quarantine metadata and did not present a normal accepted/notarized trust assessment. '
                        'Some developer builds do this legitimately, but trojanized apps and fake installers do as well.'
                    ),
                    'confidence': 'context',
                })
            for component in self._collect_bundle_components(path_value):
                component_meta = component.get('metadata', {})
                component_path = component.get('path', '')
                if component_meta.get('signature_type', '').lower() == 'unsigned' and component_path != path_value:
                    issues.append({
                        'rule_id': 'unsigned_nested_bundle_component',
                        'title': 'App bundle contains unsigned nested executable component',
                        'threat_level': 'mid',
                        'path': component_path,
                        'evidence': component_meta.get('signature_type', 'unsigned nested component'),
                        'description': (
                            f'App bundle {path_value} contains a nested executable-like component without a normal signature assessment: {component_path}. '
                            'That can be legitimate in some development builds, but it is also a classic tampered-bundle pattern.'
                        ),
                        'confidence': 'signal',
                    })
        return issues[:60]

    def _baseline_diff_findings(self, source: str) -> List[Finding]:
        snapshots = {
            'profiles': sorted(profile.get('identifier', '') for profile in self._collect_installed_profiles() if profile.get('identifier')),
            'tcc_clients': sorted(self._snapshot_key_for_tcc(entry) for entry in self._collect_tcc_entries() if self._is_suspicious_tcc_entry(entry)),
            'trust_flags': [json.dumps(self._collect_user_trust_settings(), sort_keys=True)],
            'persistence': sorted(self._snapshot_key_for_persistence(item) for item in self._collect_persistence_candidates()),
            'browser_extensions': sorted(self._snapshot_key_for_extension(item) for item in self._collect_browser_extensions() if self._is_high_risk_extension(item)),
        }
        findings: List[Finding] = []
        diff_summary = {}
        for name, current in snapshots.items():
            previous = self.storage.get_baseline(f'baseline:{name}', default=None)
            previous_exists = previous is not None
            previous_set = set(previous or [])
            current_set = set(current or [])
            new_items = sorted(current_set - previous_set)
            removed_items = sorted(previous_set - current_set)
            diff_summary[name] = {
                'new_count': len(new_items) if previous_exists else 0,
                'removed_count': len(removed_items) if previous_exists else 0,
                'new_examples': new_items[:5] if previous_exists else [],
                'removed_examples': removed_items[:5] if previous_exists else [],
                'baseline_initialized': not previous_exists,
            }
            if previous_exists and new_items:
                findings.append(Finding(
                    rule_id=f'baseline_change_{name}',
                    title=f'New host state detected since the previous local baseline: {name}',
                    family='Host Baseline Diff',
                    threat_level='low',
                    author_or_actor='Baseline comparison only',
                    description=(
                        f'Local baseline comparison found {len(new_items)} newly observed item(s) in {name}. '
                        'A change is not proof of compromise, but new sensitive profiles, TCC grants, persistence targets, or high-risk extensions should be reviewed.'
                    ),
                    evidence_type='baseline-diff',
                    source=source,
                    matched_regex='; '.join(new_items[:5]),
                    confidence='context',
                ))
            self.storage.set_baseline(f'baseline:{name}', list(current))
        self._last_diff_summary = diff_summary
        return findings

    def _snapshot_key_for_tcc(self, entry: Dict) -> str:
        return '|'.join([
            str(entry.get('service', '')),
            str(entry.get('client', '')),
            str(entry.get('db_path', '')),
        ])

    def _snapshot_key_for_persistence(self, item: Dict) -> str:
        return '|'.join([
            str(item.get('name', '')),
            str(item.get('identifier', '')),
            str(item.get('path', '')),
            str(item.get('type', '')),
        ])

    def _snapshot_key_for_extension(self, item: Dict) -> str:
        return '|'.join([
            str(item.get('browser', '')),
            str(item.get('profile', '')),
            str(item.get('extension_id', '')),
            str(item.get('version', '')),
        ])

    def _correlated_findings(
        self,
        source: str,
        profile_findings: List[Finding],
        tcc_findings: List[Finding],
        download_findings: List[Finding],
        trust_findings: List[Finding],
        persistence_findings: List[Finding],
        provenance_findings: List[Finding],
    ) -> List[Finding]:
        findings: List[Finding] = []
        if profile_findings and tcc_findings:
            findings.append(Finding(
                rule_id='correlated_profile_plus_tcc',
                title='Sensitive profile and suspicious TCC grant observed together',
                family='Correlation / Elevated Review Priority',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description=(
                    'This Mac has both an installed sensitive configuration profile and a suspicious TCC grant to a user-writable or staging-path binary. '
                    'That combination is substantially stronger than either signal alone and should be investigated before treating the host as clean.'
                ),
                evidence_type='correlation',
                source=source,
                matched_path='; '.join([item.matched_path for item in profile_findings[:2] + tcc_findings[:2] if item.matched_path]),
                matched_regex='profile + suspicious TCC grant',
                confidence='correlated',
            ))
        if trust_findings and profile_findings:
            findings.append(Finding(
                rule_id='correlated_profile_plus_trust_override',
                title='Sensitive profile and custom trust settings observed together',
                family='Correlation / Elevated Review Priority',
                threat_level='mid',
                author_or_actor='Correlation-based triage',
                description=(
                    'Sensitive installed profiles were found together with custom certificate trust settings. '
                    'This can be legitimate in managed environments, but it raises the review priority when the device was not intentionally enrolled.'
                ),
                evidence_type='correlation',
                source=source,
                matched_regex='profile + custom trust settings',
                confidence='correlated',
            ))
        if download_findings and (tcc_findings or profile_findings or persistence_findings or provenance_findings):
            findings.append(Finding(
                rule_id='correlated_download_plus_control_signal',
                title='Downloaded untrusted executable correlates with a control or persistence signal',
                family='Correlation / Delivery + Post-Exploitation',
                threat_level='mid',
                author_or_actor='Correlation-based triage',
                description=(
                    'A quarantined untrusted executable was observed along with either a suspicious TCC grant, a sensitive device-management profile, '
                    'a suspicious persistence target, or a bundle provenance anomaly. That combination deserves manual review because it links initial-delivery context with host-control signals.'
                ),
                evidence_type='correlation',
                source=source,
                matched_path='; '.join([item.matched_path for item in download_findings[:2] if item.matched_path]),
                matched_regex='download + control signal',
                confidence='correlated',
            ))
        return findings

    def _collect_installed_profiles(self) -> List[Dict]:
        collector = getattr(self.collector, 'collect_installed_profiles', None)
        return collector() if callable(collector) else []

    def _collect_tcc_entries(self) -> List[Dict]:
        collector = getattr(self.collector, 'collect_tcc_entries', None)
        return collector() if callable(collector) else []

    def _collect_diagnostic_reports(self, days: int = 7) -> List[Dict]:
        collector = getattr(self.collector, 'collect_diagnostic_reports', None)
        return collector(days=days, limit=200) if callable(collector) else []

    def _collect_downloaded_candidates(self, days: int = 30) -> List[Dict]:
        collector = getattr(self.collector, 'collect_recent_downloaded_candidates', None)
        return collector(days=days, limit=120) if callable(collector) else []

    def _collect_file_security_metadata(self, path: str) -> Dict:
        collector = getattr(self.collector, 'collect_file_security_metadata', None)
        return collector(path) if callable(collector) else {}

    def _collect_user_trust_settings(self) -> Dict:
        collector = getattr(self.collector, 'collect_user_trust_settings', None)
        return collector() if callable(collector) else {}

    def _collect_browser_extensions(self) -> List[Dict]:
        collector = getattr(self.collector, 'collect_browser_extensions', None)
        return collector(limit=150) if callable(collector) else []

    def _collect_persistence_candidates(self) -> List[Dict]:
        items: List[Dict] = []
        login_collector = getattr(self.collector, 'collect_login_items', None)
        bg_collector = getattr(self.collector, 'collect_background_items', None)
        if callable(login_collector):
            for item in login_collector(limit=60):
                items.append({
                    'type': 'login-item',
                    'name': item.get('name', ''),
                    'identifier': item.get('name', ''),
                    'path': item.get('path', ''),
                })
        if callable(bg_collector):
            for item in bg_collector(limit=120):
                items.append({
                    'type': item.get('type', 'background-item'),
                    'name': item.get('identifier', '') or item.get('path', ''),
                    'identifier': item.get('identifier', ''),
                    'path': item.get('path', ''),
                })
        return items

    def _collect_bundle_components(self, app_path: str) -> List[Dict]:
        collector = getattr(self.collector, 'collect_bundle_components', None)
        return collector(app_path, limit=40) if callable(collector) else []

    def _is_user_writable_persistence_path(self, path_value: str) -> bool:
        if not path_value:
            return False
        normalized = os.path.normpath(path_value)
        if normalized.startswith(BENIGN_CLIENT_PREFIXES):
            return False
        return any(marker in normalized for marker in PERSISTENCE_USER_WRITABLE_MARKERS)
