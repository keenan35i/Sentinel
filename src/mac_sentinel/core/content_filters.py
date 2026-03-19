from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable

TEXT_LIKE_EXTENSIONS = {
    '.sh', '.zsh', '.bash', '.command', '.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.json', '.plist', '.xml', '.yaml', '.yml', '.toml', '.conf', '.cfg', '.ini', '.txt',
    '.log', '.sql', '.scpt', '.applescript', '.osa', '.html', '.htm', '.css', '.md', '.pbxproj',
    '.strings', '.env', '.swift', '.rb', '.php', '.pyi', '.properties',
}

BINARY_OR_NOISY_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.tiff', '.bmp', '.ico', '.icns',
    '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.dmg', '.pkg', '.iso',
    '.sqlite', '.sqlite3', '.db', '.blob', '.pak', '.nib', '.car',
    '.dylib', '.so', '.a', '.o', '.node', '.class', '.jar', '.pyc',
    '.ttf', '.otf', '.woff', '.woff2',
    '.mp3', '.wav', '.m4a', '.aac', '.mp4', '.mov', '.avi', '.mkv',
}

KNOWN_NOISY_PATH_SNIPPETS = {
    '/Contents/Frameworks/',
    '/Contents/Resources/',
    '/node_modules/',
    '/site-packages/',
    '/.venv/',
    '/__pycache__/',
    '/IndexedDB/indexeddb.blob/',
    '/WebStorage/',
    '/Cache/',
    '/Caches/Google/',
    '/fontawesome/',
    '/dist/renderer/assets/',
    '/dist/assets/',
    '/electron/renderer/vendor/',
    '/vendor/',
    '/build/',
    '/metadata/',
    '/tests/',
    '/fixtures/',
    '/artifacts/',
    '/mac_sentinel/',
    '/mac-sentinel/',
    '/mvt/',
    '/WasmTtsEngine/',
    '/DiagnosticReports/',
}

IGNORED_FILENAMES = {
    'ioc_patterns.json',
    'rules.py',
    'models.py',
    'diagnostics.py',
    'host_intelligence.py',
}


IGNORED_SUFFIXES = {
    '.min.js',
}

IGNORED_NAME_PATTERNS = (
    'brands.js',
    'brands.min.js',
    'v4-shims.js',
    'v4-shims.min.js',
    'messages.json',
)


def is_inside_app_bundle(path: str) -> bool:
    parts = Path(path).parts
    return any(part.endswith('.app') for part in parts)



def is_probably_binary(data: bytes) -> bool:
    if not data:
        return False
    if b'\x00' in data:
        return True
    sample = data[:4096]
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return (control / max(1, len(sample))) > 0.20



def _is_vendor_or_generated_asset(path: str) -> bool:
    lowered = path.lower()
    name = Path(path).name.lower()

    if '/_locales/' in lowered:
        return True
    if any(snippet.lower() in lowered for snippet in KNOWN_NOISY_PATH_SNIPPETS):
        return True
    if name in IGNORED_FILENAMES:
        return True
    if name.startswith('test_') and name.endswith('.py'):
        return True
    if any(name.endswith(suffix) for suffix in IGNORED_SUFFIXES):
        return True
    if name in IGNORED_NAME_PATTERNS:
        return True
    return False



def should_scan_content(path: str, rule: Dict) -> bool:
    normalized = path.replace('\\', '/')
    lowered = normalized.lower()

    if _is_vendor_or_generated_asset(normalized):
        return False

    if rule.get('skip_app_bundle_content', True) and is_inside_app_bundle(path):
        return False

    ext = Path(path).suffix.lower()
    include = {str(item).lower() for item in rule.get('content_extensions_include', []) if item}
    exclude = {str(item).lower() for item in rule.get('content_extensions_exclude', []) if item}

    if ext in exclude:
        return False
    if include:
        return ext in include
    if ext in BINARY_OR_NOISY_EXTENSIONS:
        return False
    return ext in TEXT_LIKE_EXTENSIONS



def count_content_hits(patterns: Iterable[str], matcher) -> tuple[int, str]:
    count = 0
    first = ''
    for pattern in patterns or []:
        hit = matcher(pattern)
        if hit:
            count += 1
            first = first or hit
    return count, first
