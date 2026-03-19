from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / 'backend-dist'
SPEC_NAME = 'mac-sentinel-backend'


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['dir', 'package'], default='package')
    options = parser.parse_args()

    DIST_DIR.mkdir(exist_ok=True)
    build_dir = ROOT / 'build-backend'
    if build_dir.exists():
        shutil.rmtree(build_dir)
    target = DIST_DIR / SPEC_NAME
    if target.exists():
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    cmd = [
        sys.executable,
        '-m',
        'PyInstaller',
        '--noconfirm',
        '--clean',
        '--name',
        SPEC_NAME,
        '--paths',
        str(ROOT),
        '--add-data',
        f'{ROOT / "data"}:data',
        '--distpath',
        str(DIST_DIR),
        '--workpath',
        str(build_dir),
    ]
    if options.mode == 'package':
        cmd.append('--onefile')
    else:
        cmd.append('--onedir')
    cmd.append('app.py')
    run(cmd)


if __name__ == '__main__':
    main()
