import os
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault('MAC_SENTINEL_STATE_DIR', tempfile.mkdtemp(prefix='mac_sentinel_test_state_'))
