import sys
from pathlib import Path

# ensure the 'src' directory is on the import path so that our package
# can be imported during tests without needing installation.
ROOT = Path(__file__).parent.parent.resolve()
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
