import os
import subprocess
import sys
from pathlib import Path

try:
    from piiscan.cli import main
except ModuleNotFoundError:
    if os.environ.get("PIISCAN_RELAUNCHED"):
        sys.exit("piiscan: the project environment is broken; run `uv run scripts/setup.py`")
    here = Path(__file__).resolve()
    try:
        sys.exit(subprocess.call(["uv", "run", "--project", str(here.parent), str(here), *sys.argv[1:]],
                                 env={**os.environ, "PIISCAN_RELAUNCHED": "1"}))
    except FileNotFoundError:
        sys.exit("piiscan: uv wasn't found; install it (winget install astral-sh.uv / brew install uv)")

if __name__ == "__main__":
    main(sys.argv[1:] or ["label"])
