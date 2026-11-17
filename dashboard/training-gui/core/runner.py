"""Tiny cross-platform wrapper: runs TRAIN_CMD (inherits the log as stdout) and records its exit code."""
import os
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    rc = subprocess.call(os.environ["TRAIN_CMD"], shell=True)
    (Path(sys.argv[1]) / "exitcode").write_text(str(rc))
