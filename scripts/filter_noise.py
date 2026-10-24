#!/usr/bin/env python3
"""filter_noise.py — read stdin, print only the signal lines to stdout.

Drops:
  - scapy module-import tracebacks (ERROR: Loading module ... Invalid DH parameters)
  - TensorFlow absl / CUDA / oneDNN / cpu_feature_guard info lines
  - Keras HDF5 deprecation warnings
  - Per-epoch progress bars (keeps the final 'val_loss improved' lines)

Usage: <some_command> 2>&1 | python3 filter_noise.py
"""
from __future__ import annotations
import re
import sys

NOISE = re.compile(
    r"^WARNING: All log messages|"
    r"^I0000 00:00|"
    r"^E0000 00:00|"
    r"^To enable the following instructions|"
    r"oneDNN custom operations|"
    r"cuda drivers|"
    r"cpu_feature_guard|"
    r"^WARNING:absl:You are saving your model as an HDF5|"
    r"^WARNING:absl:Compiled the loaded model|"
    r"^\s*\d+/\d+\s+━+.*(?:ETA|loss:|accuracy:|auc:)"   # per-batch Keras progress
)

in_scapy_block = False

for line in sys.stdin:
    s = line.rstrip("\n")

    # Scapy traceback: a block that starts with ERROR: Loading module scapy
    # and ends with the ValueError: Invalid DH parameters.
    if s.startswith("ERROR: Loading module scapy"):
        in_scapy_block = True
        continue
    if in_scapy_block:
        if "ValueError: Invalid DH parameters" in s:
            in_scapy_block = False
        continue

    if NOISE.search(s):
        continue

    print(s, flush=True)
