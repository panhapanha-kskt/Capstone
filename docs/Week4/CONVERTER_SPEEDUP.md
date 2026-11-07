# Faster Tunnel Converter: What Changed and How to Check It

**DNS Traffic Anomaly Detection · speed-up of `scripts/convert_external_tunnels.py` · 2026-11-07**

Converting the 57 new tunnel captures (Tu et al., 2023) into labeled records took too long on the Kali machine. This document explains:

- why the converter was slow;
- what was changed;
- how the changes were checked to give exactly the same output;
- how to compare old vs new speed yourself.

The training steps that use the converter are in [NEW_DATASET_TRAINING_STEPS.md](NEW_DATASET_TRAINING_STEPS.md) (step 2).

---

## Contents

1. [Why it was slow](#1-why-it-was-slow)
2. [What was changed](#2-what-was-changed)
3. [Why the output stays the same](#3-why-the-output-stays-the-same)
4. [The worker start-up fix (spawn)](#4-the-worker-start-up-fix-spawn)
5. [How it was checked](#5-how-it-was-checked)
6. [How to use it](#6-how-to-use-it)
7. [Compare old vs new yourself](#7-compare-old-vs-new-yourself)
8. [Files changed](#8-files-changed)

---

## 1. Why it was slow

The converter reads every packet with scapy, which parses packets in pure Python and is the slowest part of the work. Reading the code showed four sources of waste:

| # | Problem | Where | Effect |
|---|---|---|---|
| 1 | **Every capture was parsed twice**: once for the truncation check, once to read the queries | `convert_family()` called `truncation_report()`, then `records_from_pcap()` | twice the parsing work |
| 2 | **The truncation check re-encoded every packet** (`bytes(pkt)`) just to measure its captured length | `make_labeled_features.truncation_report()` | extra work per packet, although scapy already keeps the original bytes |
| 3 | **Features were computed for every query, then most were thrown away**: the domain filter drops OS background lookups, and the cap keeps at most 5,000 queries per tool | `records_from_pcap()` computes entropy, encoding checks and heuristics per query | for big tools (iodine: 36 captures) most of the feature work was wasted |
| 4 | **One CPU core, one file at a time** | the main loop | 3 of the machine's 4 cores sat idle |

---

## 2. What was changed

| Before | After |
|---|---|
| Two full passes per capture | **One pass**: the truncation count and the queries come from the same loop (`scan_pcap()`) |
| `bytes(pkt)` to get the captured length | **The packet's original bytes** (`pkt.original`), with no re-encoding |
| Features for every query, then filter and cap | **Light fields first** (domain, time, client, port, protocol, type). Then find the tunnel domain, filter, and apply the cap. **Then compute features only for the kept rows** (≤ 5,000 per tool), in `full_record()` |
| 1 file at a time | **Files scanned in parallel** on `--jobs` cores (default: all cores but one, so 3 on the 4-core Kali machine), **largest files first** so a big file doesn't start last and hold up the end |
| No progress output | **One line per capture** (`[ 12/57] iodine_base128/iodine128_txt_up.pcapng: 8412 queries (95s)`) and the total time at the end (`[*] done in Ns`) |

Kept as before:

- **`--legacy`** runs the original code path unchanged, for comparison.
- **`make_labeled_features.py` is not changed.** `train_models.sh` and `convert_cic_dns.py` also use its `records_from_pcap()` and `truncation_report()`. The fast path is new code inside the converter only.
- **The output files and options are unchanged**: `tunnels_<tool>.json`, `conversion_summary.json`, `--families`, `--domain`, `--max-per-family`, `--block`, `--max-truncated`, `--seed`.
- **`conversion_summary.json` is written once by one process.** Running one converter per tool by hand is no longer needed. That workaround made each run overwrite the others' summary.

---

## 3. Why the output stays the same

A faster converter is only useful if it produces exactly the same training data. Three facts make that hold:

1. **Same rules for what counts.** `scan_pcap()` uses the same two rules as the original:
   - a packet counts for the truncation check when it goes to port 53, and is cut when its on-wire length exceeds its captured length;
   - a packet is a query when it has a DNS question, `qr == 0`, and a non-empty name.
2. **The features depend only on the query itself.** The feature extractor keeps no memory between queries that affects its results; it only counts totals for a printed summary. Computing features later, for fewer rows, therefore gives the same values for those rows.
3. **The cap picks the same rows.** The 5,000-per-tool cap (`cap_family()`) looks only at timestamps. The light rows carry exactly the same timestamp strings, in the same order, so the cap selects the same contiguous time blocks.

---

## 4. The worker start-up fix (spawn)

The first version of the test passed but printed a warning:

```
DeprecationWarning: This process ... is multi-threaded, use of fork() may lead to deadlocks in the child.
```

**Why it matters.** On Linux, Python starts worker processes by default with `fork`, which copies the running process. If that process has background threads (from a library or from pytest), a copied worker can occasionally freeze before it starts. The converter would then hang forever on the first progress line.

**Fix.** Workers are now started with `spawn`: each one is a fresh Python process. This costs about a second at start-up and nothing per file:

```python
with ProcessPoolExecutor(max_workers=jobs, mp_context=multiprocessing.get_context("spawn")) as pool:
```

After this fix the test ran on Kali with no warning (commit `1f680f0`).

---

## 5. How it was checked

New test file: `tests/test_convert_tunnels_fast.py`. It builds small sample captures with scapy. They contain:

- tunnel queries (TXT and A) under `tunnel-example.com`, plus a DNS-over-TCP query;
- normal queries to another domain, which must be dropped;
- DNS responses, which must be ignored;
- non-DNS UDP packets, which must be ignored.

| Test | Checks |
|---|---|
| `test_scan_matches_truncation_report` | the single-pass truncation count equals the original `truncation_report()` for every file |
| `test_fast_path_equals_legacy[0]` | with no cap, fast and original give the same domain, the same dropped count, **the same records** and **the same key order** |
| `test_fast_path_equals_legacy[50]` | the same, with a cap that drops rows (the cap selects the same rows) |
| `test_parallel_scan_equals_serial` | scanning on 2 cores gives exactly the same result as on 1 core |

Result on Kali: **4 passed**, no warnings.

The test uses small synthetic captures. The real-data check in [section 7](#7-compare-old-vs-new-yourself) compares both versions on an actual tool from the dataset.

---

## 6. How to use it

```bash
cd /home/ounnha/Documents/Capstone
export PYTHONPATH=src
R=data/external/tu2023/repo/datasets/base_malicious_dataset

python3 scripts/convert_external_tunnels.py --root $R --out-dir data/external/tu2023 \
    --families cobaltstrike det dns_shell dnscat2 iodine ozymandns
```

| Option | Effect |
|---|---|
| (default) | fast path on all cores but one |
| `--jobs N` | use N cores. Use fewer (e.g. `--jobs 2`) to keep the machine responsive while working, more if nothing else runs. |
| `--legacy` | the original single-core code, for comparison only |

The 6 new tools have **57 captures**: cobaltstrike 6, det 1, dns_shell 2, dnscat2 10, iodine 36, ozymandns 2. iodine dominates the run time.

After the run, check every tool's detected tunnel domain in the summary lines (`<tool>  domain=...`). A domain that looks like a normal site means the auto-detection picked the wrong one. Re-run that tool with `--domain TOOL=REAL.DOMAIN`.

---

## 7. Compare old vs new yourself

Use a small tool (dns_shell, 2 captures), so the slow original finishes quickly:

```bash
python3 scripts/convert_external_tunnels.py --root $R --families dns_shell --out-dir /tmp/old --legacy
python3 scripts/convert_external_tunnels.py --root $R --families dns_shell --out-dir /tmp/new
cmp /tmp/old/tunnels_dns_shell.json /tmp/new/tunnels_dns_shell.json && echo "IDENTICAL"
```

- `cmp` compares the two output files byte for byte. `IDENTICAL` means the fast path produced exactly the same training data.
- Each run ends with `[*] done in Ns`. The two times show the speed-up.

With only 2 captures, at most 2 cores are used, so this small comparison understates the gain. The full run benefits more: 57 files spread over 3 cores, and most of iodine's feature work skipped.

Record the results here:

| Run | Time | Output |
|---|---|---|
| dns_shell, `--legacy` | … s | — |
| dns_shell, fast | … s | `cmp`: … |
| all 6 tools, fast (3 cores) | … s | 6 files, 57 captures |

---

## 8. Files changed

| File | Change |
|---|---|
| `scripts/convert_external_tunnels.py` | single-pass `scan_pcap()`, features computed after the filter and cap (`full_record()`), parallel `scan_all()` with `--jobs`, `spawn` workers, progress and timing output, `--legacy` keeps the original path |
| `tests/test_convert_tunnels_fast.py` | new: 4 tests, fast path = original path |
| `docs/Week4/NEW_DATASET_TRAINING_STEPS.md` | step 2: speed note |
| `scripts/make_labeled_features.py` | **unchanged** |
