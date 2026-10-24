# Progress & Next Steps — 2026-10-24

A short record of where the DNS tunnel detector stands after the fix round,
and the research-backed plan for what to do next. See
`docs/MODEL_EVALUATION_2026-10-24.md` for the full evaluation; this file is the
roadmap.

---

## 1. Where we are

Fix round (patches §3.1–3.4 applied, retrained on 18,353 records):

| | Before patches | After patches |
|---|---|---|
| Path A F1 (chosen branch) | 1.0000 (`rf_only`) | 0.9997 (`rf_gbt`) |
| **Path B F1** | **not evaluated** (test had 0 attacks) | **1.0000** |
| Benign heuristic FP rate | 23.8% | 6.3% |
| Benign records / clients | 5,662 / 1 | 8,353 / 4 |
| Attack families | dns2tcp, dnsexfiltrator | dns2tcp, dnsexfiltrator |

**What's still true, and will keep being true until we add new data:**

- A single feature (`query_length`) separates the classes with ROC-AUC 0.998.
  The 1.00 is dataset easiness, not model sophistication.
- Leave-one-tool-out recall: dns2tcp 0.32, dnsexfiltrator 0.00. The model
  learns tool fingerprints, not tunneling behavior.
- Benign is one pcap (≈50 s of browsing from 4 clients on one subnet). It
  cannot represent "normal network traffic".
- No evaluation on data the model never saw during training.

---

## 2. What recent papers say to do

Six 2024–2026 publications were surveyed. The pattern is consistent:

1. **Hold out whole tool families, not shuffled rows.** The 2025 LSH paper
   ([arXiv 2511.20229](https://arxiv.org/pdf/2511.20229)) splits GraphTunnel
   into a *Known* training subset and an *Unknown* subset of four tools used
   only at test time. "This subset is exclusively used for the detection task
   to evaluate the ability of the model to generalize to fully unknown
   tunneling tools."
2. **Expect perfect in-dataset scores to collapse on new data.** The 2025 NIDS
   survey ([arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)) reports that
   "evaluation of both works on the large-scale dataset yielded sub-par results
   that were significantly different from their reported results, even for
   the DNS tunneling class." This is normal; report it.
3. **Benign should be ~99% of real traffic**, not ~50%
   ([arXiv 1709.08395](https://arxiv.org/pdf/1709.08395)). Our 54.5% split
   flatters the model.
4. **Benign variety matters more than benign volume.** DNSTunnel2026
   ([Zenodo](https://zenodo.org/records/23326431)) draws benign from 25
   enterprise clients and keeps the imbalance "to reflect real-world network
   conditions".
5. **Combine emulated + synthetic + real benign** rather than one source
   ([arXiv 2502.06688](https://arxiv.org/pdf/2502.06688)).
6. **Reproducibility: publish testbed setup, domain lists, capture tooling,
   and feature-extraction code.** Several papers specifically ask for this.

---

## 3. Plan — in order of priority

### Step 1. Public holdout dataset (≈ half a day)

Pick one dataset and run `scripts/verify_models.py --holdout` against it.
This is the minimum step for a defensible capstone.

| Option | What's in it | Status for us |
|---|---|---|
| **DNSTunnel2026** ([Zenodo](https://zenodo.org/records/23326431)) | Benign from 25 enterprise clients + synthetic tunnels, imbalanced | **Preferred.** Solves "unseen tool" and "varied benign" together. |
| CIRA-CIC-DoHBrw-2020 ([UNB](https://www.unb.ca/cic/datasets/dohbrw-2020.html)) | Benign + iodine + dns2tcp + DNSCat2 over DoH | Need to adapt DoH flow features back to per-query features. |
| GraphTunnel PCAPs (cited by [LSH 2025](https://arxiv.org/pdf/2511.20229)) | Plain DNS, multiple tools incl. iodine | Format matches our pipeline; download link not verified. |

### Step 2. More varied own benign (≈ half a day, in parallel)

Follow the pattern from CIC-Bell-DNS 2021 and the NIDS survey:

1. Pick a benign domain list (Tranco top-1M or Alexa top-10k).
2. Capture from **2–3 different hosts** for at least a few hours each.
3. Target **≥ 50,000 benign queries** total.

Minimal recipe (per host):

```bash
sudo tcpdump -i any -w benign_$(hostname)_$(date +%F).pcap 'port 53' &
# Use the machine normally for 1–2 hours, or:
while read d; do dig +short "$d" >/dev/null; done < top1k_domains.txt
```

### Step 3. Real evaluation on unseen data (≈ 1 hour)

```bash
# Rebuild training set with new benign
python3 scripts/make_labeled_features.py --label 0 --family benign \
  --input benign_capture_1.pcap benign_capture_2.pcap benign_capture_3.pcap \
  --output data/processed/labeled_benign.json

./scripts/train_quiet.sh

# Evaluate on the unseen tool from Step 1
python3 scripts/verify_models.py \
  --holdout data/processed/holdout_benign.json data/processed/holdout_iodine.json
```

**Expected (from published patterns):**

- Known-tool recall: ≥ 0.95 (ours)
- **Unseen-tool recall: 0.3 – 0.7** (not 1.0 — and that is the honest result)
- Cross-dataset benign FP rate: 1 – 10%

### Step 4. Rewrite the paper's results section with these numbers (≈ half a day)

Add a §7 "Honest evaluation" to `docs/MODEL_EVALUATION_2026-10-24.md`:

> On the in-distribution test split, F1 = 1.00. On a held-out tool the model
> never saw (iodine), recall drops to R; false-positive rate on a cross-dataset
> benign capture is F. This is consistent with the generalization gap reported
> in LSH 2025 and Domainator 2025.

That paragraph is what makes the paper defensible. The 1.00 alone is not.

---

## 4. Optional — methodology work (after Steps 1–3 land)

These are worth doing only once the honest evaluation numbers are in. They
are the research direction the current literature points toward:

- **Per-domain / per-client aggregation features.** Infoblox's production
  detector groups by second-level domain + client IP and computes volume,
  entropy of subdomains, and query frequency. Our Path B already does
  per-client windows; Path A does not.
- **Temporal features.** Query interval, burstiness, inter-arrival entropy.
  These resist tools that mimic benign lexical shape.
- **Replace `query_length`-dominant features.** Our RF feature importance is
  dominated by `query_length` and `query_entropy`. The LSH 2025 and Domainator
  2025 papers use metadata *sequences* (query-type patterns, response-code
  patterns) that generalize better across tools.
- **DoH coverage.** Encrypted DNS breaks DPI; the detection moves to
  per-connection timing features. CIC-DoHBrw-2020 is the standard set for
  this.

---

## 5. If you only do one thing

Download **DNSTunnel2026** from [Zenodo](https://zenodo.org/records/23326431),
run `scripts/verify_models.py --holdout` against it, and put the result in
`docs/MODEL_EVALUATION_2026-10-24.md`. That one step turns the project from
"got 1.00 on an easy dataset" into "measured generalization gap and reported
it honestly" — which is the credible version of the same work.

---

## 6. Did we improve from before? — the honest answer

**Yes, but not in the way the F1 scores suggest.**

### What genuinely improved

| | Before | After | Real improvement? |
|---|---|---|---|
| Path B evaluability | Broken — test set had 0 attacks | Works — reports metrics | ✅ Structural |
| Fusion logic | Diluted Path A, ignored Path B gaps | OR-gate + `max(A, fused)` | ✅ Correctness |
| Benign heuristic FP | 23.8% | 6.3% | ✅ 4× cleaner labels |
| `longest_label` feature | Secretly = `first_label_length` | Actually longest label | ✅ Honesty |
| Benign client diversity | 1 host, 50 s | 4 hosts, same subnet | 🟡 Marginal |
| Documentation | 1 eval doc | Eval + roadmap + sources | ✅ Yes |

These are real engineering improvements. The project is in a better shape to
defend than it was.

### What did not improve

| | Before | After |
|---|---|---|
| Path A F1 (chosen) | 1.0000 | 0.9997 |
| Path A ROC-AUC | 1.000 | 1.000 |
| Single-feature AUC (`query_length`) | 0.998 | **still 0.998** |
| Leave-one-tool-out recall (dns2tcp) | 0.32 | **still 0.32** |
| Leave-one-tool-out recall (dnsexfiltrator) | 0.00 | **still 0.00** |
| Tool families covered | 2 | 2 |
| Evaluation on unseen data | None | None |

The headline numbers haven't moved because the fundamental problem — **the
dataset is too easy and too narrow** — is a *data* problem, not a *code*
problem. Fixing bugs cannot fix that.

### The honest one-liner

> The code is now correct enough to trust. The results are not yet strong
> enough to claim.

### What this means for the capstone defense

**You can now say** (and prove with the diffs):

- "I found and fixed four bugs that would have invalidated the Path B
  evaluation and biased the fusion decision."
- "I independently verified the pipeline against a label-shuffle test, a
  domain-grouped split, and a leave-one-tool-out protocol."
- "The project's methodology matches the current literature (per-client
  windows, benign-only autoencoder, two-detector fusion)."

**You cannot yet say** (and shouldn't try):

- "My detector works on new tunneling tools."
- "My detector generalizes to real networks."
- "My 1.00 F1 is meaningful."

### So — am I further along?

**Technically yes, scientifically only a little.** The improvement is from
"a working-looking project with hidden bugs" to "a working project with
known, documented limitations and a clear plan to address them". That is the
kind of progress a reviewer rewards, even when the numbers look identical.

The real jump — the one that will change the defense from "I built this" to
"I measured this and it works on data it never saw" — comes from **Step 1
above** (DNSTunnel2026 holdout). Until then, we are better prepared, not
better evaluated.

---

## 7. Pipeline-flow audit against the canonical 17 steps

Checked whether the implementation follows the standard training-plus-
detection ML pipeline. Result: **all 17 steps are implemented**, and the one
step the canonical diagram marks as "missing" (step 16, monitoring) is
actually present with Population Stability Index drift, alert-volume
tracking, and score-saturation checks.

### Training pipeline (steps 1–11)

| # | Step | Where it lives in this project | Status |
|---|---|---|---|
| 1 | Ingestion | `scripts/make_labeled_features.py` + `tshark` + `extractor.py`; `train_models.sh` STEP 0-A/0-B pre-processes LOG + PCAP | ✅ |
| 2 | Pre-processing | `features/extractor.py` computes the 8 lexical features; `parsing/dns_parser.py` normalizes column names | ✅ |
| 3 | Merge | `train_models.sh` STEP 0-C → `data/processed/merged_features_all.json` | ✅ |
| 4 | EDA | `train_models.sh` STEP 0-D runs `features/eda.py` → `data/processed/eda_report.json` | ✅ |
| 5 | Labeling | Provenance labels from the capture file in `make_labeled_features.py` (independent ground truth, as the diagram wants); `bridge.py --label-only` preserves them | ✅ |
| 6 | Split (before scaling) | `path_a.py` splits raw `X` first, then fits the scaler. The code comment literally says `"STEP 1: SPLIT BEFORE SCALING (prevents data leakage)"` | ✅ |
| 7 | Normalization | Path A: `StandardScaler.fit(X_train)` then transforms val/test. Path B: per-feature min/range from `X_train` only, saved to `dns_trafficformer_norm.json` | ✅ |
| 8 | Training | Path A: RF + HistGradientBoosting (production) + Transformer (baseline). Path B: Trafficformer autoencoder on **benign-only** windows | ✅ |
| 9 | Validation | Thresholds calibrated on validation: Path A uses F1-max from precision-recall curve; Path B uses 99th percentile of benign-val reconstruction error | ✅ |
| 10 | Testing | Final metrics on held-out test set → `models/evaluation_metrics.json` | ✅ (Path B was broken here before the §3.1 fix) |
| 11 | Save artifacts | `dns_tunnel_rf.pkl`, `dns_tunnel_gbt.pkl`, `dns_scaler.pkl`, `dns_threshold.json`, `dns_trafficformer.h5`, `dns_trafficformer_threshold.json`, `dns_trafficformer_norm.json`, `training_metadata.json`, `training_provenance.json`, `trained_files_registry.json` | ✅ |

### Detection pipeline (steps 12–17)

| # | Step | Where it lives in this project | Status |
|---|---|---|---|
| 12 | Ingestion | `scripts/run_pipeline.sh` reads new traffic | ✅ |
| 13 | Feature extraction | Same `extractor.py` / `parsing/dns_parser.py` as training (single source of truth) | ✅ |
| 14 | ML inference | `path_a.run_inference` + `path_b_predict.score_records` + `fusion/bridge.run_pipeline` | ✅ |
| 15 | Detection rules | `detection/engine.py`: 6 rules + Z-score detector (`zscore_threshold=2.0`, Rule 6 uses `ml_threat_score`) | ✅ |
| 16 | Monitoring (diagram marks this missing) | **Actually present:** `monitoring/monitor.py` computes PSI drift per feature, tracks alert-volume rate, checks for score saturation, writes `monitoring_report.json` | ✅ **exceeds the diagram** |
| 17 | Retrain trigger | `monitor.py` sets `retrain_recommended = true` on major drift / implausible alert volume / score saturation, and prints the exact command: `./scripts/train_models.sh --retrain`. The trainer has a smart `--retrain` mode that only picks up new files via `trained_files_registry.json`. | ✅ semi-automatic |

### The one gap worth noting

Step 17 is **recommend-only**, not **auto-execute**. The monitor writes the
recommendation; an operator (or a cron job reading `monitoring_report.json`)
still has to run `train_models.sh --retrain`. The docstring is explicit about
this — *"an operator (or a cron job reading the JSON) decides"* — because
auto-retraining on drift is dangerous without a human check. If closed-loop
retraining is desired, it is one cron entry plus a wrapper away.

### What this means for the defense

Your pipeline matches the canonical 17-step ML operations loop end to end,
with the split-before-scale discipline and independent provenance labels
cutting off the two most common sources of inflated metrics in prior work.

Honest one-liner for the paper:

> "The pipeline follows the standard 17-step ML operations loop: ingest →
> preprocess → merge → EDA → label → split → scale → train → validate →
> test → persist → infer → rule-check → **monitor for drift** → recommend
> retrain. The split-before-scale discipline and the independent provenance
> labels remove the two most common sources of inflated metrics in prior
> work."

The remaining weakness is still **data**, not **flow**. The flow is already
correct.

---

## Sources

- [LSH paper (arXiv 2511.20229)](https://arxiv.org/pdf/2511.20229) — unseen-tool evaluation protocol
- [Domainator (arXiv 2505.22220)](https://arxiv.org/pdf/2505.22220) — metadata sequences, cross-dataset gap
- [NIDS Datasets Survey (arXiv 2502.06688)](https://arxiv.org/pdf/2502.06688) — cross-dataset drop, benign-realism gap
- [Nadler et al. (arXiv 1709.08395)](https://arxiv.org/pdf/1709.08395) — 99% benign ratio
- [DNS-HyXNet (arXiv 2512.09565)](https://arxiv.org/html/2512.09565) — recent benchmark claims
- [DNSTunnel2026 (Zenodo)](https://zenodo.org/records/23326431) — primary holdout candidate
- [CIRA-CIC-DoHBrw-2020 (UNB)](https://www.unb.ca/cic/datasets/dohbrw-2020.html) — iodine + DNSCat2 + dns2tcp
- [CIC-Bell-DNS 2021 (UNB)](https://www.unb.ca/cic/datasets/dns-2021.html) — benign-generation recipe
- [DNS Tunneling Threat Landscape (arXiv 2507.10267)](https://arxiv.org/abs/2507.10267) — "two numbers" caveat
- [Infoblox ML DNS Tunneling](https://www.infoblox.com/blog/security/novel-ai-techniques-for-dns-tunnel-security/) — per-domain/client features
