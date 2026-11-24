# v4 candidate: GraphTunnel data added (2026-11-21)

**DNS Traffic Anomaly Detection · Week 7 · first training run with a second public tunnel dataset**

## 1. What was done today

| Step | Result |
|---|---|
| Dataset found | **GraphTunnel "DNS-Tunnel-Datasets"** (ggyggy666, IEEE 2024): raw pcaps, 131 files, 885 MB; full packets (snaplen 262144 on the classic pcaps; the pcapng splits passed the converter's truncation check). No licence text; the authors ask for citation of the dataset and the GraphTunnel paper. |
| Converter | `scripts/convert_graphtunnel.sh` (new): stages one folder per attack family, runs `convert_external_tunnels.py` (one tunnel domain per family, contiguous blocks, 5,000 queries per family), converts the first 15 `normal/` files and first 4 `wildcard/` files as benign with `make_labeled_features.py --label 0`. 87 s for the 41 attack captures on 19 cores. |
| Duplicate found | `unkownTunnel/dns2tcp-key.pcap` is the same 34,555-query capture as `tunnel/dns2tcp-key/` (3 pieces). Only one is used; the script no longer stages the second. |
| Tunnel domain | `ggy666.tk` for all 25 families (the authors used one domain). Correct detection. |
| Training | `DNS_DETECT_MODELS_DIR=runs/v4_graphtunnel ./scripts/train_models.sh --force-retrain --seed 42 --files <3 local files> data/external/graphtunnel/tunnels_*.json data/external/graphtunnel/benign_*.json` — **29 min 38 s**. |
| New option | `train_models.sh --add-files F…` / `run_all.sh --retrain --add-files F…` / `ADD_FILES=… run_candidate_seeds.sh`: the live model's training files (from `models/training_provenance.json`) plus the new ones, so "train more data" is one argument. Refuses when a live file is missing locally (the 7 Tu 2023 files are still on the Kali VM, so this run used `--files` instead). |

## 2. Training data of `runs/v4_graphtunnel`

514,896 rows after merge (29 files): **130,000 attack / 384,896 benign**, 26 attack families.

| Source | Rows | Class |
|---|---|---|
| `labeled_tunnels.json` (dns2tcp, dnsexfiltrator; Tu 2019 captures) | 10,000 | attack |
| `labeled_benign.json` | 8,353 | benign |
| `cic_benign_train.json` | 41,275 | benign |
| GraphTunnel `tunnels_*.json` × 24 families | 5,000 each = 120,000 | attack |
| GraphTunnel `benign_graphtunnel.json` (normal_00000–00014) | 225,000 | benign |
| GraphTunnel `benign_wildcard.json` (wildcard_00000–00003) | 110,272 | benign |

GraphTunnel families: andiodine (cname, mx, null, srv, txt), cobaltstrike_gt, dns2tcp_key_gt, dns2tcp_txt_unk, dns_shell_gt, dnscat2 (cname, mx, txt), dnspot, iodine (a, cname, mx, null, private, srv, txt), ozymandns_gt, tcp_over_dns (cname, txt), tuns.

**Record types now in the attack class:** A (dnspot, dns_shell, iodine_a, cobaltstrike), CNAME (dnscat2, iodine, tuns, tcp-over-dns, andiodine), MX, SRV, PRIVATE/65399 — not only TXT/KEY/NULL. **This is the "harder data" Week 7 Task 2 asked for**, obtained from a public set instead of the lab (the lab captures A1–A4/B1–B3 are still worth doing: they are on *your* resolver).

Merge warnings worth keeping in mind: 89 % of rows repeat another row's exact feature vector (tunnel traffic is repetitive; the split is by feature vector so this is handled), 25 feature vectors carry both labels (415 rows, dropped by Path A), and every source file holds one class.

## 3. Results — read the caveat first

**Caveat: the test set is still the frozen 2,568 rows of `time_seed42.json`** (1,168 benign, 1,400 attack, all from the 2019/2020/2026 data). By design (`--split-manifest` extends; new rows go to train/val only), **none of the GraphTunnel rows are in the test set.** The numbers below therefore say "the new model still passes the old test"; they say nothing yet about how it does on GraphTunnel traffic.

| Detector | Test recall | False alarms / 1,168 benign | Note |
|---|---|---|---|
| Path A (RF only; gate preferred RF over RF+GBT) | 1.000 | **0** (0.00 %) | threshold 0.4412, set on 77,048 validation rows (val FPR 0.0 %) |
| **Path B (Isolation Forest)** | **0.000** | 0 | threshold p99 = 0.6009; `recall_at_fpr_0.001` = 1.0 → the ranking is still perfect, the **threshold is now too high** (benign validation is far more diverse, so its 99th percentile moved above the old attack windows) |
| OR rule | 1.000 | 0 | |
| Fusion V1 | 1.000 | **0** | weights A 14.85, B 2.55, has_B −3.97, rule hits −0.18; threshold 0.4995. Relies on Path A entirely. |
| Budget check | — | upper 95 % bound 0.26 % | still above 0.1 %: 1,168 benign rows cannot show it (needs ≥ 2,995 with no false alarms) |

Compared with the live model `v3_iforest` on the same test rows: fusion 7 false alarms → **0**; Path A 8 → **0**. Test rows with an exact twin in train: 32 % (was 27 %).

**Path B regression.** Recall 0.0 at the saved threshold is the same failure mode the autoencoder had in Week 5, for a different reason: the Isolation Forest still ranks attack windows above benign ones (recall at 0.1 % FPR = 1.0), but the fixed p99-of-benign-validation threshold does not transfer when the benign validation population changes. The audit (finding #3 and the T4 notes) already argued for a calibrated, budget-based Path B threshold; this run makes it necessary before v4 can be judged.

## 4. What this run does *not* yet show, and the commands to show it

1. **Performance on the new data itself.** Options, in order of honesty:
   - Later-traffic check on the **held-out** GraphTunnel files (never trained on): `normal_00015…00067` (53 files, ~800k benign) and `wildcard_00004…00012` (9 files). Convert a few with `make_labeled_features.py --label 0` and score with `scripts/evaluate_detectors.py --runs runs/v4_graphtunnel` on that file — this is Week 7 **Task 4** with real data.
   - Leave-one-tool-out over the 24 GraphTunnel families (`scripts/run_cv.py`, strategy `lofo`).
   - A **domain-grouped split** is now possible for the first time: attack domains `ggy666.tk`, `dns2tcp-key.com` (+ the Tu 2023 domains once copied). Week 7 **Task 3** is unblocked.
2. **Seed stability.** One seed. `RUN_NAME=v4_graphtunnel SEEDS="42 43 44" FILES="<same 28 files>" bash scripts/run_candidate_seeds.sh` → gate. The gate's "beats every rule baseline" criterion should finally be *beatable*: the TXT/KEY/NULL rule cannot catch the A/CNAME/MX/SRV tunnels now in the data.
3. **Path B threshold.** Re-set it for a false-alarm budget on benign validation windows (as Path A does) instead of a fixed percentile, then re-score.

## 5. Files

- `runs/v4_graphtunnel/` — full model set (`dns_tunnel_rf.pkl`, `dns_trafficformer_iforest.pkl`, `fusion_lr.pkl`, `split_manifest.json`, `evaluation_metrics.json`, `run_record.json`, `training_provenance.json` with 29 files)
- `data/external/graphtunnel/` — 24 `tunnels_*.json`, `benign_graphtunnel.json`, `benign_wildcard.json`, `conversion_summary.json`; `repo/` is the clone (1.2 GB, keep out of git)
- `scripts/convert_graphtunnel.sh` — the converter (idempotent; `--normal-files 68 --wildcard-files 13` converts all benign)
- `logs/training_20261121_183813.log`

**`models/` was not changed.** `runs/v4_graphtunnel` is a candidate.

## 6. Citation

Gao et al., *GraphTunnel: Robust DNS Tunnel Detection Based on DNS Recursive Resolution Graph*, IEEE 2024 (https://ieeexplore.ieee.org/document/10636232); dataset https://github.com/ggyggy666/DNS-Tunnel-Datasets.

## 7. Follow-up the same evening: `runs/v5_dmachard`

Added dmachard's five reference captures (https://github.com/dmachard/datasets-malicious-dns, no licence stated):
`dns2tcp_dm` 22 queries (TXT, `hsc.fr`), `dnscat2_dm` 12 (MX/TXT/CNAME, `biillpi.com`), `dnsextrator_dm` 14 (TXT, `hsc.fr`),
`iodine_dm` 12 (NULL, `biillpi.com`), `sods_dm` 493 (CNAME/A/TXT, `hsc.fr`). Same command as §1 plus `data/external/dmachard/tunnels_*.json`.

Result: 515,449 rows, 31 families, 28 min 0 s; frozen-test numbers identical to v4 (fusion recall 1.0, 0 false alarms; Path B
threshold 0.6009). The rows barely matter; the **two new attack domains** do: with `ggy666.tk`, `dns2tcp-key.com`, `hsc.fr` and
`biillpi.com` a parent-domain-grouped split (Task 3) is now possible. `models/` unchanged.
