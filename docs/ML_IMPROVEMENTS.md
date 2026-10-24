# ML Improvements: Rationale, Decisions, and References

This page records **what we changed in the ML, why, and which literature backs each
choice**. It is the reference for the defense: every design decision below links to the
source it comes from, and the limitations section states what the results can and
cannot support.

---

## 1. Problems found in the original pipeline

A full `--force-retrain` run on the lab dataset (8,152 queries) showed three problems:

| # | Problem | Evidence | Why it matters |
|---|---------|----------|----------------|
| 1 | **Circular labeling** | Labels came from `attack_count`, which is the extractor's own six heuristics | A 0.98 ROC-AUC only shows that the ML imitates the heuristics. The ML could never find an attack the rules miss (Arp et al., pitfall P2) |
| 2 | **The Transformer did not learn** | val/test AUC ≈ 0.51, accuracy frozen at 0.7232 (the benign share) | It always predicted the majority class. The Random Forest produced all of the ensemble's performance |
| 3 | **Path B was weak** | It used one feature (query length). There were 59 benign training windows and 0 benign validation windows | The anomaly threshold was not calibrated on normal traffic |

---

## 2. Decisions, each backed by a source

### Tier 1: Independent ground-truth labels (fixes problem 1)

- **What:** `scripts/label_from_manifest.py` labels a query as an attack when its
  timestamp falls inside an attack window that is recorded in `data/attack_manifest.csv`
  and its client IP matches the attacker (if one is given). Every other query is benign.
  `train_models.sh` uses the manifest automatically when the file exists. Without it,
  the script falls back to the heuristic labels and prints a warning.
- **Why:** CIC-IDS2017 labels its benchmark the same way: by timestamp, source and
  destination IP, port, protocol, and attack type, taken from the published attack
  schedule. The HERA tool also matches flows against a ground-truth file and treats
  everything unmatched as benign. Sommer & Paxson argue that without sound ground truth
  an evaluation is not worth doing.
- **Template:** `data/attack_manifest.example.csv`. Copy it to `data/attack_manifest.csv`
  and add one row for each attack run.

### Tier 2a: Path A is now Random Forest + Gradient Boosting; the Transformer is a baseline (fixes problem 2)

- **What:** The production Path A score is the soft vote (mean probability) of a
  `RandomForestClassifier` and a `HistGradientBoostingClassifier`. A **decision gate**
  keeps this combination only if its held-out F1 is at least the RF-only F1. Otherwise
  Path A falls back to RF alone. The choice is saved in `models/dns_threshold.json`
  (`decision`). The Transformer is still trained, and its metrics are reported under
  `transformer_baseline`, but it is **excluded from the decision**.
- **Why:**
  - Tree models still beat deep networks on small and medium tabular data
    (Grinsztajn et al., NeurIPS 2022). FT-Transformer is only competitive on datasets
    larger than about 10K rows (Gorishniy et al., 2021). Our dataset has about 8K rows
    and 8 features.
  - Gradient boosting usually edges out RF on network-intrusion tabular data (on
    CIC-IDS2017, XGBoost reached macro-F1 0.97 against 0.95 for RF). The two models also
    weight features differently: RF spreads importance across many features, while
    boosting concentrates it on a few. That makes them a real pair of independent
    opinions. Combining them does not always help, which is why the gate exists.

### Tier 2b: Path B uses multiple features, a percentile threshold, and per-client windows (fixes problem 3)

- **Multiple features:** Path B now reconstructs five features per query:
  `query_length, query_entropy, subdomain_count, digit_ratio, longest_label`
  (`PATH_B_FEATURES` in `parsing/dns_parser.py`). Kitsune (Mirsky et al., NDSS 2018)
  reconstructs multi-dimensional feature vectors, and DNS-tunneling detection combines
  length, entropy, and label structure.
- **Per-client, time-ordered windows:** The records are sorted by time and split
  70/15/15 in time order. Inside each split, sliding windows are built **within each
  `client_ip`**, so a window never mixes hosts and always represents a real temporal
  sequence. Sequence-anomaly work builds windows per host or per host pair in the same
  way.
- **Percentile threshold:** The threshold is the **99th percentile** of the
  reconstruction error on benign validation windows. This replaces `mean + 2.5σ`, which
  assumes the errors are roughly normal. The percentile can be set in `config/settings.yaml`
  (`training.path_b_threshold_percentile`). The `mean + k·σ` rule is still available with
  `--threshold-method mean_std`. The method used is saved in
  `models/dns_trafficformer_threshold.json`.
- **Simplification we document:** Kitsune's full design is an *ensemble* of small
  autoencoders over subsets of the features (KitNET). We use a single multi-feature
  autoencoder, which is a reasonable scope for a capstone. KitNET is future work.

### Tier 3: Evaluation rigor

- **PR-AUC is the primary metric**, reported next to its random baseline (the attack
  prevalence). ROC-AUC and accuracy are secondary. Saito & Rehmsmeier (2015) show that
  the precision-recall curve is more informative than ROC when the classes are
  imbalanced.
- **Per-attack-family recall** (`recall_by_family`) is computed from the manifest's
  `family` column. It shows which kinds of attack are caught and which are missed.
- **Label-shuffle check:** `python -m dns_detect.models.path_a --train <file> --shuffle-labels`
  retrains on permuted labels. If the pipeline does not leak information, the scores fall
  toward the prevalence baseline. This is the logic behind scikit-learn's
  `permutation_test_score`.
  - **Caveat:** this check catches *pipeline* leakage and overfitting. It does **not**
    catch circular labeling. When labels are computed from the features, the dependency
    between features and labels is real, so the check still passes. Only Tier 1 fixes
    circular labeling.

All metrics are written to `models/evaluation_metrics.json` under `path_a` (with
`candidates`, `decision`, `transformer_baseline`, `shuffle_labels`, and `recall_by_family`)
and `path_b`.

---

## 3. How to run it

```bash
# 1. Prerequisites for Tier 1 to be valid
#    - Turn on NTP / clock sync on the Technitium host and the attacker VM
#    - Capture a benign-only period (browse the nginx store, run dig loops, no attacks)
# 2. Record every attack run in the manifest
cp data/attack_manifest.example.csv data/attack_manifest.csv   # then edit the rows
# 3. Retrain and detect
./scripts/run_all.sh --force-retrain
# 4. (Optional) Run the leakage check
PYTHONPATH=src python -m dns_detect.models.path_a \
    --train data/processed/merged_features_labeled.json --shuffle-labels
```

---

## 4. Before and after (fill these in from `models/evaluation_metrics.json`)

| Metric (held-out test) | Before: heuristic labels, RF+TF | After: manifest labels, RF+GBT |
|------------------------|---------------------------------|--------------------------------|
| Path A PR-AUC (prevalence baseline) | not reported | |
| Path A ROC-AUC | 0.9827 | |
| Path A attack F1 | 0.91 | |
| Path A decision | RF+TF 0.6/0.4 | |
| Transformer baseline AUC | 0.516 | |
| Path B PR-AUC | skipped (single-class test set) | |
| Shuffled-label PR-AUC | not run | |

Expect the headline numbers to **fall** once the labels are independent. The drop is the
honest result: it measures how much of the earlier score came from the circular labels.

---

## 5. Limits of the results

- **Small, single-host dataset.** The current data is about 8K queries from **one client
  IP on one day**. Report the metrics as results on a small single-host lab dataset. Do
  not claim generalization until there is data from several hosts, several days, and
  held-out attack campaigns.
- **Small test set.** The held-out test set is about 1.2K rows, so a small difference
  between RF and RF+GBT may not be statistically meaningful. Use stratified
  cross-validation or a confidence interval before claiming one beats the other. The gate
  breaks ties in favour of the combination.
- **Label quality depends on clocks.** Labels based on time windows are only as accurate
  as the clocks of the hosts involved. Clock drift mislabels queries without any visible
  error.
- **Clients with fewer records than one window** (20 by default) get no Path B score.

---

## References

1. Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022. https://www.usenix.org/system/files/sec22-arp.pdf
2. Sommer & Paxson, *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection*, IEEE S&P 2010. https://www.icir.org/robin/papers/oakland10-ml.pdf
3. Grinsztajn, Oyallon & Varoquaux, *Why do tree-based models still outperform deep learning on tabular data?*, NeurIPS 2022 (arXiv 2207.08815). https://www.alphaxiv.org/abs/2207.08815
4. Gorishniy et al., *Revisiting Deep Learning Models for Tabular Data*, 2021 (arXiv 2106.11959). https://arxiv.org/pdf/2106.11959
5. Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018 (arXiv 1802.09089). https://arxiv.org/pdf/1802.09089
6. Saito & Rehmsmeier, *The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets*, PLoS ONE 2015. https://www.ncbi.nlm.nih.gov/pmc/articles/PMC4349800/
7. UNB CIC-IDS2017 dataset (labeling methodology). https://www.unb.ca/cic/datasets/ids-2017.html
8. HERA network traffic labeling tool (arXiv 2501.07475). https://arxiv.org/pdf/2501.07475
9. scikit-learn, *Test with permutations the significance of a classification score*. https://scikit-learn.org/dev/auto_examples/model_selection/plot_permutation_tests_for_classification.html
10. Gradient boosting compared with RF on intrusion-detection data: arXiv 2607.00763 (CIC-IDS2017), arXiv 2510.17883 (UNSW-NB15), arXiv 2605.13922 (UAVIDS-2025).
11. Autoencoder thresholds set as a percentile of reconstruction error: PMC9103022; arXiv 2512.05069.
12. Sliding windows built per host for sequence anomaly detection: arXiv 1805.03735.
