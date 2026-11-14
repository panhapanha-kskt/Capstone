# Evidence for the Week 5 and Week 6 results

Saved 2026-11-14 05:15 by `scripts/save_evidence.sh` from `runs/` and `logs/` on the training machine.
These are the small files behind the numbers in [V3_BALANCED_TRAINING.md](../V3_BALANCED_TRAINING.md),
[V3_EVALUATION_RESULTS.md](../../Week6/V3_EVALUATION_RESULTS.md) and
[PATH_B_ISOLATION_FOREST.md](../../Week6/PATH_B_ISOLATION_FOREST.md). Model files are not included.

| Folder | Contents |
|---|---|
| `baseline`, `v_dnsshell`, `v_det`, `v3`, `v3_iforest` | each run's `evaluation_metrics.json` (frozen-test results), fusion weights, split, Path B threshold, training metadata; `multiseed_summary.json` (5 seeds) |
| `v3` | also `cv_lofo.json` (leave-one-tool-out), `cic_test_results.csv` (CIC capture 3 scores), key lines of the training log |
| `v3_iforest` | also CIC capture 3 scores and key lines of its training log |
| `v3_pathb_iforest` | the Path B-only Isolation Forest test (65.8 s run) |
| `eval` | the latest `week5_eval.sh` summary and the multi-seed log |
| `unseen_tool` | Week 4 unseen-tool results that survived (det, dns_shell) |

## Unseen-tool CSV check

- `tunnels_det_model_results.csv`: 5000 rows, 5000 flagged as attack (matches the Week 4 unseen-tool result 5,000 / 5,000)
- `tunnels_dns_shell_model_results.csv`: 5000 rows, 5000 flagged as attack (matches the Week 4 unseen-tool result 5,000 / 5,000)

## Files

- baseline/evaluation_metrics.json (6 KB)
- baseline/fusion_lr.json (0 KB)
- baseline/fusion_lr_tiers.json (0 KB)
- baseline/split_manifest.json (655 KB)
- baseline/dns_trafficformer_threshold.json (0 KB)
- baseline/training_metadata.json (3 KB)
- v_dnsshell/evaluation_metrics.json (6 KB)
- v_dnsshell/fusion_lr.json (0 KB)
- v_dnsshell/fusion_lr_tiers.json (0 KB)
- v_dnsshell/split_manifest.json (835 KB)
- v_dnsshell/dns_trafficformer_threshold.json (0 KB)
- v_dnsshell/training_metadata.json (3 KB)
- v_det/evaluation_metrics.json (6 KB)
- v_det/fusion_lr.json (0 KB)
- v_det/fusion_lr_tiers.json (0 KB)
- v_det/split_manifest.json (835 KB)
- v_det/dns_trafficformer_threshold.json (0 KB)
- v_det/training_metadata.json (3 KB)
- v3/evaluation_metrics.json (6 KB)
- v3/fusion_lr.json (0 KB)
- v3/fusion_lr_tiers.json (0 KB)
- v3/split_manifest.json (7823 KB)
- v3/dns_trafficformer_threshold.json (0 KB)
- v3/training_metadata.json (4 KB)
- v3_iforest/evaluation_metrics.json (6 KB)
- v3_iforest/fusion_lr.json (0 KB)
- v3_iforest/fusion_lr_tiers.json (0 KB)
- v3_iforest/split_manifest.json (7823 KB)
- v3_iforest/dns_trafficformer_threshold.json (0 KB)
- v3_iforest/training_metadata.json (4 KB)
- baseline/multiseed_summary.json (1 KB)
- v_dnsshell/multiseed_summary.json (1 KB)
- v_det/multiseed_summary.json (1 KB)
- v3/multiseed_summary.json (1 KB)
- v3/cv_lofo.json (7 KB)
- v3/cic_test_results.csv (6696 KB)
- v3_iforest/cic_test_results.csv (6696 KB)
- v3_pathb_iforest/evaluation_metrics.json (1 KB)
- v3_pathb_iforest/dns_trafficformer_threshold.json (0 KB)
- v3/training_log_summary.txt (key lines of training_20261107_220017.log)
- v3_iforest/training_log_summary.txt (key lines of train_v3_iforest.log)
- eval/week5_eval_summary.txt (2 KB)
- eval/multiseed_all.txt (4 KB)
- unseen_tool/tunnels_det_model_results.csv (1763 KB)
- unseen_tool/tunnels_dns_shell_model_results.csv (1720 KB)
