# Saved evaluation results

These CSV files were previously stored in the project root. They are historical
evaluation outputs, not inputs to the detection pipeline.

- `cic_benign_test_model_results.csv`: saved CIC benign test scores.
- `tunnels_det_model_results.csv` and `tunnels_dns_shell_model_results.csv`:
  Week 4 unseen-tool scores. Identical report copies are in
  `docs/Week5/evidence/unseen_tool/`.

Running `path_a --infer` directly still creates a new CSV in the current working
directory. `scripts/week5_eval.sh` moves its generated CIC CSV into the run folder.
