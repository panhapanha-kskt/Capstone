# References

Verifiable bibliography for `RESEARCH_AND_IMPROVEMENT_PLAN.md`, `IMPLEMENTATION_REPORT.md`, `EVALUATION_REPORT.md`, and `docs/Week2/Need-Improve.md`. The canonical list is in `Need-Improve.md §References`; this file reanchors it and adds the 2025 confirmation sources used during this plan.

## Pitfalls and evaluation methodology (core)

- Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Kargl, F., Wressnegger, C., Cavallaro, L., Rieck, K. *Dos and Don'ts of Machine Learning in Computer Security*. USENIX Security 2022. Distinguished Paper Award. https://www.usenix.org/system/files/sec22summer_arp.pdf · arXiv (preprint v2 2021-11-30): https://arxiv.org/abs/2010.09470 · CACM 2024 highlight: https://cacm.acm.org/research-highlights/pitfalls-in-machine-learning-for-computer-security/
- Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., Cavallaro, L. *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time*. USENIX Security 2019. https://arxiv.org/abs/1807.07838 · extended: https://arxiv.org/pdf/2402.01359
- Axelsson, S. *The Base-Rate Fallacy and the Difficulty of Intrusion Detection*. https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf
- *Base-Rate Fallacy Redux and a Deep Dive Review in Cybersecurity*. https://arxiv.org/pdf/2203.08801
- *Unmasking Shortcut Learning in IoT Intrusion Detection*. https://arxiv.org/pdf/2609.28725
- *Network Intrusion Datasets: A Survey, Limitations, and Recommendations*. https://arxiv.org/pdf/2502.06688
- *ICS Cybersecurity Datasets: A Systematic Meta-Review*. https://arxiv.org/pdf/2608.24757
- Engelen, G., Rimmer, V., Joosen, W. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*. https://intrusion-detection.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf
- *Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes*. https://dl.acm.org/doi/10.1007/978-3-031-31108-6_2
- Northcutt, C., Jiang, L., Chuang, I. *Confident Learning: Estimating Uncertainty in Dataset Labels*. https://arxiv.org/pdf/1911.00068 (cleanlab)
- Gebru, T. et al. *Datasheets for Datasets*. https://arxiv.org/abs/1803.09010v1
- Ratner, A., Bach, S. H., Ehrenberg, H., Fries, J., Wu, S., Ré, C. *Snorkel*. VLDB 2018. https://www.vldb.org/pvldb/vol11/p269-ratner.pdf

## DNS tunneling and exfiltration detection (domain references)

- Farnham, G. *Detecting DNS Tunneling*. SANS Institute, 2013. https://www.sans.org/white-papers/34152
- Nadler, A., Aminov, A., Shabtai, A. *Detection of Malicious and Low Throughput Data Exfiltration Over the DNS Protocol*. Computers & Security, 2019. https://arxiv.org/pdf/1709.08395
- Ozery, Y., Nadler, A., Shabtai, A. *Information-Based Heavy Hitters for Real-Time DNS Data Exfiltration Detection*. NDSS 2024. https://www.ndss-symposium.org/wp-content/uploads/2024-388-paper.pdf
- Elastic Security Labs. *Plight at the end of the tunnel*. https://www.elastic.co/blog/plight-end-tunnel

## 2024–2026 confirmation pass (web search, Oct–Dec 2025)

- *DNS-HyXNet*, Dec 2025 preprint. https://arxiv.org/html/2512.09565v1 — recent DNS-tunneling classifier; split methodology not fully documented.
- *Evasion-Resilient Detection of DNS-over-HTTPS Data Exfiltration: A Practical Evaluation and Toolkit*, Dec 2025. https://arxiv.deeppaper.ai/papers/2512.20423v1 — adversarial evaluation of DoH exfiltration detectors.
- Amirov et al. *Detecting DNS Tunneling-Based Data Exfiltration Using ML*, July 2025. https://web3.arxiv.org/abs/2507.10267 — classical-ML comparison; limited split-protocol detail.
- *Towards a Near-real-time Protocol Tunneling Detector based on ML* (arXiv 2309.12720).

## Fusion and bridge (Stacker V2 / Bridge V2)

Used by `STACKER_V2_IMPLEMENTATION_REPORT.md` and `BRIDGE_V2_IMPLEMENTATION_REPORT.md`. (Snorkel and confident learning /
cleanlab, also cited there, are listed above under *Pitfalls and evaluation methodology*.) The bridge audit's
"references 13–15" were not available in the repository; the sources below are the ones the implementation relies on.

- Tong, X., Feng, Y., Li, J. J. *Neyman-Pearson classification algorithms and NP receiver operating characteristics*. Science Advances 4(2), eaao1659, 2018. https://doi.org/10.1126/sciadv.aao1659 — umbrella algorithm behind `thresholds.np_threshold`.
- Wolpert, D. H. *Stacked generalization*. Neural Networks 5(2), 241–259, 1992. https://doi.org/10.1016/S0893-6080(05)80023-1 — fitting a combiner on predictions the base models did not train on.
- Niculescu-Mizil, A., Caruana, R. *Predicting good probabilities with supervised learning*. ICML 2005. https://doi.org/10.1145/1102351.1102430 — reliability diagrams, isotonic / Platt calibration.
- Guo, C., Pleiss, G., Sun, Y., Weinberger, K. Q. *On calibration of modern neural networks*. ICML 2017. https://arxiv.org/abs/1706.04599 — expected calibration error (ECE).
- Brier, G. W. *Verification of forecasts expressed in terms of probability*. Monthly Weather Review 78(1), 1–3, 1950. https://doi.org/10.1175/1520-0493(1950)078%3C0001:VOFEIT%3E2.0.CO;2 — Brier score.
- Wilson, E. B. *Probable inference, the law of succession, and statistical inference*. JASA 22(158), 209–212, 1927. https://doi.org/10.1080/01621459.1927.10502953 — score interval used for FPR / recall CIs.
- King, G., Zeng, L. *Logistic regression in rare events data*. Political Analysis 9(2), 137–163, 2001. https://doi.org/10.1093/oxfordjournals.pan.a004868 — prior correction for class-weighted logistic regression (considered, not applied: no measured deployment prevalence).
- scikit-learn. `StratifiedGroupKFold`. https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html · `LogisticRegression`. https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html

## Protocols and standards

- RFC 1034 — *Domain names — concepts and facilities*. https://www.rfc-editor.org/rfc/rfc1034
- RFC 1035 — *Domain names — implementation and specification*. https://www.rfc-editor.org/rfc/rfc1035
- RFC 7858 — *DNS over TLS*. https://www.rfc-editor.org/rfc/rfc7858
- RFC 8484 — *DNS Queries over HTTPS (DoH)*. https://www.rfc-editor.org/rfc/rfc8484
- MITRE ATT&CK T1071.004 — *Application Layer Protocol: DNS*. https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK T1048 — *Exfiltration Over Alternative Protocol*. https://attack.mitre.org/techniques/T1048/

## Datasets

- CIC-Bell-DNS-EXF-2021. https://www.unb.ca/cic/datasets/dns-exf-2021.html — targeted for N6 external validation; staged by a follow-up iteration.

## Teaching references used in Need-Improve.md

- Stanford CS229 / CS230 cheat sheets (project skill `dns-ml-tuning`): bias/variance diagnosis, k-fold cross-validation, ablative and error analysis.

## Reproducibility tooling (optional / future)

- DVC data versioning. https://oneuptime.com/blog/post/2026-01-25-dvc-data-versioning/view
- Dataset lineage practice. https://dev.to/beefedai/implementing-dataset-versioning-and-lineage-for-reproducible-ml-3n7l
