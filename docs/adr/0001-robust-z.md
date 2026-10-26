# ADR 0001: Median/MAD z-scores for volume anomalies
Status: accepted. Mean/stdev is inflated by the very bursts we look for; MAD is not. Consequence: thresholds are in robust-z units (default 8, tuned on synthetic data only).
