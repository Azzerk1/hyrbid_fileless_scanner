"""
validate_if.py
==============
Verifies the quality of a trained Isolation Forest model without ground-truth
labels, using the synthetic dataset the model was trained on.

Since the model is unsupervised, "accuracy" is not a single number.
Instead this script answers four concrete questions:

  Q1  Score separation — are anomaly-indicator rows scored differently
      from clearly-normal rows?  (the core validity check)

  Q2  Anomaly feature correlation — when the model flags a row, does it
      tend to have anomalous feature values?  (flag quality check)

  Q3  Score distribution — what does the full score histogram look like?
      (bimodal = model has found a real separation)

  Q4  Threshold sensitivity — how does flag rate change if you adjust the
      contamination threshold?  (robustness check)

Usage
-----
    python validate_if.py \\
        --model  models/if_model.pkl \\
        --data   synthetic_data.csv \\
        [--top   20]          # show top-N most anomalous rows

Output
------
Printed report + summary verdict.  No files are written.

Requirements
------------
    pip install scikit-learn joblib numpy pandas
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

try:
    import joblib
except ImportError:
    print("ERROR: pip install scikit-learn joblib numpy pandas")
    sys.exit(1)


MISSING       = -1
IMPUTE_VALUE  = 0.0   # same as train_if.py

# Rows with ANY of these features set are considered "known anomalous"
# (these are the features synth_gen injects extreme values into).
ANOMALY_INDICATORS = {
    "has_mz_header":                lambda v: v >= 1,
    "has_pe_header":                lambda v: v >= 1,
    "entropy_max":                  lambda v: v > 6.5,
    "cross_process_writes_count":   lambda v: v >= 5,
    "api_writeprocessmemory_count": lambda v: v >= 8,
    "num_executable_regions":       lambda v: v >= 4,
    "api_createremotethread_count": lambda v: v >= 1,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_and_prepare(model_dir: str, csv_path: str):
    model_path   = os.path.join(model_dir, "if_model.pkl")
    scaler_path  = os.path.join(model_dir, "if_scaler.pkl")
    feature_path = os.path.join(model_dir, "if_features.json")

    for p in (model_path, scaler_path, feature_path):
        if not os.path.isfile(p):
            print(f"ERROR: {p} not found. Train first with train_if.py.")
            sys.exit(1)

    model   = joblib.load(model_path)
    scaler  = joblib.load(scaler_path)
    with open(feature_path) as fh:
        features = json.load(fh)

    df_raw = pd.read_csv(csv_path)
    df = df_raw.copy()

    # Drop meta cols, keep only training features (same as train_if.py)
    meta = [c for c in df.columns if c.startswith("meta_")]
    df   = df.drop(columns=[c for c in meta if c in df.columns])
    df   = df[[f for f in features if f in df.columns]]

    # Impute missing sentinel
    for col in df.columns:
        df.loc[df[col] == MISSING, col] = IMPUTE_VALUE

    X_scaled = scaler.transform(df.values.astype(float))

    return model, scaler, features, df_raw, df, X_scaled


def sep(char="─", n=64):
    return char * n


# ---------------------------------------------------------------------------
# Q1 — Score separation
# ---------------------------------------------------------------------------

def q1_score_separation(df_raw, scores, preds):
    print(f"\n{sep()}")
    print("  Q1 — SCORE SEPARATION")
    print(f"  (Do indicator-positive rows score lower than indicator-negative?)")
    print(sep("─"))

    results = []
    for col, condition in ANOMALY_INDICATORS.items():
        if col not in df_raw.columns:
            continue
        pos_mask = df_raw[col].apply(
            lambda v: condition(float(v)) if v != MISSING else False
        )
        neg_mask = ~pos_mask

        pos_scores = scores[pos_mask.values]
        neg_scores = scores[neg_mask.values]

        if len(pos_scores) == 0:
            continue

        sep_gap = neg_scores.mean() - pos_scores.mean()
        results.append((col, len(pos_scores), pos_scores.mean(),
                        neg_scores.mean(), sep_gap))

    print(f"  {'Feature':<35} {'N anom':>7} {'anom score':>11} "
          f"{'normal score':>13} {'gap':>8}  {'verdict'}")
    print(f"  {'-'*90}")
    for col, n, anom_m, norm_m, gap in sorted(results, key=lambda x: -x[4]):
        verdict = "GOOD ✓" if gap > 0.02 else ("WEAK" if gap > 0 else "FAIL ✗")
        print(f"  {col:<35} {n:>7} {anom_m:>11.4f} {norm_m:>13.4f} "
              f"{gap:>8.4f}  {verdict}")

    good = sum(1 for *_, gap, __ in results if gap > 0.02)
    print(f"\n  {good}/{len(results)} features show clear separation (gap > 0.02)")
    if good == len(results):
        print("  → Excellent: model separates all anomaly indicators correctly.")
    elif good >= len(results) * 0.6:
        print("  → Good: model finds most anomaly indicators.")
    else:
        print("  → Weak: retrain with more diverse data or adjust contamination.")


# ---------------------------------------------------------------------------
# Q2 — Flag quality
# ---------------------------------------------------------------------------

def q2_flag_quality(df_raw, scores, preds):
    print(f"\n{sep()}")
    print("  Q2 — FLAG QUALITY")
    print(f"  (When the model flags a row, does it have anomalous features?)")
    print(sep("─"))

    flagged   = preds == -1
    unflagged = preds == 1

    n_flagged = flagged.sum()
    if n_flagged == 0:
        print("  No rows flagged — lower contamination or check model.")
        return

    # For each indicator, what % of flagged rows meet the condition?
    print(f"  {'Feature':<35} {'% of flagged rows':>20} {'% of normal rows':>18}")
    print(f"  {'-'*76}")
    for col, condition in ANOMALY_INDICATORS.items():
        if col not in df_raw.columns:
            continue
        col_vals = df_raw[col].astype(float)
        indicator = col_vals.apply(
            lambda v: condition(v) if v != MISSING else False
        ).values

        pct_flagged  = indicator[flagged].mean()  * 100
        pct_normal   = indicator[unflagged].mean() * 100
        enrichment   = pct_flagged / max(pct_normal, 0.01)
        tag = f"  {enrichment:.1f}x enriched" if enrichment > 2 else ""
        print(f"  {col:<35} {pct_flagged:>19.1f}% {pct_normal:>17.1f}%{tag}")

    # Any-indicator presence in flagged vs unflagged
    any_indicator = pd.Series(False, index=df_raw.index)
    for col, condition in ANOMALY_INDICATORS.items():
        if col in df_raw.columns:
            any_indicator |= df_raw[col].astype(float).apply(
                lambda v: condition(v) if v != MISSING else False
            )

    pct_flagged_any  = any_indicator.values[flagged].mean()  * 100
    pct_unflagged_any = any_indicator.values[unflagged].mean() * 100
    print(f"\n  Rows with ANY anomaly indicator:")
    print(f"    In flagged rows  : {pct_flagged_any:.1f}%")
    print(f"    In normal rows   : {pct_unflagged_any:.1f}%")
    if pct_flagged_any > pct_unflagged_any * 2:
        print("  → Flags are enriched in anomalous rows. Flag quality: GOOD ✓")
    else:
        print("  → Flags not concentrated in anomalous rows. Quality: WEAK")


# ---------------------------------------------------------------------------
# Q3 — Score distribution
# ---------------------------------------------------------------------------

def q3_score_distribution(scores, preds):
    print(f"\n{sep()}")
    print("  Q3 — SCORE DISTRIBUTION")
    print(f"  (Bimodal = clear normal / anomaly clusters)")
    print(sep("─"))

    flagged   = scores[preds == -1]
    unflagged = scores[preds == 1]

    print(f"\n  All scores (n={len(scores)})")
    print(f"    min    : {scores.min():.4f}")
    print(f"    p5     : {np.percentile(scores, 5):.4f}")
    print(f"    p25    : {np.percentile(scores, 25):.4f}")
    print(f"    median : {np.median(scores):.4f}")
    print(f"    p75    : {np.percentile(scores, 75):.4f}")
    print(f"    p95    : {np.percentile(scores, 95):.4f}")
    print(f"    max    : {scores.max():.4f}")

    print(f"\n  Normal rows  (n={len(unflagged)})")
    print(f"    mean   : {unflagged.mean():.4f}    std: {unflagged.std():.4f}")
    print(f"    range  : [{unflagged.min():.4f}, {unflagged.max():.4f}]")

    if len(flagged):
        print(f"\n  Flagged rows (n={len(flagged)})")
        print(f"    mean   : {flagged.mean():.4f}    std: {flagged.std():.4f}")
        print(f"    range  : [{flagged.min():.4f}, {flagged.max():.4f}]")

        separation = unflagged.mean() - flagged.mean()
        overlap    = (flagged.max() > unflagged.min())
        print(f"\n  Mean separation : {separation:.4f}")
        if separation > 0.05:
            print("  → Clear score gap. Distribution looks BIMODAL ✓")
        elif separation > 0.01:
            print("  → Moderate separation. More training data would help.")
        else:
            print("  → Scores overlap heavily — model may not have found a real boundary.")

    # ASCII histogram
    print(f"\n  Score histogram (all rows):")
    min_s, max_s = scores.min(), scores.max()
    bins = np.linspace(min_s, max_s, 21)
    hist, edges = np.histogram(scores, bins=bins)
    bar_max = hist.max()
    for i, count in enumerate(hist):
        bar_len = int(count / bar_max * 40) if bar_max > 0 else 0
        marker  = "▓" if edges[i] < 0 else "░"
        print(f"  {edges[i]:>7.3f} │ {marker * bar_len} {count}")
    print(f"  {'▓':>10} = anomaly score range  ░ = normal score range")


# ---------------------------------------------------------------------------
# Q4 — Threshold sensitivity
# ---------------------------------------------------------------------------

def q4_threshold_sensitivity(scores):
    print(f"\n{sep()}")
    print("  Q4 — THRESHOLD SENSITIVITY")
    print(f"  (How does flag rate vary with contamination?)")
    print(sep("─"))
    print(f"\n  {'contamination':>15} {'threshold':>11} {'flagged':>9} {'flag rate':>11}")
    print(f"  {'-'*50}")
    for cont in (0.01, 0.02, 0.03, 0.05, 0.07, 0.10):
        threshold  = np.percentile(scores, cont * 100)
        n_flagged  = (scores <= threshold).sum()
        flag_rate  = n_flagged / len(scores) * 100
        print(f"  {cont:>15.2f} {threshold:>11.4f} {n_flagged:>9} {flag_rate:>10.1f}%")
    print(f"\n  Your trained contamination={0.02} flags the bottom {0.02*100:.0f}% of scores.")
    print(f"  Adjust if you see too many / too few flags on real scans.")


# ---------------------------------------------------------------------------
# Top N most anomalous rows
# ---------------------------------------------------------------------------

def show_top_anomalous(df_raw, scores, features, top_n: int):
    print(f"\n{sep()}")
    print(f"  TOP {top_n} MOST ANOMALOUS ROWS")
    print(sep("─"))
    idx_sorted = np.argsort(scores)[:top_n]
    key_cols = [c for c in ANOMALY_INDICATORS if c in df_raw.columns]
    for rank, idx in enumerate(idx_sorted, 1):
        row = df_raw.iloc[idx]
        proc = row.get("meta_process_name", "unknown")
        s    = scores[idx]
        flags = [c for c in key_cols
                 if ANOMALY_INDICATORS[c](float(row.get(c, 0))
                    if row.get(c, MISSING) != MISSING else 0)]
        print(f"\n  #{rank:<3} score={s:.4f}  process={proc}")
        if flags:
            for f in flags:
                print(f"       [!] {f} = {row.get(f, '?')}")
        else:
            print(f"       (no obvious anomaly indicators — IF found structural isolation)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Validate trained IF model quality.")
    parser.add_argument("--model", required=True,
                        help="Directory containing if_model.pkl, if_scaler.pkl, if_features.json")
    parser.add_argument("--data",  required=True, help="Path to synthetic_data.csv")
    parser.add_argument("--top",   type=int, default=10,
                        help="Number of most anomalous rows to display (default 10)")
    args = parser.parse_args()

    print(f"\n{'=' * 64}")
    print(f"  ISOLATION FOREST MODEL VALIDATION")
    print(f"{'=' * 64}")
    print(f"  Model dir : {args.model}")
    print(f"  Data      : {args.data}")

    model, scaler, features, df_raw, df, X_scaled = load_and_prepare(
        args.model, args.data
    )
    print(f"  Rows      : {len(df_raw)}")
    print(f"  Features  : {len(features)}")
    print(f"  Trees     : {model.n_estimators}")
    print(f"  Contam.   : {model.contamination}")

    scores = model.decision_function(X_scaled)   # more negative = more anomalous
    preds  = model.predict(X_scaled)              # -1 = anomaly, 1 = normal

    flagged = (preds == -1).sum()
    print(f"\n  Flagged   : {flagged} / {len(preds)}  ({flagged/len(preds)*100:.1f}%)")

    q1_score_separation(df_raw, scores, preds)
    q2_flag_quality(df_raw, scores, preds)
    q3_score_distribution(scores, preds)
    q4_threshold_sensitivity(scores)
    show_top_anomalous(df_raw, scores, features, args.top)

    print(f"\n{'=' * 64}")
    print("  VALIDATION COMPLETE")
    print(f"{'=' * 64}\n")


if __name__ == "__main__":
    main()