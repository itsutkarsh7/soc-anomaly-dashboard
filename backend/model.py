"""
ZeTheta Anomaly Detection System — Full ML Engine
Models: Isolation Forest + LOF + XGBoost + Random Forest + Logistic Regression
        + DBSCAN + ECOD + COPOD + Z-Score + Modified Z-Score + IQR
Features: Velocity checks, trading fraud patterns, score calibration
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neighbors import LocalOutlierFactor
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, precision_score, recall_score
from pyod.models.ecod import ECOD
from pyod.models.copod import COPOD
import xgboost as xgb
import joblib
import os
import warnings
warnings.filterwarnings("ignore")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_model.pkl")

# ── 1. DATA GENERATION (Kaggle creditcard.csv style) ─────────────────────────
def generate_training_data(n_samples=12000, fraud_ratio=0.02):
    np.random.seed(42)
    n_fraud  = int(n_samples * fraud_ratio)
    n_normal = n_samples - n_fraud

    # Normal transactions
    normal_pca     = np.random.randn(n_normal, 28)
    normal_amounts = np.random.lognormal(3.5, 1.2, n_normal).clip(0.5, 5000)
    normal_times   = np.sort(np.random.uniform(0, 172800, n_normal))

    # Fraud transactions
    fraud_pca = np.random.randn(n_fraud, 28)
    fraud_pca[:, 0]  += np.random.uniform(-6, -2, n_fraud)
    fraud_pca[:, 1]  += np.random.uniform(2,  5,  n_fraud)
    fraud_pca[:, 3]  += np.random.uniform(-5, -1, n_fraud)
    fraud_pca[:, 9]  += np.random.uniform(3,  7,  n_fraud)
    fraud_pca[:, 11] += np.random.uniform(-8, -3, n_fraud)
    fraud_pca[:, 13] += np.random.uniform(-7, -2, n_fraud)
    fraud_pca[:, 16] += np.random.uniform(-5, -1, n_fraud)
    fraud_amounts = np.random.lognormal(4.5, 1.5, n_fraud).clip(1, 10000)
    fraud_times   = np.random.uniform(0, 172800, n_fraud)

    X_normal = np.column_stack([normal_pca, normal_amounts, normal_times])
    X_fraud  = np.column_stack([fraud_pca,  fraud_amounts,  fraud_times])

    X = np.vstack([X_normal, X_fraud])
    y = np.array([0]*n_normal + [1]*n_fraud)

    cols = [f"V{i}" for i in range(1, 29)] + ["Amount", "Time"]
    df = pd.DataFrame(X, columns=cols)
    df["Class"] = y
    return df


# ── 2. FEATURE ENGINEERING ────────────────────────────────────────────────────
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    feat   = df.copy()
    v_cols = [f"V{i}" for i in range(1, 29)]

    # Basic PCA statistics
    feat["amount_log"]        = np.log1p(feat["Amount"])
    feat["pca_mean"]          = feat[v_cols].mean(axis=1)
    feat["pca_std"]           = feat[v_cols].std(axis=1)
    feat["pca_max_abs"]       = feat[v_cols].abs().max(axis=1)
    feat["pca_min"]           = feat[v_cols].min(axis=1)

    # Interaction features
    feat["v1_v2_interaction"] = feat["V1"] * feat["V2"]
    feat["v14_v17_ratio"]     = feat["V14"] / (feat["V17"].abs() + 1e-5)
    feat["v3_v4_product"]     = feat["V3"] * feat["V4"]
    feat["v10_v12_sum"]       = feat["V10"] + feat["V12"]

    # Statistical Z-score (Modified Z-score uses MAD)
    amt_mean = feat["Amount"].mean() if len(feat) > 1 else 50.0
    amt_std  = feat["Amount"].std()  if len(feat) > 1 else 1.0
    feat["amount_zscore"] = (feat["Amount"] - amt_mean) / (amt_std + 1e-5)

    # Modified Z-Score (robust, uses median + MAD)
    amt_median = feat["Amount"].median() if len(feat) > 1 else 50.0
    amt_mad    = (feat["Amount"] - amt_median).abs().median() if len(feat) > 1 else 1.0
    feat["amount_mod_zscore"] = 0.6745 * (feat["Amount"] - amt_median) / (amt_mad + 1e-5)

    # IQR outlier flag
    Q1 = feat["Amount"].quantile(0.25) if len(feat) > 1 else 10.0
    Q3 = feat["Amount"].quantile(0.75) if len(feat) > 1 else 200.0
    IQR = Q3 - Q1
    feat["amount_iqr_outlier"] = (
        (feat["Amount"] < Q1 - 1.5 * IQR) |
        (feat["Amount"] > Q3 + 1.5 * IQR)
    ).astype(float)

    # Temporal features (velocity checks)
    if "Time" in feat.columns:
        feat["hour_of_day"] = (feat["Time"] % 86400) / 3600
        feat["is_night"]    = ((feat["hour_of_day"] < 6) | (feat["hour_of_day"] > 22)).astype(float)
    else:
        feat["hour_of_day"] = 12.0
        feat["is_night"]    = 0.0

    # Trading fraud pattern features
    feat["v1_extreme"]  = (feat["V1"].abs() > 4).astype(float)   # front-running signal
    feat["v14_extreme"] = (feat["V14"].abs() > 5).astype(float)  # spoofing signal
    feat["v12_extreme"] = (feat["V12"].abs() > 5).astype(float)  # layering signal
    feat["high_amount"] = (feat["Amount"] > 1000).astype(float)  # large transaction flag
    feat["low_amount"]  = (feat["Amount"] < 1).astype(float)     # micro-transaction flag (test transaction)

    feat = feat.fillna(0.0).replace([np.inf, -np.inf], 0.0)
    return feat


def get_feature_cols():
    v_cols = [f"V{i}" for i in range(1, 29)]
    return v_cols + [
        "Amount", "amount_log", "pca_mean", "pca_std", "pca_max_abs", "pca_min",
        "v1_v2_interaction", "v14_v17_ratio", "v3_v4_product", "v10_v12_sum",
        "amount_zscore", "amount_mod_zscore", "amount_iqr_outlier",
        "hour_of_day", "is_night",
        "v1_extreme", "v14_extreme", "v12_extreme", "high_amount", "low_amount"
    ]


# ── 3. STATISTICAL DETECTION ──────────────────────────────────────────────────
class StatisticalDetector:
    """Z-Score, Modified Z-Score, and IQR outlier detection"""
    def __init__(self):
        self.stats = {}

    def fit(self, df: pd.DataFrame):
        amounts = df["Amount"].values
        self.stats["mean"]   = float(np.mean(amounts))
        self.stats["std"]    = float(np.std(amounts))
        self.stats["median"] = float(np.median(amounts))
        self.stats["mad"]    = float(np.median(np.abs(amounts - np.median(amounts))))
        self.stats["q1"]     = float(np.percentile(amounts, 25))
        self.stats["q3"]     = float(np.percentile(amounts, 75))
        self.stats["iqr"]    = self.stats["q3"] - self.stats["q1"]

        # Per-feature Z-score stats for V1-V28
        v_cols = [f"V{i}" for i in range(1, 29)]
        self.stats["v_means"] = df[v_cols].mean().values
        self.stats["v_stds"]  = df[v_cols].std().values + 1e-5

    def score(self, transaction: dict) -> dict:
        amount = transaction.get("Amount", 50.0)
        s = self.stats

        # Standard Z-Score
        zscore = abs((amount - s["mean"]) / (s["std"] + 1e-5))

        # Modified Z-Score (robust)
        mod_zscore = abs(0.6745 * (amount - s["median"]) / (s["mad"] + 1e-5))

        # IQR check
        iqr_outlier = (amount < s["q1"] - 1.5 * s["iqr"]) or (amount > s["q3"] + 1.5 * s["iqr"])

        # PCA feature Z-scores
        v_cols = [f"V{i}" for i in range(1, 29)]
        v_vals = np.array([transaction.get(c, 0.0) for c in v_cols])
        v_zscores = np.abs((v_vals - s["v_means"]) / s["v_stds"])
        max_v_zscore = float(np.max(v_zscores))
        extreme_features = [v_cols[i] for i in np.where(v_zscores > 3)[0]]

        stat_score = min(1.0, (zscore / 5.0) * 0.4 +
                              (mod_zscore / 5.0) * 0.3 +
                              float(iqr_outlier) * 0.15 +
                              (max_v_zscore / 8.0) * 0.15)

        return {
            "stat_score":      round(float(np.clip(stat_score, 0, 1)), 4),
            "zscore":          round(zscore, 4),
            "mod_zscore":      round(mod_zscore, 4),
            "iqr_outlier":     iqr_outlier,
            "max_v_zscore":    round(max_v_zscore, 4),
            "extreme_features": extreme_features[:3],
        }


# ── 4. VELOCITY CHECKER ───────────────────────────────────────────────────────
class VelocityChecker:
    """
    Detects unusual transaction frequency patterns.
    In real systems this would query a time-series DB;
    here we simulate it with statistical analysis.
    """
    def __init__(self):
        self.normal_velocity = {
            "avg_per_hour":    2.5,
            "max_per_hour":    8.0,
            "avg_gap_seconds": 1440.0,
        }

    def fit(self, df: pd.DataFrame):
        if "Time" in df.columns:
            times = np.sort(df["Time"].values)
            gaps  = np.diff(times)
            if len(gaps) > 0:
                self.normal_velocity["avg_gap_seconds"] = float(np.median(gaps))
                self.normal_velocity["avg_per_hour"]    = 3600.0 / max(float(np.median(gaps)), 1)
                self.normal_velocity["max_per_hour"]    = float(np.percentile(3600.0 / (gaps + 1), 95))

    def score(self, transaction: dict, simulated_recent: int = None) -> dict:
        if simulated_recent is None:
            simulated_recent = int(np.random.poisson(self.normal_velocity["avg_per_hour"]))

        velocity_ratio = simulated_recent / max(self.normal_velocity["avg_per_hour"], 0.1)
        velocity_score = float(np.clip((velocity_ratio - 1.0) / 3.0, 0, 1))

        hour = transaction.get("hour_of_day", 12)
        is_unusual_time = hour < 2 or hour > 23
        time_penalty = 0.2 if is_unusual_time else 0.0

        final = float(np.clip(velocity_score + time_penalty, 0, 1))

        return {
            "velocity_score":    round(final, 4),
            "recent_txn_count":  simulated_recent,
            "normal_rate":       round(self.normal_velocity["avg_per_hour"], 2),
            "is_unusual_time":   is_unusual_time,
        }


# ── 5. TRADING FRAUD PATTERN DETECTOR ────────────────────────────────────────
class TradingFraudDetector:
    """
    Detects specific trading manipulation patterns:
    - Front-running: trading ahead of known orders
    - Spoofing: placing/canceling orders to manipulate price
    - Layering: multiple orders creating false impression
    - Wash trading: simultaneous buy/sell to generate volume
    """
    def __init__(self):
        self.thresholds = {
            "front_running_v1": -3.5,
            "spoofing_v14":     -4.0,
            "layering_v12":     -4.0,
            "wash_v3":           3.0,
        }

    def fit(self, df: pd.DataFrame):
        # Learn thresholds from training data
        for col, default_thresh in [("V1", -3.5), ("V14", -4.0), ("V12", -4.0)]:
            if col in df.columns:
                p5 = float(df[col].quantile(0.05))
                self.thresholds[f"{col}_thresh"] = min(p5, default_thresh)

    def score(self, transaction: dict) -> dict:
        v1  = transaction.get("V1",  0.0)
        v12 = transaction.get("V12", 0.0)
        v14 = transaction.get("V14", 0.0)
        v3  = transaction.get("V3",  0.0)
        amt = transaction.get("Amount", 50.0)

        # Front-running: V1 strongly negative + high amount
        front_running = max(0, (-v1 - 2) / 4.0) * (1.2 if amt > 500 else 1.0)

        # Spoofing: V14 strongly negative
        spoofing = max(0, (-v14 - 2) / 5.0)

        # Layering: V12 strongly negative
        layering = max(0, (-v12 - 2) / 6.0)

        # Wash trading: V3 extreme in either direction
        wash = max(0, (abs(v3) - 2) / 3.0)

        # Micro-transaction (test transaction before larger fraud)
        micro_test = 1.0 if amt < 2.0 else 0.0

        pattern_score = float(np.clip(
            0.30 * front_running +
            0.25 * spoofing +
            0.25 * layering +
            0.10 * wash +
            0.10 * micro_test,
            0, 1
        ))

        patterns = []
        if front_running > 0.5: patterns.append("Front-running pattern detected")
        if spoofing > 0.5:      patterns.append("Spoofing pattern detected (V14 anomaly)")
        if layering > 0.5:      patterns.append("Layering pattern detected (V12 anomaly)")
        if wash > 0.5:          patterns.append("Wash trading signal (V3 anomaly)")
        if micro_test:          patterns.append("Micro-test transaction (possible probe)")

        return {
            "trading_score":    round(pattern_score, 4),
            "front_running":    round(float(np.clip(front_running, 0, 1)), 4),
            "spoofing":         round(float(np.clip(spoofing, 0, 1)), 4),
            "layering":         round(float(np.clip(layering, 0, 1)), 4),
            "wash_trading":     round(float(np.clip(wash, 0, 1)), 4),
            "patterns_detected": patterns,
        }


# ── 6. FULL ENSEMBLE DETECTOR ─────────────────────────────────────────────────
class EnsembleAnomalyDetector:
    def __init__(self):
        # Unsupervised
        self.iso_forest = IsolationForest(
            n_estimators=200, contamination=0.02, random_state=42, n_jobs=-1)
        self.lof = LocalOutlierFactor(
            n_neighbors=20, contamination=0.02, novelty=True, n_jobs=-1)
        self.ecod  = ECOD(contamination=0.02)
        self.copod = COPOD(contamination=0.02)

        # Supervised
        self.xgb_model = None
        self.rf_model  = None
        self.lr_model  = None

        # Clustering
        self.dbscan = DBSCAN(eps=1.5, min_samples=5, n_jobs=-1)
        self.dbscan_center = None

        # Statistical + domain
        self.stat_detector    = StatisticalDetector()
        self.velocity_checker = VelocityChecker()
        self.trading_detector = TradingFraudDetector()

        self.scaler       = StandardScaler()
        self.feature_cols = get_feature_cols()
        self.trained      = False

        # Performance metrics
        self.metrics = {}

    def fit(self, df: pd.DataFrame):
        df_feat  = engineer_features(df)
        X        = df_feat[self.feature_cols].values
        X_scaled = self.scaler.fit_transform(X)
        y        = df["Class"].values

        # ── Unsupervised ──────────────────────────────────────────
        print("  [1/8] Training Isolation Forest...")
        self.iso_forest.fit(X_scaled)

        print("  [2/8] Training Local Outlier Factor...")
        self.lof.fit(X_scaled)

        print("  [3/8] Training ECOD (PyOD)...")
        self.ecod.fit(X_scaled)

        print("  [4/8] Training COPOD (PyOD)...")
        self.copod.fit(X_scaled)

        # ── Supervised ───────────────────────────────────────────
        scale_pos = int((y == 0).sum() / max((y == 1).sum(), 1))
        print(f"  [5/8] Training XGBoost (scale_pos_weight={scale_pos})...")
        self.xgb_model = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            scale_pos_weight=scale_pos, eval_metric="logloss",
            random_state=42, verbosity=0)
        self.xgb_model.fit(X_scaled, y)

        print("  [6/8] Training Random Forest...")
        self.rf_model = RandomForestClassifier(
            n_estimators=200, max_depth=10, class_weight="balanced",
            random_state=42, n_jobs=-1)
        self.rf_model.fit(X_scaled, y)

        print("  [7/8] Training Logistic Regression...")
        base_lr = LogisticRegression(
            class_weight="balanced", max_iter=1000, random_state=42, C=1.0)
        self.lr_model = CalibratedClassifierCV(base_lr, cv=3, method="isotonic")
        self.lr_model.fit(X_scaled, y)

        # ── Clustering (DBSCAN) ──────────────────────────────────
        print("  [8/8] Training DBSCAN clustering...")
        # Use subset for speed
        idx = np.random.choice(len(X_scaled), min(3000, len(X_scaled)), replace=False)
        X_sub = X_scaled[idx]
        labels = self.dbscan.fit_predict(X_sub)
        normal_mask = labels != -1
        if normal_mask.sum() > 0:
            self.dbscan_center = X_sub[normal_mask].mean(axis=0)
        else:
            self.dbscan_center = X_sub.mean(axis=0)

        # ── Domain detectors ─────────────────────────────────────
        self.stat_detector.fit(df)
        self.velocity_checker.fit(df)
        self.trading_detector.fit(df)

        # ── Evaluate on training data ─────────────────────────────
        xgb_preds = self.xgb_model.predict(X_scaled)
        self.metrics = {
            "xgb_precision": round(float(precision_score(y, xgb_preds, zero_division=0)), 4),
            "xgb_recall":    round(float(recall_score(y, xgb_preds, zero_division=0)), 4),
        }

        self.trained = True
        print("✅ All 8 models trained successfully")
        print(f"   XGBoost → Precision: {self.metrics['xgb_precision']}, Recall: {self.metrics['xgb_recall']}")

    def predict_score(self, transaction: dict) -> dict:
        v_cols = [f"V{i}" for i in range(1, 29)]
        row    = {c: float(transaction.get(c, np.random.randn())) for c in v_cols}
        row["Amount"] = float(transaction.get("Amount", 50.0))
        row["Time"]   = float(transaction.get("Time", 43200.0))

        df_row   = pd.DataFrame([row])
        df_feat  = engineer_features(df_row)
        X        = df_feat[self.feature_cols].values
        X_scaled = self.scaler.transform(X)

        # ── Model scores ──────────────────────────────────────────

        # 1. Isolation Forest
        iso_raw   = float(self.iso_forest.score_samples(X_scaled)[0])
        iso_score = float(np.clip(1 - (iso_raw + 0.7) / 0.8, 0, 1))

        # 2. LOF
        lof_raw   = float(self.lof.score_samples(X_scaled)[0])
        lof_score = float(np.clip((-lof_raw - 0.5) / 2.0, 0, 1))

        # 3. ECOD
        ecod_score = float(np.clip(self.ecod.decision_function(X_scaled)[0] / 10.0, 0, 1))

        # 4. COPOD
        copod_score = float(np.clip(self.copod.decision_function(X_scaled)[0] / 10.0, 0, 1))

        # 5. XGBoost
        xgb_score = float(self.xgb_model.predict_proba(X_scaled)[0][1])

        # 6. Random Forest
        rf_score = float(self.rf_model.predict_proba(X_scaled)[0][1])

        # 7. Logistic Regression (calibrated)
        lr_score = float(self.lr_model.predict_proba(X_scaled)[0][1])

        # 8. DBSCAN distance from normal cluster center
        if self.dbscan_center is not None:
            dist = float(np.linalg.norm(X_scaled[0] - self.dbscan_center))
            dbscan_score = float(np.clip((dist - 2.0) / 6.0, 0, 1))
        else:
            dbscan_score = 0.0

        # 9. Statistical detection
        stat_result   = self.stat_detector.score(row)
        stat_score    = stat_result["stat_score"]

        # 10. Velocity check
        velocity_result = self.velocity_checker.score(row)
        velocity_score  = velocity_result["velocity_score"]

        # 11. Trading fraud patterns
        trading_result = self.trading_detector.score(row)
        trading_score  = trading_result["trading_score"]

        # ── Weighted Ensemble ─────────────────────────────────────
        final_score = float(np.clip(
            0.18 * iso_score    +
            0.15 * lof_score    +
            0.15 * xgb_score    +
            0.12 * rf_score     +
            0.08 * lr_score     +
            0.08 * ecod_score   +
            0.06 * copod_score  +
            0.06 * dbscan_score +
            0.06 * stat_score   +
            0.03 * velocity_score +
            0.03 * trading_score,
            0, 1
        ))

        # ── Risk Level ────────────────────────────────────────────
        if final_score >= 0.70:
            risk = "HIGH"
        elif final_score >= 0.40:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # ── Reasons ──────────────────────────────────────────────
        reasons = []
        if iso_score > 0.65:
            reasons.append("Isolation Forest: unusual feature combination")
        if lof_score > 0.60:
            reasons.append("LOF: transaction isolated from normal clusters")
        if xgb_score > 0.60:
            reasons.append(f"XGBoost: {xgb_score:.0%} fraud probability")
        if rf_score > 0.60:
            reasons.append(f"Random Forest: {rf_score:.0%} fraud probability")
        if lr_score > 0.55:
            reasons.append(f"Logistic Regression: {lr_score:.0%} fraud probability")
        if dbscan_score > 0.50:
            reasons.append("DBSCAN: outlier — far from normal cluster center")
        if stat_result["zscore"] > 3:
            reasons.append(f"Z-Score: amount ${row['Amount']:.2f} is {stat_result['zscore']:.1f}σ from mean")
        if stat_result["mod_zscore"] > 3.5:
            reasons.append(f"Modified Z-Score: {stat_result['mod_zscore']:.1f} (threshold 3.5)")
        if stat_result["iqr_outlier"]:
            reasons.append("IQR: amount is outside 1.5×IQR bounds")
        if stat_result["extreme_features"]:
            reasons.append(f"Extreme PCA features: {', '.join(stat_result['extreme_features'])}")
        if velocity_result["is_unusual_time"]:
            reasons.append("Velocity: transaction at unusual hour")
        if velocity_result["velocity_score"] > 0.5:
            reasons.append(f"Velocity: high transaction frequency ({velocity_result['recent_txn_count']} recent)")
        reasons.extend(trading_result["patterns_detected"])

        if not reasons:
            reasons.append("All models within normal behavioral baseline")

        return {
            "anomaly_score":    round(final_score, 4),
            "risk_level":       risk,
            # Model scores
            "iso_forest_score": round(iso_score, 4),
            "lof_score":        round(lof_score, 4),
            "xgb_score":        round(xgb_score, 4),
            "rf_score":         round(rf_score, 4),
            "lr_score":         round(lr_score, 4),
            "ecod_score":       round(ecod_score, 4),
            "copod_score":      round(copod_score, 4),
            "dbscan_score":     round(dbscan_score, 4),
            # Statistical
            "stat_score":       round(stat_score, 4),
            "zscore_amount":    round(stat_result["zscore"], 4),
            "mod_zscore":       round(stat_result["mod_zscore"], 4),
            "iqr_outlier":      stat_result["iqr_outlier"],
            # Velocity
            "velocity_score":   round(velocity_score, 4),
            "velocity_details": velocity_result,
            # Trading patterns
            "trading_score":    round(trading_score, 4),
            "trading_details":  trading_result,
            # Meta
            "amount":           row["Amount"],
            "reasons":          reasons,
        }

    def save(self):
        joblib.dump(self, MODEL_PATH)
        print(f"Model saved → {MODEL_PATH}")

    @staticmethod
    def load():
        if os.path.exists(MODEL_PATH):
            try:
                return joblib.load(MODEL_PATH)
            except Exception:
                return None
        return None


# ── 7. TRANSACTION GENERATOR ─────────────────────────────────────────────────
def random_transaction(fraud_probability=0.15):
    """Generate a synthetic transaction, occasionally fraudulent"""
    is_fraud = np.random.random() < fraud_probability
    v_cols   = [f"V{i}" for i in range(1, 29)]
    txn      = {c: float(np.random.randn()) for c in v_cols}

    if is_fraud:
        fraud_type = np.random.choice(["standard", "front_run", "spoof", "layer", "micro"])
        if fraud_type == "front_run":
            txn["V1"]  += np.random.uniform(-6, -2)
            txn["Amount"] = float(np.random.lognormal(6, 1))
        elif fraud_type == "spoof":
            txn["V14"] += np.random.uniform(-7, -3)
            txn["Amount"] = float(np.random.lognormal(5, 0.5))
        elif fraud_type == "layer":
            txn["V12"] += np.random.uniform(-8, -4)
            txn["Amount"] = float(np.random.lognormal(4, 1))
        elif fraud_type == "micro":
            txn["Amount"] = float(np.random.uniform(0.01, 2.0))
        else:
            txn["V1"]  += np.random.uniform(-6, -2)
            txn["V2"]  += np.random.uniform(2, 5)
            txn["V12"] += np.random.uniform(-8, -3)
            txn["V14"] += np.random.uniform(-7, -2)
            txn["Amount"] = float(np.random.lognormal(5, 1.5))
    else:
        txn["Amount"] = float(np.random.lognormal(3.5, 1.2))

    txn["Amount"] = round(float(np.clip(txn["Amount"], 0.01, 15000)), 2)
    txn["Time"]   = float(np.random.uniform(0, 172800))
    return txn


# ── 8. STARTUP: TRAIN OR LOAD ─────────────────────────────────────────────────
print("🔄 Loading/training models...")
_detector = EnsembleAnomalyDetector.load()

if _detector is None:
    print("No saved model found — training fresh (8 models)...")
    df_train  = generate_training_data(n_samples=12000)
    _detector = EnsembleAnomalyDetector()
    _detector.fit(df_train)
    _detector.save()
else:
    print("✅ Loaded saved model")


def generate_alert():
    txn    = random_transaction(fraud_probability=0.20)
    result = _detector.predict_score(txn)
    return result["risk_level"], result["anomaly_score"], " | ".join(result["reasons"])


def score_transaction(txn: dict) -> dict:
    return _detector.predict_score(txn)


def get_model_metrics() -> dict:
    return _detector.metrics