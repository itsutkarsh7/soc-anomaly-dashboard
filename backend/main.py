"""
ZeTheta Anomaly Detection System — FastAPI Backend (Complete)
All endpoints: alerts, generate, stats, score, velocity, trading patterns, feedback loop
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import datetime

from database import get_db
from model import generate_alert, score_transaction, random_transaction, get_model_metrics

app = FastAPI(title="ZeTheta Anomaly Detection API", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Schemas ───────────────────────────────────────────────────────────────────
class TransactionInput(BaseModel):
    V1: Optional[float] = None;  V2: Optional[float] = None
    V3: Optional[float] = None;  V4: Optional[float] = None
    V5: Optional[float] = None;  V6: Optional[float] = None
    V7: Optional[float] = None;  V8: Optional[float] = None
    V9: Optional[float] = None;  V10: Optional[float] = None
    V11: Optional[float] = None; V12: Optional[float] = None
    V13: Optional[float] = None; V14: Optional[float] = None
    V15: Optional[float] = None; V16: Optional[float] = None
    V17: Optional[float] = None; V18: Optional[float] = None
    V19: Optional[float] = None; V20: Optional[float] = None
    V21: Optional[float] = None; V22: Optional[float] = None
    V23: Optional[float] = None; V24: Optional[float] = None
    V25: Optional[float] = None; V26: Optional[float] = None
    V27: Optional[float] = None; V28: Optional[float] = None
    Amount: float = 100.0
    Time: float = 43200.0

class FeedbackInput(BaseModel):
    alert_id: int
    status: str
    analyst_note: Optional[str] = ""

def row_to_dict(row):
    return dict(row)

def insert_alert(db, result: dict):
    db.execute("""
        INSERT INTO alerts (
            risk_level, score, iso_score, lof_score, xgb_score,
            rf_score, lr_score, ecod_score, copod_score, dbscan_score,
            stat_score, velocity_score, trading_score,
            zscore_amount, mod_zscore, amount, reason, status
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING')
    """, (
        result["risk_level"],       result["anomaly_score"],
        result["iso_forest_score"], result["lof_score"],
        result["xgb_score"],        result["rf_score"],
        result["lr_score"],         result["ecod_score"],
        result["copod_score"],      result["dbscan_score"],
        result["stat_score"],       result["velocity_score"],
        result["trading_score"],    result["zscore_amount"],
        result["mod_zscore"],       result["amount"],
        " | ".join(result["reasons"])
    ))
    db.commit()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ZeTheta Anomaly Detection API", "version": "3.0",
            "models": ["IsolationForest","LOF","XGBoost","RandomForest",
                       "LogisticRegression","DBSCAN","ECOD","COPOD",
                       "Z-Score","ModifiedZ-Score","IQR","Velocity","TradingPatterns"]}


@app.get("/alerts")
def get_alerts(limit: int = 100, risk: Optional[str] = None, status: Optional[str] = None):
    db = get_db()
    query = "SELECT * FROM alerts"
    filters, params = [], []
    if risk:
        filters.append("risk_level = ?"); params.append(risk.upper())
    if status:
        filters.append("status = ?"); params.append(status.upper())
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [row_to_dict(r) for r in rows]


@app.post("/generate")
def generate_single():
    txn    = random_transaction(fraud_probability=0.20)
    result = score_transaction(txn)
    db = get_db()
    insert_alert(db, result)
    db.close()
    return {"msg": "Alert generated", "alert": {
        "risk_level": result["risk_level"],
        "score":      result["anomaly_score"],
        "amount":     result["amount"],
        "trading":    result["trading_details"]["patterns_detected"],
        "velocity":   result["velocity_details"]["recent_txn_count"],
    }}


@app.post("/generate/bulk/{count}")
def generate_bulk(count: int):
    count = min(count, 50)
    db    = get_db()
    generated = []
    for _ in range(count):
        txn    = random_transaction(fraud_probability=0.18)
        result = score_transaction(txn)
        insert_alert(db, result)
        generated.append(result["risk_level"])
    db.close()
    return {
        "msg": f"Generated {count} alerts",
        "breakdown": {
            "HIGH":   generated.count("HIGH"),
            "MEDIUM": generated.count("MEDIUM"),
            "LOW":    generated.count("LOW"),
        }
    }


@app.post("/score")
def score_custom(txn: TransactionInput):
    """Score a custom transaction with full model breakdown"""
    return score_transaction(txn.dict())


@app.post("/feedback")
def submit_feedback(fb: FeedbackInput):
    """
    Feedback loop — analyst marks result, system records for retraining.
    In production this triggers model retraining pipeline.
    """
    valid = ["PENDING","RESOLVED","FALSE_POSITIVE","ESCALATED","CONFIRMED_FRAUD"]
    if fb.status.upper() not in valid:
        raise HTTPException(400, f"Status must be one of {valid}")

    db = get_db()
    db.execute(
        "UPDATE alerts SET status=?, analyst_note=? WHERE id=?",
        (fb.status.upper(), fb.analyst_note, fb.alert_id)
    )
    if db.execute("SELECT changes()").fetchone()[0] == 0:
        db.close()
        raise HTTPException(404, "Alert not found")
    db.commit()

    # Log feedback for retraining
    db.execute(
        "INSERT INTO feedback_log (alert_id, status, analyst_note) VALUES (?,?,?)",
        (fb.alert_id, fb.status.upper(), fb.analyst_note)
    )
    db.commit()
    db.close()

    return {
        "msg": f"Feedback recorded for alert {fb.alert_id}",
        "retraining_triggered": fb.status.upper() in ["FALSE_POSITIVE","CONFIRMED_FRAUD"],
        "note": "Model retraining queue updated" if fb.status.upper() in ["FALSE_POSITIVE","CONFIRMED_FRAUD"] else "Status updated"
    }


@app.post("/update/{alert_id}/{status}")
def update_alert(alert_id: int, status: str):
    valid = ["PENDING","RESOLVED","FALSE_POSITIVE","ESCALATED","CONFIRMED_FRAUD"]
    if status.upper() not in valid:
        raise HTTPException(400, f"Status must be one of {valid}")
    db = get_db()
    db.execute("UPDATE alerts SET status=? WHERE id=?", (status.upper(), alert_id))
    db.commit()
    db.close()
    return {"msg": f"Alert {alert_id} → {status.upper()}"}


@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: int):
    db = get_db()
    db.execute("DELETE FROM alerts WHERE id=?", (alert_id,))
    db.commit()
    db.close()
    return {"msg": f"Alert {alert_id} deleted"}


@app.delete("/alerts")
def clear_all():
    db = get_db()
    db.execute("DELETE FROM alerts")
    db.commit()
    db.close()
    return {"msg": "All alerts cleared"}


@app.get("/stats")
def get_stats():
    db = get_db()
    def q(sql): return db.execute(sql).fetchone()[0] or 0

    total     = q("SELECT COUNT(*) FROM alerts")
    high      = q("SELECT COUNT(*) FROM alerts WHERE risk_level='HIGH'")
    medium    = q("SELECT COUNT(*) FROM alerts WHERE risk_level='MEDIUM'")
    low       = q("SELECT COUNT(*) FROM alerts WHERE risk_level='LOW'")
    pending   = q("SELECT COUNT(*) FROM alerts WHERE status='PENDING'")
    resolved  = q("SELECT COUNT(*) FROM alerts WHERE status='RESOLVED'")
    false_p   = q("SELECT COUNT(*) FROM alerts WHERE status='FALSE_POSITIVE'")
    escalated = q("SELECT COUNT(*) FROM alerts WHERE status='ESCALATED'")
    confirmed = q("SELECT COUNT(*) FROM alerts WHERE status='CONFIRMED_FRAUD'")
    avg_score = q("SELECT AVG(score) FROM alerts") or 0
    avg_amt   = q("SELECT AVG(amount) FROM alerts") or 0
    avg_trading = q("SELECT AVG(trading_score) FROM alerts") or 0
    avg_velocity = q("SELECT AVG(velocity_score) FROM alerts") or 0

    recent = db.execute(
        "SELECT score, risk_level, timestamp, trading_score, velocity_score FROM alerts ORDER BY id DESC LIMIT 20"
    ).fetchall()
    db.close()

    trend = [{"score": r[0], "risk": r[1], "time": r[2],
              "trading": r[3], "velocity": r[4]} for r in reversed(recent)]

    detection_rate = round((high + medium) / total * 100, 1) if total > 0 else 0
    false_pos_rate = round(false_p / total * 100, 1) if total > 0 else 0

    model_metrics = get_model_metrics()

    return {
        "total": total, "high": high, "medium": medium, "low": low,
        "pending": pending, "resolved": resolved,
        "false_positive": false_p, "escalated": escalated, "confirmed_fraud": confirmed,
        "avg_score":    round(float(avg_score), 4),
        "avg_amount":   round(float(avg_amt), 2),
        "avg_trading":  round(float(avg_trading), 4),
        "avg_velocity": round(float(avg_velocity), 4),
        "detection_rate":      detection_rate,
        "false_positive_rate": false_pos_rate,
        "model_metrics":       model_metrics,
        "trend": trend,
        "risk_distribution": [
            {"name": "HIGH",   "value": high,   "color": "#f43f5e"},
            {"name": "MEDIUM", "value": medium, "color": "#f59e0b"},
            {"name": "LOW",    "value": low,    "color": "#10b981"},
        ],
        "status_distribution": [
            {"name": "Pending",        "value": pending,   "color": "#6366f1"},
            {"name": "Resolved",       "value": resolved,  "color": "#22c55e"},
            {"name": "False Positive", "value": false_p,   "color": "#94a3b8"},
            {"name": "Escalated",      "value": escalated, "color": "#f97316"},
            {"name": "Confirmed Fraud","value": confirmed,  "color": "#f43f5e"},
        ]
    }


@app.get("/model/info")
def model_info():
    """Return full model architecture info"""
    return {
        "models": [
            {"name": "Isolation Forest",     "type": "Unsupervised", "weight": "18%"},
            {"name": "Local Outlier Factor", "type": "Unsupervised", "weight": "15%"},
            {"name": "XGBoost",              "type": "Supervised",   "weight": "15%"},
            {"name": "Random Forest",        "type": "Supervised",   "weight": "12%"},
            {"name": "Logistic Regression",  "type": "Supervised",   "weight": "8%"},
            {"name": "ECOD (PyOD)",          "type": "Statistical",  "weight": "8%"},
            {"name": "COPOD (PyOD)",         "type": "Statistical",  "weight": "6%"},
            {"name": "DBSCAN",               "type": "Clustering",   "weight": "6%"},
            {"name": "Z-Score",              "type": "Statistical",  "weight": "6%"},
            {"name": "Velocity Checks",      "type": "Domain",       "weight": "3%"},
            {"name": "Trading Patterns",     "type": "Domain",       "weight": "3%"},
        ],
        "trading_patterns": ["Front-running", "Spoofing", "Layering", "Wash trading", "Micro-test transactions"],
        "statistical_methods": ["Z-Score", "Modified Z-Score", "IQR", "Mahalanobis-like distance"],
        "success_criteria": {"detection_rate": ">85%", "false_positive_rate": "<5%", "uptime": "99.5%+"},
        "metrics": get_model_metrics()
    }


@app.get("/feedback/log")
def get_feedback_log(limit: int = 50):
    """Get analyst feedback log for retraining pipeline"""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM feedback_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    db.close()
    return [row_to_dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
# SOC / CYBER LOG ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════
from cyber_engine import (
    generate_cyber_log, generate_bulk_logs, extract_iocs,
    THREAT_TYPES, gen_network_log, gen_auth_log, gen_endpoint_log
)

@app.get("/cyber/logs")
def get_cyber_logs(limit: int = 100, threat_type: Optional[str] = None,
                   severity: Optional[str] = None, log_type: Optional[str] = None):
    """Get all cyber logs with optional filters"""
    db = get_db()
    query  = "SELECT * FROM cyber_logs"
    filters, params = [], []

    if threat_type:
        filters.append("threat_type = ?"); params.append(threat_type.upper())
    if severity:
        filters.append("severity = ?"); params.append(severity.upper())
    if log_type:
        filters.append("log_type = ?"); params.append(log_type.upper())
    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, params).fetchall()
    db.close()
    return [row_to_dict(r) for r in rows]


@app.post("/cyber/generate")
def generate_single_cyber_log():
    """Generate one cyber log entry"""
    log = generate_cyber_log()
    iocs = extract_iocs(log)
    db = get_db()
    db.execute("""
        INSERT INTO cyber_logs
        (log_id, log_type, threat_type, severity, severity_score,
         src_ip, dst_ip, indicator, mitre, is_threat, raw_json, status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        log["id"], log["log_type"], log["threat_type"],
        log["severity"], log["severity_score"],
        log.get("src_ip",""), log.get("dst_ip",""),
        log.get("indicator",""), log.get("mitre",""),
        int(log["is_threat"]),
        str(log), "OPEN"
    ))
    db.commit()
    db.close()
    return {"log": log, "iocs": iocs}


@app.post("/cyber/generate/bulk/{count}")
def generate_bulk_cyber(count: int):
    """Generate multiple cyber logs"""
    count = min(count, 100)
    logs  = generate_bulk_logs(count)
    db    = get_db()
    breakdown = {}
    for log in logs:
        iocs = extract_iocs(log)
        db.execute("""
            INSERT INTO cyber_logs
            (log_id, log_type, threat_type, severity, severity_score,
             src_ip, dst_ip, indicator, mitre, is_threat, raw_json, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            log["id"], log["log_type"], log["threat_type"],
            log["severity"], log["severity_score"],
            log.get("src_ip",""), log.get("dst_ip",""),
            log.get("indicator",""), log.get("mitre",""),
            int(log["is_threat"]), str(log), "OPEN"
        ))
        t = log["threat_type"]
        breakdown[t] = breakdown.get(t, 0) + 1
    db.commit()
    db.close()

    threats = {k:v for k,v in breakdown.items() if k != "NORMAL"}
    return {
        "msg": f"Generated {count} cyber logs",
        "threats_detected": threats,
        "normal": breakdown.get("NORMAL", 0)
    }


@app.post("/cyber/generate/threat/{threat_type}")
def generate_specific_threat(threat_type: str):
    """Generate a specific threat type for testing"""
    valid = list(THREAT_TYPES.keys())
    if threat_type.upper() not in valid:
        raise HTTPException(400, f"Threat type must be one of: {valid}")
    log  = generate_cyber_log(force_threat=threat_type.upper())
    iocs = extract_iocs(log)
    db   = get_db()
    db.execute("""
        INSERT INTO cyber_logs
        (log_id, log_type, threat_type, severity, severity_score,
         src_ip, dst_ip, indicator, mitre, is_threat, raw_json, status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        log["id"], log["log_type"], log["threat_type"],
        log["severity"], log["severity_score"],
        log.get("src_ip",""), log.get("dst_ip",""),
        log.get("indicator",""), log.get("mitre",""),
        int(log["is_threat"]), str(log), "OPEN"
    ))
    db.commit()
    db.close()
    return {"log": log, "iocs": iocs}


@app.post("/cyber/update/{log_id}/{status}")
def update_cyber_log(log_id: int, status: str):
    """Update cyber log investigation status"""
    valid = ["OPEN","INVESTIGATING","RESOLVED","FALSE_POSITIVE","ESCALATED"]
    if status.upper() not in valid:
        raise HTTPException(400, f"Status must be one of {valid}")
    db = get_db()
    db.execute("UPDATE cyber_logs SET status=? WHERE id=?", (status.upper(), log_id))
    db.commit()
    db.close()
    return {"msg": f"Cyber log {log_id} → {status.upper()}"}


@app.delete("/cyber/logs")
def clear_cyber_logs():
    db = get_db()
    db.execute("DELETE FROM cyber_logs")
    db.commit()
    db.close()
    return {"msg": "All cyber logs cleared"}


@app.get("/cyber/stats")
def get_cyber_stats():
    """SOC dashboard statistics"""
    db = get_db()
    def q(sql): return db.execute(sql).fetchone()[0] or 0

    total     = q("SELECT COUNT(*) FROM cyber_logs")
    threats   = q("SELECT COUNT(*) FROM cyber_logs WHERE is_threat=1")
    critical  = q("SELECT COUNT(*) FROM cyber_logs WHERE severity='CRITICAL'")
    high      = q("SELECT COUNT(*) FROM cyber_logs WHERE severity='HIGH'")
    medium    = q("SELECT COUNT(*) FROM cyber_logs WHERE severity='MEDIUM'")
    low       = q("SELECT COUNT(*) FROM cyber_logs WHERE severity='LOW'")
    open_c    = q("SELECT COUNT(*) FROM cyber_logs WHERE status='OPEN'")
    invest    = q("SELECT COUNT(*) FROM cyber_logs WHERE status='INVESTIGATING'")
    resolved  = q("SELECT COUNT(*) FROM cyber_logs WHERE status='RESOLVED'")
    false_p   = q("SELECT COUNT(*) FROM cyber_logs WHERE status='FALSE_POSITIVE'")

    # Threat type breakdown
    threat_rows = db.execute("""
        SELECT threat_type, COUNT(*) as cnt FROM cyber_logs
        WHERE is_threat=1 GROUP BY threat_type ORDER BY cnt DESC
    """).fetchall()

    # MITRE breakdown
    mitre_rows = db.execute("""
        SELECT mitre, COUNT(*) as cnt FROM cyber_logs
        WHERE mitre != '' AND mitre IS NOT NULL
        GROUP BY mitre ORDER BY cnt DESC LIMIT 10
    """).fetchall()

    # Log type breakdown
    logtype_rows = db.execute("""
        SELECT log_type, COUNT(*) as cnt FROM cyber_logs GROUP BY log_type
    """).fetchall()

    # Recent trend
    recent = db.execute("""
        SELECT severity_score, threat_type, timestamp, log_type
        FROM cyber_logs ORDER BY id DESC LIMIT 30
    """).fetchall()
    db.close()

    THREAT_COLORS = {
        "BRUTE_FORCE":"#f43f5e","PORT_SCAN":"#f59e0b","SQL_INJECTION":"#dc2626",
        "XSS_ATTACK":"#f59e0b","DATA_EXFILTRATION":"#dc2626","C2_BEACONING":"#f43f5e",
        "LATERAL_MOVEMENT":"#f43f5e","PRIV_ESCALATION":"#f43f5e","DDOS":"#f43f5e",
        "RANSOMWARE":"#dc2626","INSIDER_THREAT":"#f43f5e","DNS_TUNNELING":"#f59e0b",
    }

    detection_rate = round(threats/total*100,1) if total > 0 else 0

    return {
        "total": total, "threats": threats, "normal": total-threats,
        "critical": critical, "high": high, "medium": medium, "low": low,
        "open": open_c, "investigating": invest, "resolved": resolved, "false_positive": false_p,
        "detection_rate": detection_rate,
        "threat_breakdown": [
            {"name": r[0], "value": r[1], "color": THREAT_COLORS.get(r[0],"#6366f1")}
            for r in threat_rows
        ],
        "mitre_breakdown": [
            {"technique": r[0], "count": r[1]} for r in mitre_rows
        ],
        "log_type_breakdown": [
            {"name": r[0], "value": r[1],
             "color": {"NETWORK":"#0ea5e9","AUTH":"#8b5cf6","ENDPOINT":"#f97316"}.get(r[0],"#6366f1")}
            for r in logtype_rows
        ],
        "severity_distribution": [
            {"name": "CRITICAL", "value": critical, "color": "#dc2626"},
            {"name": "HIGH",     "value": high,     "color": "#f43f5e"},
            {"name": "MEDIUM",   "value": medium,   "color": "#f59e0b"},
            {"name": "LOW",      "value": low,       "color": "#10b981"},
        ],
        "trend": [{"score": r[0], "type": r[1], "time": r[2], "log_type": r[3]}
                  for r in reversed(recent)],
    }