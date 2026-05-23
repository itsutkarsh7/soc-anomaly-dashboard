"""
ZeTheta Anomaly Detection — Thread-safe SQLite Database
Tables: alerts, cyber_logs, feedback_log, stats_log
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts.db")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT    DEFAULT (datetime('now')),
            risk_level       TEXT    NOT NULL,
            score            REAL    NOT NULL,
            iso_score        REAL,
            lof_score        REAL,
            xgb_score        REAL,
            rf_score         REAL,
            lr_score         REAL,
            ecod_score       REAL,
            copod_score      REAL,
            dbscan_score     REAL,
            stat_score       REAL,
            velocity_score   REAL,
            trading_score    REAL,
            zscore_amount    REAL,
            mod_zscore       REAL,
            amount           REAL,
            reason           TEXT,
            status           TEXT DEFAULT 'PENDING',
            analyst_note     TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS cyber_logs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT    DEFAULT (datetime('now')),
            log_id           TEXT,
            log_type         TEXT,
            threat_type      TEXT,
            severity         TEXT,
            severity_score   REAL,
            src_ip           TEXT,
            dst_ip           TEXT,
            indicator        TEXT,
            mitre            TEXT,
            is_threat        INTEGER DEFAULT 0,
            raw_json         TEXT,
            status           TEXT DEFAULT 'OPEN',
            analyst_note     TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS feedback_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT    DEFAULT (datetime('now')),
            alert_id     INTEGER NOT NULL,
            status       TEXT    NOT NULL,
            analyst_note TEXT    DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS stats_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at TEXT    DEFAULT (datetime('now')),
            total       INTEGER,
            high_risk   INTEGER,
            medium_risk INTEGER,
            low_risk    INTEGER,
            resolved    INTEGER,
            false_pos   INTEGER
        );
    """)
    conn.commit()
    conn.close()
    print("✅ Database ready")

init_db()