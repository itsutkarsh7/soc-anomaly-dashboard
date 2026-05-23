# SOC Analyst Dashboard & Anomaly Detection System

A unified security platform combining financial fraud detection and SOC cyber log analysis.

## Features
- **8 ML Models**: Isolation Forest, LOF, XGBoost, Random Forest, Logistic Regression, DBSCAN, ECOD, COPOD
- **Statistical Detection**: Z-Score, Modified Z-Score, IQR
- **Trading Fraud Patterns**: Front-running, Spoofing, Layering, Wash Trading
- **SOC Cyber Logs**: 12 threat types — Ransomware, Brute Force, SQL Injection, C2 Beaconing, DDoS, and more
- **MITRE ATT&CK** mapping for all cyber threats
- **Real-time Dashboard**: React + Recharts with 4 tabs

## Setup

### Backend
```bash
cd backend
pip install -r requirements.txt
python3 -m uvicorn main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173
