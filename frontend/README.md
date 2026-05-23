# 🔍 ZeTheta Anomaly Detection System

**Market anomaly detection platform** for fraud & manipulation identification  
Built with FastAPI + React + Isolation Forest + LOF + Statistical Z-Score ensemble

---

## 📁 Project Structure

```
anomaly_detection_system/
├── backend/
│   ├── main.py         
│   ├── model.py        
│   └── database.py     
└── frontend/
    └── src/
        ├── App.jsx     
        └── main.jsx    
```

---

## ⚙️ ML Architecture

| Model | Weight | Purpose |
|---|---|---|
| Isolation Forest | 45% | Global anomaly detection via path length |
| Local Outlier Factor | 40% | Local density-based outlier scoring |
| Amount Z-Score | 15% | Statistical deviation of transaction amount |

**Features engineered from Kaggle creditcard.csv structure:**
- V1–V28 (PCA-transformed features)
- Amount, log(Amount)
- PCA mean/std/max-abs
- V1×V2 interaction, V14/V17 ratio
- Amount Z-score

**Risk thresholds:**
- `HIGH`   → ensemble score ≥ 0.70
- `MEDIUM` → ensemble score ≥ 0.40
- `LOW`    → ensemble score < 0.40

---

## 🚀 Setup & Run

### Backend
```bash
cd backend
pip install fastapi uvicorn scikit-learn pandas numpy joblib pyod
uvicorn main:app --reload --port 8000
```
Model trains automatically on first run (~5 seconds).

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET  | `/alerts` | List all alerts (filter by risk/status) |
| POST | `/generate` | Generate 1 random transaction alert |
| POST | `/generate/bulk/{n}` | Generate N alerts (max 50) |
| POST | `/score` | Score a custom transaction (V1-V28 + Amount) |
| POST | `/update/{id}/{status}` | Update alert status |
| DELETE | `/alerts/{id}` | Delete single alert |
| DELETE | `/alerts` | Clear all alerts |
| GET  | `/stats` | Dashboard statistics + chart data |

---

## 📊 Dashboard Features

- **Real-time KPI cards** — Total, High/Medium, Resolved, Detection Rate, Avg Score
- **Alert table** — Expandable rows with score breakdown per model
- **Investigation workflow** — Mark Resolved / False Positive / Escalate
- **Analytics tab** — Score trend chart, risk pie chart, status bar chart
- **Bulk generation** — Generate 1, 5, or 20 alerts at once
- **Filters** — Filter by risk level and investigation status

---

## ✅ Success Criteria (per ZeTheta spec)
- Detection rate target: **>85%** (configurable via contamination param)
- False positive rate target: **<5%**
- Uptime: 99.5%+ (stateless FastAPI + SQLite)

---

## 📦 Tech Stack
`FastAPI` · `SQLite` · `scikit-learn` · `Isolation Forest` · `LOF` · `React 19` · `Recharts` · `Framer Motion` · `Tailwind CSS` · `Vite`