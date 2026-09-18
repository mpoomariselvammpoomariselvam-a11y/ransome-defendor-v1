# Ransome Defender Backend

## What it does
A hackathon prototype backend for scanning Windows PE files using the supplied ransomware dataset and a Random Forest classifier.

## Setup (Windows)
```powershell
cd ransome_backend
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
py train_model.py
uvicorn app.main:app --reload
```

API: http://127.0.0.1:8000
Docs: http://127.0.0.1:8000/docs
Health: GET /health
Scan: POST /scan (multipart field: file)

## Frontend
Point the frontend scan request to `http://127.0.0.1:8000/scan`.

## Important limitation
The supplied dataset contains PE/executable features. Therefore this backend scans PE files. It is not yet a complete whole-computer ransomware detector. A separate Windows startup agent and real-time behavior monitor are needed for the login-time requirement.
