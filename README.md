# QR Checkpoint

Run:
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000 (camera access needs localhost or HTTPS).

Frontend: static/index.html, style.css, script.js (QR decoding in-browser with jsQR).
Backend: app.py (Flask API: POST /api/analyze), analyzer.py (rule-based scoring).
