# Website Security Scanner (Flask)

A simple, beginner‑friendly website security scanner built with Python (Flask).  
It checks for common issues:
- SSL/TLS certificate problems
- SQL Injection error/reflection hints
- XSS (reflected) hints
- CSRF (missing token fields in forms)

## Quick Start

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Notes
- This is a lightweight educational tool. It does **not** replace a full DAST/SAST suite.
- Scans are best-effort heuristics and may produce false positives/negatives.
- Use only on systems you own or have permission to test.
