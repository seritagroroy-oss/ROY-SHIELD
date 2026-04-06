# ROY SHIELD

ROY SHIELD is a phishing and scam detection tool focused on fast URL analysis. It combines frontend heuristics, backend enrichment, and optional VirusTotal checks to help users evaluate suspicious links before interacting with them.

## Highlights

- Multi-engine URL risk scoring
- Suspicious keyword detection
- Free-hosting and risky TLD detection
- Typo-squatting checks for common brands
- WHOIS and SSL enrichment from the FastAPI backend
- HTML content inspection for phishing signals
- Optional VirusTotal integration in the browser
- Local scan history and report export

## Stack

- Frontend: `index.html`, `style.css`, `app.js`, `analyzer.js`
- Backend: FastAPI entrypoint in [backend.py](/e:/SITE/backend.py)
- Backend modules: [backend_app/app.py](/e:/SITE/backend_app/app.py), [backend_app/routes/scan.py](/e:/SITE/backend_app/routes/scan.py), [backend_app/services/scan_service.py](/e:/SITE/backend_app/services/scan_service.py)
- Config: [config.js](/e:/SITE/config.js) and [.env.example](/e:/SITE/.env.example)
- Tests: [tests/test_backend.py](/e:/SITE/tests/test_backend.py)
- CI: [.github/workflows/ci.yml](/e:/SITE/.github/workflows/ci.yml)

## Quick start

Recommended Python version: `3.11`

```bash
git clone https://github.com/seritagroroy-oss/ROY-SHIELD.git
cd ROY-SHIELD
python -m venv .venv
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
source .venv/bin/activate
```

## Backend configuration

Copy [.env.example](/e:/SITE/.env.example) to `.env` and adjust values if needed.

Available variables:

- `ROY_SHIELD_ENV`
- `ROY_SHIELD_ALLOWED_ORIGINS`
- `ROY_SHIELD_FETCH_TIMEOUT`
- `ROY_SHIELD_SSL_TIMEOUT`

Run the API locally:

```bash
uvicorn backend:app --reload
```

## Frontend configuration

Edit [config.js](/e:/SITE/config.js) to point the UI to the backend you want to use.

Example:

```js
window.ROY_SHIELD_CONFIG = {
  backendUrl: "http://127.0.0.1:8000"
};
```

Then open [index.html](/e:/SITE/index.html) in your browser.

## API

- `POST /scan`
- `GET /health`
- `GET /stats`
- `GET /recent-scans`

## Testing

Run backend tests locally with:

```bash
pytest
```

GitHub Actions runs the same backend test suite on pushes and pull requests to `main`.

## Roadmap

- [x] Browser-based scam scanner
- [x] Python backend enrichment
- [x] VirusTotal integration
- [x] Basic automated tests
- [x] GitHub Actions CI
- [ ] Structured scan logging
- [ ] Dashboard metrics
- [ ] Public demo assets
- [ ] Community reporting backend

## Note

ROY SHIELD is a decision-support tool, not a guarantee. Always verify sensitive requests through official channels before sharing credentials, payment details, or personal data.
