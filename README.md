# ROY SHIELD

ROY SHIELD is a phishing and scam detection platform focused on fast URL analysis, operator review, and actionable security signals. It combines frontend heuristics, backend enrichment, community reporting, and persistent analytics to help users evaluate suspicious links before interacting with them.

## Highlights

- Multi-engine URL risk scoring
- Suspicious keyword detection
- Free-hosting and risky TLD detection
- Typo-squatting checks for common brands
- WHOIS and SSL enrichment from the FastAPI backend
- HTML content inspection for phishing signals
- Optional VirusTotal integration in the browser
- Persistent scan and report storage with SQLite
- Live dashboard for recent scans, risk levels, and community reports
- Filterable analytics dashboard with 7/30/90-day views
- Analyst workspace with lightweight authentication and personal scan history
- Rate limiting and structured validation on critical API routes
- Security posture scoring and anomaly alerts in backend analytics
- Shareable read-only report links for investigations
- Admin moderation endpoints for community reports
- Optional webhook alerts for dangerous scans and moderation events
- Local history and export-friendly reporting flow

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
- `ROY_SHIELD_RATE_LIMIT_WINDOW_SECONDS`
- `ROY_SHIELD_RATE_LIMIT_SCAN`
- `ROY_SHIELD_RATE_LIMIT_REPORTS`
- `ROY_SHIELD_RATE_LIMIT_AUTH`
- `ROY_SHIELD_WEBHOOK_URL`
- `ROY_SHIELD_ADMIN_TOKEN`

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
- `POST /reports`
- `GET /reports/recent`
- `GET /reports/stats`
- `POST /reports/share`
- `GET /shared-reports/{token}`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /me`
- `GET /me/scans`
- `GET /admin/reports`
- `POST /admin/reports/{report_id}/moderate`

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
- [x] Persistent storage for scans and reports
- [x] Dashboard metrics and recent activity feeds
- [x] Community reporting backend
- [x] Analyst workspace authentication
- [x] Filterable analytics views
- [x] API rate limiting and stricter validation
- [x] Security posture and anomaly alerts
- [x] Shareable read-only reports
- [x] Admin moderation workflow
- [x] Webhook event notifications
- [ ] Public demo assets
- [ ] Shareable scan report pages
- [ ] Alerting and notification channels

## Note

ROY SHIELD is a decision-support tool, not a guarantee. Always verify sensitive requests through official channels before sharing credentials, payment details, or personal data.
