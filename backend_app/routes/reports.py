import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from backend_app.models import ReportModerationRequest, ReportRequest, ShareReportRequest
from backend_app.routes.auth import require_admin, resolve_token_user
from backend_app.services.notification_service import dispatch_webhook
from backend_app.services.rate_limit import enforce_rate_limit
from backend_app.services.storage import (
    create_report,
    create_shared_report,
    get_shared_report,
    moderate_report,
    read_reports,
    summarize_reports,
)

router = APIRouter()


@router.post("/reports")
def submit_report(req: ReportRequest, request: Request, user: dict | None = Depends(resolve_token_user)):
    enforce_rate_limit(request, "reports")
    payload = req.model_dump()
    payload["user_id"] = user["id"] if user else None
    report = create_report(payload)
    dispatch_webhook("report_created", report)
    return {"ok": True, "report": report}


@router.get("/reports/recent")
def recent_reports(limit: int = 5, days: int = 30, report_type: str | None = None):
    safe_limit = max(1, min(limit, 20))
    safe_days = max(1, min(days, 365))
    reports = read_reports(limit=safe_limit, days=safe_days, report_type=report_type)
    return {"items": reports, "count": len(reports)}


@router.get("/reports/stats")
def report_stats(days: int = 30, report_type: str | None = None):
    safe_days = max(1, min(days, 365))
    reports = read_reports(days=safe_days, report_type=report_type)
    return summarize_reports(reports)


@router.post("/reports/share")
def share_report(req: ShareReportRequest):
    share = create_shared_report(req.model_dump())
    dispatch_webhook("shared_report_created", {"token": share["token"], "url": share["url"], "level": share["level"]})
    return {"ok": True, "share": share}


@router.get("/shared-reports/{token}")
def shared_report(token: str):
    payload = get_shared_report(token)
    if payload is None:
        raise HTTPException(status_code=404, detail="shared_report_not_found")
    return {"ok": True, "report": payload}


@router.get("/shared-reports/{token}/view", response_class=HTMLResponse)
def shared_report_view(token: str):
    payload = get_shared_report(token)
    if payload is None:
        raise HTTPException(status_code=404, detail="shared_report_not_found")
    return _render_shared_report_page(payload)


@router.get("/admin/reports")
def admin_reports(status: str = "pending", days: int = 90, is_admin: bool = Depends(require_admin)):
    safe_days = max(1, min(days, 365))
    reports = read_reports(days=safe_days)
    if status:
        reports = [report for report in reports if report.get("status") == status]
    return {"ok": True, "items": reports, "count": len(reports)}


@router.post("/admin/reports/{report_id}/moderate")
def admin_moderate_report(
    report_id: int,
    req: ReportModerationRequest,
    is_admin: bool = Depends(require_admin),
):
    report = moderate_report(report_id, req.status, req.note)
    if report is None:
        raise HTTPException(status_code=404, detail="report_not_found")
    dispatch_webhook("report_moderated", report)
    return {"ok": True, "report": report}


def _render_shared_report_page(payload: dict) -> str:
    serialized = json.dumps(payload, ensure_ascii=False)
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ROY SHIELD | Rapport partagé</title>
  <style>
    :root {{
      --bg: #081019;
      --surface: rgba(12, 18, 28, 0.9);
      --surface-strong: rgba(18, 28, 42, 0.96);
      --border: rgba(255,255,255,0.08);
      --text: #e8edf5;
      --muted: #93a0b4;
      --safe: #10b981;
      --warn: #f59e0b;
      --danger: #ef4444;
      --primary: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, system-ui, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top, rgba(56,189,248,0.18), transparent 34%),
        linear-gradient(180deg, #081019 0%, #05080f 100%);
      min-height: 100vh;
    }}
    .wrap {{
      width: min(980px, calc(100% - 32px));
      margin: 0 auto;
      padding: 40px 0 72px;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 28px;
    }}
    .brand {{
      font-weight: 900;
      letter-spacing: 0.08em;
    }}
    .brand span {{ color: var(--primary); }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(56,189,248,0.12);
      color: var(--primary);
      font-size: 0.82rem;
      font-weight: 700;
    }}
    .hero {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 28px;
      padding: 28px;
      box-shadow: 0 24px 80px rgba(0,0,0,0.28);
    }}
    .hero-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 18px;
      align-items: center;
    }}
    .kicker {{
      color: var(--primary);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.76rem;
      margin-bottom: 8px;
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: clamp(1.8rem, 4vw, 3rem);
      line-height: 1.05;
    }}
    .url {{
      color: var(--muted);
      word-break: break-all;
      line-height: 1.6;
    }}
    .score {{
      width: 128px;
      height: 128px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: radial-gradient(circle, rgba(8,16,25,0.94) 54%, transparent 55%), conic-gradient(var(--ring-color) calc(var(--score) * 3.6deg), rgba(255,255,255,0.08) 0deg);
      border: 1px solid var(--border);
    }}
    .score-inner {{ text-align: center; }}
    .score-num {{ font-size: 2.2rem; font-weight: 900; line-height: 1; }}
    .score-label {{ color: var(--muted); font-size: 0.78rem; margin-top: 4px; }}
    .meta-grid {{
      margin-top: 18px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
    }}
    .card {{
      background: var(--surface-strong);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 18px;
    }}
    .card-label {{
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }}
    .card-value {{ font-size: 1.05rem; font-weight: 700; }}
    .signals {{
      margin-top: 20px;
      display: grid;
      gap: 12px;
    }}
    .signal {{
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px 16px;
    }}
    .signal strong {{
      display: block;
      margin-bottom: 6px;
      font-size: 0.95rem;
    }}
    .signal span {{
      color: var(--muted);
      line-height: 1.55;
      font-size: 0.84rem;
    }}
    .signal.safe strong {{ color: var(--safe); }}
    .signal.warn strong {{ color: var(--warn); }}
    .signal.danger strong {{ color: var(--danger); }}
    .footer {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.8rem;
      line-height: 1.6;
      text-align: center;
    }}
    @media (max-width: 720px) {{
      .hero-grid, .meta-grid {{
        grid-template-columns: 1fr;
      }}
      .score {{
        margin: 0 auto;
      }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">ROY<span>SHIELD</span></div>
      <div class="badge">Rapport partagé en lecture seule</div>
    </div>
    <div class="hero">
      <div class="hero-grid">
        <div>
          <div class="kicker">Investigation publique</div>
          <h1 id="verdict">Rapport d'analyse</h1>
          <div class="url" id="targetUrl"></div>
        </div>
        <div class="score" id="scoreRing" style="--score:0;--ring-color:var(--primary)">
          <div class="score-inner">
            <div class="score-num" id="scoreValue">0</div>
            <div class="score-label">score de risque</div>
          </div>
        </div>
      </div>
      <div class="meta-grid">
        <div class="card">
          <div class="card-label">Niveau</div>
          <div class="card-value" id="levelValue">-</div>
        </div>
        <div class="card">
          <div class="card-label">Créé le</div>
          <div class="card-value" id="createdAtValue">-</div>
        </div>
        <div class="card">
          <div class="card-label">Référence</div>
          <div class="card-value" id="tokenValue">-</div>
        </div>
      </div>
      <div class="signals" id="signalsList"></div>
      <div class="footer">
        Ce rapport est partagé à titre informatif. Vérifiez toujours les demandes sensibles via les canaux officiels.
      </div>
    </div>
  </div>
  <script>
    const payload = {serialized};
    const levelColors = {{
      safe: "var(--safe)",
      warn: "var(--warn)",
      danger: "var(--danger)"
    }};
    document.getElementById("verdict").textContent = payload.verdict || "Rapport partagé";
    document.getElementById("targetUrl").textContent = payload.url || "";
    document.getElementById("scoreValue").textContent = payload.score ?? 0;
    document.getElementById("levelValue").textContent = payload.level || "inconnu";
    document.getElementById("createdAtValue").textContent = payload.created_at
      ? new Date(payload.created_at).toLocaleString("fr-FR", {{ day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }})
      : "-";
    document.getElementById("tokenValue").textContent = payload.token || "-";
    const ring = document.getElementById("scoreRing");
    ring.style.setProperty("--score", String(payload.score ?? 0));
    ring.style.setProperty("--ring-color", levelColors[payload.level] || "var(--primary)");
    const list = document.getElementById("signalsList");
    const signals = Array.isArray(payload.signals) ? payload.signals : [];
    list.innerHTML = signals.length
      ? signals.map(signal => `
          <div class="signal ${{signal.type || 'warn'}}">
            <strong>${{signal.label || 'Signal détecté'}}</strong>
            <span>${{signal.detail || 'Aucun détail fourni.'}}</span>
          </div>
        `).join("")
      : '<div class="signal warn"><strong>Aucun signal détaillé</strong><span>Ce rapport partagé ne contient pas encore de détails supplémentaires.</span></div>';
  </script>
</body>
</html>"""
