from fastapi.testclient import TestClient

import backend
from backend_app.routes import auth as auth_route
from backend_app.routes import reports as reports_route
from backend_app.services import scan_service, storage
from backend_app.routes import stats as stats_route


client = TestClient(backend.app)


def test_health_endpoint_returns_runtime_metadata():
    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["version"] == backend.APP_VERSION
    assert "allowed_origins" in payload


def test_scan_marks_trusted_domain_as_safe():
    response = client.post("/scan", json={"url": "https://github.com"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["level"] == "safe"
    assert payload["score"] == 0


def test_scan_detects_http_and_shortener(monkeypatch):
    async def fake_fetch_page_content(url: str):
        return {"ok": False, "error": "network disabled in tests"}

    def fake_check_ssl(hostname: str):
        return {"valid": True, "days_left": 120}

    def fake_get_whois_info(domain: str):
        return {"found": False}

    monkeypatch.setattr(scan_service, "fetch_page_content", fake_fetch_page_content)
    monkeypatch.setattr(scan_service, "check_ssl", fake_check_ssl)
    monkeypatch.setattr(scan_service, "get_whois_info", fake_get_whois_info)

    response = client.post("/scan", json={"url": "http://bit.ly/reset-password"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["level"] == "danger"
    assert payload["score"] >= 60
    labels = [signal["label"] for signal in payload["python_signals"]]
    assert any("Connexion non securisee" in label for label in labels)
    assert any("Lien raccourci" in label for label in labels)


def test_stats_and_recent_scans_endpoints(monkeypatch):
    sample_events = [
        {
            "timestamp": "2026-04-06T18:00:00+00:00",
            "raw_url": "http://bit.ly/test",
            "normalized_url": "http://bit.ly/test",
            "hostname": "bit.ly",
            "score": 88,
            "level": "danger",
            "verdict": "Arnaque probable",
            "content_analyzed": True,
            "signal_count": 4,
        },
        {
            "timestamp": "2026-04-06T18:05:00+00:00",
            "raw_url": "https://github.com",
            "normalized_url": "https://github.com",
            "hostname": "github.com",
            "score": 0,
            "level": "safe",
            "verdict": "Site fiable",
            "content_analyzed": False,
            "signal_count": 1,
        },
    ]

    monkeypatch.setattr(storage, "read_scan_events", lambda limit=None: sample_events[-limit:] if limit else sample_events)
    monkeypatch.setattr(stats_route, "read_scan_events", lambda limit=None: sample_events[-limit:] if limit else sample_events)

    stats_response = client.get("/stats")
    recent_response = client.get("/recent-scans?limit=1")

    assert stats_response.status_code == 200
    stats_payload = stats_response.json()
    assert stats_payload["total_scans"] == 2
    assert stats_payload["danger_scans"] == 1
    assert stats_payload["safe_scans"] == 1
    assert "reports" in stats_payload

    assert recent_response.status_code == 200
    recent_payload = recent_response.json()
    assert recent_payload["count"] == 1
    assert recent_payload["items"][0]["normalized_url"] == "https://github.com"


def test_submit_report_and_report_endpoints(monkeypatch):
    sample_reports = [
        {
            "id": 1,
            "timestamp": "2026-04-06T18:10:00+00:00",
            "url": "https://fake-login.test",
            "report_type": "phishing",
            "comment": "Collecte d'identifiants",
            "score": 91,
            "verdict": "Arnaque probable",
            "level": "danger",
        }
    ]

    monkeypatch.setattr(
        reports_route,
        "create_report",
        lambda payload: {
            "id": 2,
            "timestamp": "2026-04-06T18:20:00+00:00",
            **payload,
        },
    )
    monkeypatch.setattr(storage, "read_reports", lambda limit=None: sample_reports[:limit] if limit else sample_reports)
    monkeypatch.setattr(reports_route, "read_reports", lambda limit=None: sample_reports[:limit] if limit else sample_reports)
    monkeypatch.setattr(stats_route, "read_reports", lambda limit=None: sample_reports[:limit] if limit else sample_reports)
    monkeypatch.setattr(stats_route, "read_scan_events", lambda limit=None: [])

    submit_response = client.post(
        "/reports",
        json={
            "url": "https://fake-login.test",
            "report_type": "phishing",
            "comment": "Collecte d'identifiants",
            "score": 91,
            "verdict": "Arnaque probable",
            "level": "danger",
        },
    )
    recent_response = client.get("/reports/recent?limit=1")
    stats_response = client.get("/reports/stats")
    global_stats_response = client.get("/stats")

    assert submit_response.status_code == 200
    assert submit_response.json()["ok"] is True

    assert recent_response.status_code == 200
    assert recent_response.json()["count"] == 1
    assert recent_response.json()["items"][0]["report_type"] == "phishing"

    assert stats_response.status_code == 200
    assert stats_response.json()["total_reports"] == 1
    assert stats_response.json()["by_type"]["phishing"] == 1

    assert global_stats_response.status_code == 200
    assert global_stats_response.json()["reports"]["total_reports"] == 1


def test_auth_register_login_and_profile(monkeypatch):
    sample_user = {
        "id": 10,
        "created_at": "2026-04-06T18:30:00+00:00",
        "name": "Roy Analyst",
        "email": "roy@example.com",
    }

    monkeypatch.setattr(auth_route, "create_user", lambda name, email, password: sample_user)
    monkeypatch.setattr(auth_route, "create_session", lambda user_id: "token-123")
    monkeypatch.setattr(auth_route, "authenticate_user", lambda email, password: sample_user)
    monkeypatch.setattr(auth_route, "get_user_by_token", lambda token: sample_user if token == "token-123" else None)
    monkeypatch.setattr(
        auth_route,
        "read_scan_events",
        lambda limit=None, days=None, user_id=None, level=None: [
            {
                "timestamp": "2026-04-06T19:00:00+00:00",
                "user_id": user_id,
                "raw_url": "https://github.com",
                "normalized_url": "https://github.com",
                "hostname": "github.com",
                "score": 0,
                "level": "safe",
                "verdict": "Site fiable",
                "content_analyzed": False,
                "signal_count": 1,
            }
        ],
    )

    register_response = client.post(
        "/auth/register",
        json={"name": "Roy Analyst", "email": "roy@example.com", "password": "secret123"},
    )
    login_response = client.post(
        "/auth/login",
        json={"email": "roy@example.com", "password": "secret123"},
    )
    me_response = client.get("/me", headers={"Authorization": "Bearer token-123"})
    scans_response = client.get("/me/scans?limit=5&days=30", headers={"Authorization": "Bearer token-123"})

    assert register_response.status_code == 200
    assert register_response.json()["token"] == "token-123"

    assert login_response.status_code == 200
    assert login_response.json()["user"]["email"] == "roy@example.com"

    assert me_response.status_code == 200
    assert me_response.json()["user"]["name"] == "Roy Analyst"

    assert scans_response.status_code == 200
    assert scans_response.json()["count"] == 1
    assert scans_response.json()["items"][0]["normalized_url"] == "https://github.com"
