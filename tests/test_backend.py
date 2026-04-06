from fastapi.testclient import TestClient

import backend
from backend_app.services import storage
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

    monkeypatch.setattr(backend, "fetch_page_content", fake_fetch_page_content)
    monkeypatch.setattr(backend, "check_ssl", fake_check_ssl)
    monkeypatch.setattr(backend, "get_whois_info", fake_get_whois_info)

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

    assert recent_response.status_code == 200
    recent_payload = recent_response.json()
    assert recent_payload["count"] == 1
    assert recent_payload["items"][0]["normalized_url"] == "https://github.com"
