from fastapi.testclient import TestClient

import backend


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
