"""Тесты ASGI-приложения (starlette)."""

import json


from starlette.testclient import TestClient

from phantom.api.asgi_app import create_asgi_app, _TokenBucket

API_KEY = "test-api-key-very-long-string-12345"


def _app(**kwargs):
    defaults = {
        "health_provider": lambda: {"status": "ok"},
        "security_mode": "api_key",
        "api_key": API_KEY,
        "rate_limit_per_minute": 1000,
    }
    defaults.update(kwargs)
    return create_asgi_app(**defaults)


def _client(**kwargs) -> TestClient:
    return TestClient(_app(**kwargs))


def _auth_headers(key: str = API_KEY) -> dict:
    return {"Authorization": f"Bearer {key}"}


# ---------- Health / Metrics ----------


def test_health_no_auth():
    client = _client()
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_health_v1_no_auth():
    client = _client()
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200


def test_metrics_endpoint():
    client = _client()
    resp = client.get("/metrics")
    # Либо 200 (prometheus), либо 501 (не установлен)
    assert resp.status_code in {200, 501}


# ---------- Аутентификация ----------


def test_incidents_requires_auth():
    client = _client()
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 401


def test_incidents_with_valid_key():
    client = _client()
    resp = client.get("/api/v1/incidents", headers=_auth_headers())
    assert resp.status_code == 200


def test_incidents_with_invalid_key():
    client = _client()
    resp = client.get("/api/v1/incidents", headers=_auth_headers("wrong-key"))
    assert resp.status_code == 401


def test_auth_bearer_prefix_required():
    client = _client()
    resp = client.get("/api/v1/incidents", headers={"Authorization": API_KEY})
    assert resp.status_code == 401


def test_multi_key_auth():
    client = _client(api_keys={"key-admin": "admin", "key-viewer": "viewer"})
    # Admin key
    resp = client.get("/api/v1/incidents", headers=_auth_headers("key-admin"))
    assert resp.status_code == 200
    # Viewer key
    resp = client.get("/api/v1/incidents", headers=_auth_headers("key-viewer"))
    assert resp.status_code == 200


# ---------- RBAC ----------


def test_blocks_requires_admin():
    client = _client(api_keys={"viewer-key": "viewer"})
    resp = client.post(
        "/api/v1/blocks",
        headers=_auth_headers("viewer-key"),
        content=json.dumps({"kind": "ip", "targets": ["1.2.3.4"]}),
    )
    assert resp.status_code == 403


def test_policies_mode_change_forbidden():
    client = _client()
    resp = client.post(
        "/api/v1/policies",
        headers=_auth_headers(),
        content=json.dumps({"mode": "observation"}),
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "mode_change_forbidden"


def test_put_policies_mode_change_forbidden():
    client = _client()
    resp = client.put(
        "/api/v1/policies",
        headers=_auth_headers(),
        content=json.dumps({"mode": "dry_run"}),
    )
    assert resp.status_code == 403


# ---------- Rate Limiting ----------


def test_rate_limit_not_applied_to_health():
    client = _client(rate_limit_per_minute=1)
    for _ in range(5):
        resp = client.get("/health")
        assert resp.status_code == 200


def test_rate_limit_applied_to_api():
    client = _client(rate_limit_per_minute=2)
    for i in range(5):
        resp = client.get("/api/v1/incidents", headers=_auth_headers())
    # Последние запросы должны быть 429
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


# ---------- Token Bucket ----------


def test_token_bucket_consume():
    bucket = _TokenBucket(capacity=5, rate=1.0)
    assert bucket.consume() is True
    assert bucket.consume() is True


def test_token_bucket_exhaustion():
    bucket = _TokenBucket(capacity=2, rate=0.0)
    assert bucket.consume() is True
    assert bucket.consume() is True
    assert bucket.consume() is False


# ---------- Request Size Limit ----------


def test_body_too_large():
    client = _client()
    resp = client.post(
        "/api/v1/incidents",
        headers={**_auth_headers(), "Content-Length": "2000000"},
        content=b"x" * 100,
    )
    assert resp.status_code == 413


def test_body_invalid_content_length():
    client = _client()
    resp = client.post(
        "/api/v1/incidents",
        headers={**_auth_headers(), "Content-Length": "abc"},
        content=b"{}",
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_content_length"


def test_body_negative_content_length():
    client = _client()
    resp = client.post(
        "/api/v1/incidents",
        headers={**_auth_headers(), "Content-Length": "-1"},
        content=b"{}",
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_content_length"


# ---------- 404 ----------


def test_not_found():
    client = _client()
    resp = client.get("/api/v1/nonexistent", headers=_auth_headers())
    assert resp.status_code in {404, 405}


# ---------- JWT endpoints ----------


def test_auth_token_no_jwt():
    client = _client()
    resp = client.post(
        "/api/v1/auth/token",
        headers=_auth_headers(),
        content=json.dumps({}),
    )
    assert resp.status_code == 501
    assert resp.json()["error"] == "jwt_not_configured"


def test_auth_refresh_no_jwt():
    client = _client()
    resp = client.post(
        "/api/v1/auth/refresh",
        content=json.dumps({"refresh_token": "abc"}),
    )
    assert resp.status_code == 501


def test_auth_token_with_jwt():
    from phantom.api.auth import JWTProvider

    jwt = JWTProvider(secret="a" * 64)
    client = _client(jwt_provider=jwt, security_mode="both")
    resp = client.post(
        "/api/v1/auth/token",
        headers=_auth_headers(),
        content=json.dumps({"subject": "testuser"}),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_jwt_auth_flow():
    from phantom.api.auth import JWTProvider

    jwt_prov = JWTProvider(secret="b" * 64)
    client = _client(jwt_provider=jwt_prov, security_mode="jwt")

    # Получаем токен через API-ключ
    resp = client.post(
        "/api/v1/auth/token",
        headers=_auth_headers(),
        content=json.dumps({}),
    )
    assert resp.status_code == 200
    tokens = resp.json()

    # Используем JWT для запроса
    resp = client.get(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert resp.status_code == 200


def test_mtls_mode_rejects_verified_header_without_proxy_token():
    app = _app(security_mode="mtls", api_key=None, api_keys=None)
    with TestClient(app, client=("127.0.0.1", 33001)) as client:
        resp = client.get(
            "/api/v1/incidents",
            headers={
                "x-client-cert-verified": "SUCCESS",
                "x-client-cert-subject": "CN=trusted-client",
            },
        )
    assert resp.status_code == 401


def test_mtls_mode_accepts_only_with_loopback_verified_subject_and_proxy_token():
    app = _app(
        security_mode="mtls",
        api_key=None,
        api_keys=None,
        mtls_proxy_token="proxy-shared-secret",
    )
    with TestClient(app, client=("127.0.0.1", 33002)) as client:
        resp = client.get(
            "/api/v1/incidents",
            headers={
                "x-client-cert-verified": "SUCCESS",
                "x-client-cert-subject": "CN=trusted-client",
                "x-phantom-mtls-token": "proxy-shared-secret",
            },
        )
    assert resp.status_code == 200


def test_mtls_mode_rejects_non_loopback_even_with_token():
    app = _app(
        security_mode="mtls",
        api_key=None,
        api_keys=None,
        mtls_proxy_token="proxy-shared-secret",
    )
    with TestClient(app, client=("10.0.0.2", 33003)) as client:
        resp = client.get(
            "/api/v1/incidents",
            headers={
                "x-client-cert-verified": "SUCCESS",
                "x-client-cert-subject": "CN=trusted-client",
                "x-phantom-mtls-token": "proxy-shared-secret",
            },
        )
    assert resp.status_code == 401


# ---------- Incident by ID ----------


def test_get_incident_not_found():
    client = _client()
    resp = client.get("/api/v1/incidents/nonexistent", headers=_auth_headers())
    assert resp.status_code == 404
