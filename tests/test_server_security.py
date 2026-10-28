"""Server security regressions against an isolated PostgreSQL database.

Set TEST_SERVER_DATABASE_URL to a disposable postgresql+psycopg database.
The fixture creates and removes a temporary schema for each test.
Only the external memory/LLM backend is replaced with synthetic data.
"""

import importlib
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema


@pytest.fixture
def server(monkeypatch):
    url = os.environ.get("TEST_SERVER_DATABASE_URL")
    if not url:
        pytest.skip("TEST_SERVER_DATABASE_URL must identify a disposable database")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "server"))
    monkeypatch.setenv("JWT_SECRET", "synthetic-test-signing-secret-not-for-production")
    monkeypatch.setenv("BOOTSTRAP_SECRET", "synthetic-bootstrap-token-for-local-tests")
    monkeypatch.setenv("MEM0_TELEMETRY", "false")
    monkeypatch.setenv("AUTH_DISABLED", "false")
    monkeypatch.setenv("ADMIN_API_KEY", "")

    import db
    import models  # noqa: F401

    import mem0

    root_engine = create_engine(url)
    schema = f"mem0_security_{uuid.uuid4().hex}"
    with root_engine.begin() as connection:
        connection.execute(CreateSchema(schema))
    engine = root_engine.execution_options(schema_translate_map={None: schema})
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    db.Base.metadata.create_all(engine)
    monkeypatch.setattr(db, "SessionLocal", factory)
    auth = importlib.import_module("auth")
    monkeypatch.setattr(auth, "SessionLocal", factory)
    monkeypatch.setattr(auth, "JWT_SECRET", os.environ["JWT_SECRET"])
    monkeypatch.setattr(auth, "ADMIN_API_KEY", "")
    monkeypatch.setattr(auth, "AUTH_DISABLED", False)
    reset_script = importlib.import_module("server.scripts.reset_admin_password")
    monkeypatch.setattr(reset_script, "SessionLocal", factory)
    memory = MagicMock()
    memory.get.return_value = {"id": "synthetic-memory", "memory": "private", "user_id": "other-user"}
    memory.get_all.return_value = {"results": [memory.get.return_value]}
    memory.search.return_value = {"results": [memory.get.return_value]}
    memory.add.return_value = {"results": []}
    memory.update.return_value = {"message": "updated"}
    memory.history.return_value = []
    monkeypatch.setattr(mem0.Memory, "from_config", lambda config: memory)
    main = importlib.import_module("main")
    monkeypatch.setattr(main, "SessionLocal", factory)
    import server_state

    server_state.set_session_factory(factory)
    server_state.initialize_state(main.DEFAULT_CONFIG)
    main.app.state.limiter.reset()
    try:
        with TestClient(main.app) as client:
            yield client, factory, memory
    finally:
        with root_engine.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))
        root_engine.dispose()


def register(client, **kwargs):
    return client.post(
        "/auth/register",
        json={"name": "Admin", "email": "admin@example.com", "password": "synthetic-password"},
        **kwargs,
    )


def test_first_admin_requires_bootstrap_proof_even_with_legacy_admin_key(server, monkeypatch):
    client, _, _ = server
    import auth

    monkeypatch.setattr(auth, "ADMIN_API_KEY", "synthetic-legacy-admin-key")
    assert register(client).status_code == 401
    assert register(client, headers={"X-Bootstrap-Secret": "wrong"}).status_code == 401
    assert client.get("/auth/setup-status").json() == {"needsSetup": True}
    response = register(client, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]})
    assert response.status_code == 200
    assert "access_token" in response.json()


def admin_tokens(client):
    response = register(client, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]})
    assert response.status_code == 200
    return response.json()


def bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_password_change_revokes_access_refresh_and_api_keys(server):
    client, _, _ = server
    tokens = admin_tokens(client)
    key = client.post(
        "/api-keys", headers=bearer(tokens), json={"label": "old key", "password": "synthetic-password"}
    ).json()["key"]
    rotated = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()
    assert "access_token" in rotated
    response = client.post(
        "/auth/change-password",
        headers=bearer(rotated),
        json={"current_password": "synthetic-password", "new_password": "new-synthetic-password"},
    )
    assert response.status_code == 200
    assert client.get("/auth/me", headers=bearer(tokens)).status_code == 401
    assert client.get("/auth/me", headers=bearer(rotated)).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": rotated["refresh_token"]}).status_code == 401
    assert client.get("/auth/me", headers={"X-API-Key": key}).status_code == 401
    assert (
        client.post(
            "/auth/login", json={"email": "admin@example.com", "password": "new-synthetic-password"}
        ).status_code
        == 200
    )


def test_logout_revokes_all_browser_sessions_with_refresh_proof_and_preserves_keys(server):
    client, _, _ = server
    first = admin_tokens(client)
    second = client.post("/auth/login", json={"email": "admin@example.com", "password": "synthetic-password"}).json()
    key = client.post(
        "/api-keys", headers=bearer(first), json={"label": "service key", "password": "synthetic-password"}
    ).json()["key"]
    assert client.post("/auth/logout", json={"refresh_token": first["refresh_token"]}).status_code == 200
    for tokens in (first, second):
        assert client.get("/auth/me", headers=bearer(tokens)).status_code == 401
        assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.get("/auth/me", headers={"X-API-Key": key}).status_code == 200
    fresh = client.post("/auth/login", json={"email": "admin@example.com", "password": "synthetic-password"}).json()
    assert client.post("/auth/logout", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.get("/auth/me", headers=bearer(fresh)).status_code == 200


def test_logout_still_revokes_sessions_when_another_caller_already_rotated_the_cookie(server):
    client, _, _ = server
    original = admin_tokens(client)
    rotated = client.post("/auth/refresh", json={"refresh_token": original["refresh_token"]}).json()
    other = client.post("/auth/login", json={"email": "admin@example.com", "password": "synthetic-password"}).json()
    assert client.post("/auth/logout", json={"refresh_token": original["refresh_token"]}).status_code == 200
    for tokens in (rotated, other):
        assert client.get("/auth/me", headers=bearer(tokens)).status_code == 401
        assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    fresh = client.post("/auth/login", json={"email": "admin@example.com", "password": "synthetic-password"}).json()
    assert client.post("/auth/logout", json={"refresh_token": original["refresh_token"]}).status_code == 401
    assert client.get("/auth/me", headers=bearer(fresh)).status_code == 200


SHARED_ROUTES = [
    ("GET", "/configure", None),
    ("GET", "/configure/providers", None),
    ("POST", "/configure", {"version": "v1.1"}),
    ("POST", "/generate-instructions", {"use_case": "synthetic test"}),
    ("POST", "/memories", {"user_id": "other-user", "messages": [{"role": "user", "content": "test"}]}),
    ("GET", "/memories?user_id=other-user", None),
    ("GET", "/memories", None),
    ("GET", "/memories/synthetic-memory", None),
    ("POST", "/search", {"query": "private", "filters": {"user_id": "other-user"}}),
    ("PUT", "/memories/synthetic-memory", {"text": "tampered"}),
    ("GET", "/memories/synthetic-memory/history", None),
    ("DELETE", "/memories/synthetic-memory", None),
    ("DELETE", "/memories?user_id=other-user", None),
    ("POST", "/reset", None),
    ("GET", "/entities", None),
    ("DELETE", "/entities/user/other-user", None),
]


@pytest.mark.parametrize("credential_type", ["jwt", "api_key"])
def test_non_admin_cannot_access_any_shared_data_route(server, credential_type):
    client, factory, memory = server
    admin_tokens(client)
    from auth import hash_password
    from models import User

    with factory() as db:
        db.add(
            User(name="Member", email="member@example.com", password_hash=hash_password("member-password"), role="user")
        )
        db.commit()
    tokens = client.post("/auth/login", json={"email": "member@example.com", "password": "member-password"}).json()
    headers = bearer(tokens)
    if credential_type == "api_key":
        key = client.post(
            "/api-keys", headers=headers, json={"label": "member key", "password": "member-password"}
        ).json()["key"]
        headers = {"X-API-Key": key}
    memory.reset_mock()
    for method, path, body in SHARED_ROUTES:
        response = client.request(method, path, headers=headers, json=body)
        assert response.status_code == 403, (method, path, response.text)
    assert not memory.mock_calls


@pytest.mark.parametrize("token", [None, "short"])
def test_unconfigured_bootstrap_fails_closed(server, monkeypatch, token):
    client, _, _ = server
    if token is None:
        monkeypatch.delenv("BOOTSTRAP_SECRET")
    else:
        monkeypatch.setenv("BOOTSTRAP_SECRET", token)
    assert register(client, headers={"X-Bootstrap-Secret": token or ""}).status_code == 401
    assert client.get("/auth/setup-status").json() == {"needsSetup": True}


def test_registration_closes_after_valid_bootstrap(server):
    client, _, _ = server
    admin_tokens(client)
    assert register(client, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]}).status_code == 403


@pytest.mark.parametrize("credential_type", ["jwt", "api_key", "legacy"])
def test_admin_retains_memory_access(server, monkeypatch, credential_type):
    client, _, _ = server
    tokens = admin_tokens(client)
    headers = bearer(tokens)
    if credential_type == "api_key":
        key = client.post(
            "/api-keys", headers=headers, json={"label": "admin key", "password": "synthetic-password"}
        ).json()["key"]
        headers = {"X-API-Key": key}
    elif credential_type == "legacy":
        import auth

        monkeypatch.setattr(auth, "ADMIN_API_KEY", "synthetic-legacy-admin-key")
        headers = {"X-API-Key": "synthetic-legacy-admin-key"}
    assert client.get("/memories/synthetic-memory", headers=headers).status_code == 200
    assert client.get("/memories?user_id=application-user", headers=headers).status_code == 200


def test_anonymous_cannot_access_shared_routes(server):
    client, _, memory = server
    memory.reset_mock()
    for method, path, body in SHARED_ROUTES:
        assert client.request(method, path, json=body).status_code == 401
    assert not memory.mock_calls


def test_host_password_reset_revokes_sessions_and_keys(server, monkeypatch):
    client, _, _ = server
    tokens = admin_tokens(client)
    key = client.post(
        "/api-keys", headers=bearer(tokens), json={"label": "old key", "password": "synthetic-password"}
    ).json()["key"]
    from server.scripts import reset_admin_password

    monkeypatch.setenv("EMAIL", "admin@example.com")
    monkeypatch.setenv("PASSWORD", "reset-synthetic-password")
    assert reset_admin_password.main() == 0
    assert client.get("/auth/me", headers=bearer(tokens)).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.get("/auth/me", headers={"X-API-Key": key}).status_code == 401
    assert (
        client.post(
            "/auth/login", json={"email": "admin@example.com", "password": "reset-synthetic-password"}
        ).status_code
        == 200
    )


@pytest.mark.parametrize("kind", ["access", "refresh"])
@pytest.mark.parametrize("version", [None, False, "0", -1])
def test_missing_or_malformed_token_version_fails_closed(server, kind, version):
    client, _, _ = server
    tokens = admin_tokens(client)
    from jose import jwt

    payload = jwt.decode(tokens[f"{kind}_token"], os.environ["JWT_SECRET"], algorithms=["HS256"])
    if version is None:
        payload.pop("auth_version")
    else:
        payload["auth_version"] = version
    token = jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")
    if kind == "access":
        response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    else:
        response = client.post("/auth/refresh", json={"refresh_token": token})
    assert response.status_code == 401


def test_concurrent_refresh_is_single_use(server):
    client, _, _ = server
    tokens = admin_tokens(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(client.post, "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}) for _ in range(2)
        ]
        responses = [future.result(timeout=10) for future in futures]
    assert sorted(response.status_code for response in responses) == [200, 401]
    rotated = next(response.json() for response in responses if response.status_code == 200)
    assert client.get("/auth/me", headers=bearer(rotated)).status_code == 401


@pytest.mark.parametrize("racing_operation", ["refresh", "login", "api-key"])
def test_password_change_cannot_race_to_issue_valid_old_credentials(server, racing_operation):
    client, _, _ = server
    tokens = admin_tokens(client)
    if racing_operation == "refresh":
        path, body, headers = "/auth/refresh", {"refresh_token": tokens["refresh_token"]}, {}
    elif racing_operation == "login":
        path, body, headers = "/auth/login", {"email": "admin@example.com", "password": "synthetic-password"}, {}
    else:
        path, body, headers = "/api-keys", {"label": "racing key", "password": "synthetic-password"}, bearer(tokens)
    with ThreadPoolExecutor(max_workers=2) as pool:
        issuance = pool.submit(client.post, path, json=body, headers=headers)
        change = pool.submit(
            client.post,
            "/auth/change-password",
            headers=bearer(tokens),
            json={"current_password": "synthetic-password", "new_password": "new-synthetic-password"},
        )
        assert change.result(timeout=10).status_code == 200
        response = issuance.result(timeout=10)
    assert response.status_code in (200, 201, 401)
    if response.status_code != 401:
        issued = response.json()
        if racing_operation == "api-key":
            assert client.get("/auth/me", headers={"X-API-Key": issued["key"]}).status_code == 401
        else:
            assert client.get("/auth/me", headers=bearer(issued)).status_code == 401
            assert client.post("/auth/refresh", json={"refresh_token": issued["refresh_token"]}).status_code == 401


def test_failed_refresh_issuance_does_not_consume_the_original_token(server):
    client, factory, _ = server
    tokens = admin_tokens(client)

    def fail_refresh_insert(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("INSERT INTO ") and "refresh_token_jtis" in statement:
            raise RuntimeError("synthetic storage failure")

    engine = factory.kw["bind"]
    event.listen(engine, "before_cursor_execute", fail_refresh_insert)
    try:
        with pytest.raises(RuntimeError, match="synthetic storage failure"):
            client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    finally:
        event.remove(engine, "before_cursor_execute", fail_refresh_insert)
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 200


def test_key_authentication_waiting_on_password_reset_rechecks_revocation(server, monkeypatch):
    client, factory, _ = server
    tokens = admin_tokens(client)
    key = client.post(
        "/api-keys", headers=bearer(tokens), json={"label": "compromised", "password": "synthetic-password"}
    ).json()["key"]
    from server.scripts import reset_admin_password

    monkeypatch.setenv("EMAIL", "admin@example.com")
    monkeypatch.setenv("PASSWORD", "reset-synthetic-password")
    reset_locked = threading.Event()
    key_scanned = threading.Event()
    allow_reset = threading.Event()
    reset_thread = None

    def coordinate(_connection, _cursor, statement, _parameters, _context, _executemany):
        if threading.get_ident() == reset_thread and "FOR UPDATE" in statement:
            reset_locked.set()
            assert allow_reset.wait(10), "reset was not released"
        elif statement.startswith("SELECT") and ".api_keys" in statement:
            key_scanned.set()

    def reset():
        nonlocal reset_thread
        reset_thread = threading.get_ident()
        return reset_admin_password.main()

    engine = factory.kw["bind"]
    event.listen(engine, "after_cursor_execute", coordinate)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            recovery = pool.submit(reset)
            try:
                assert reset_locked.wait(10), "reset did not acquire the user lock"
                pending_auth = pool.submit(client.get, "/auth/me", headers={"X-API-Key": key})
                assert key_scanned.wait(10), "authentication did not scan the old key"
            finally:
                allow_reset.set()
            assert recovery.result(timeout=10) == 0
            assert pending_auth.result(timeout=10).status_code == 401
    finally:
        event.remove(engine, "after_cursor_execute", coordinate)
