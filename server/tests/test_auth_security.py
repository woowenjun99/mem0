import os
import unittest
from unittest.mock import patch

os.environ["MEM0_TELEMETRY"] = "false"
os.environ["JWT_SECRET"] = "test-jwt-secret-not-for-production"
os.environ["BOOTSTRAP_SECRET"] = "test-bootstrap-secret-not-for-production"

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import auth
from db import Base, get_db
from rate_limit import limiter
from routers import auth as auth_router


class AuthSecurityTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.sessions = sessionmaker(bind=engine, expire_on_commit=False)
        self.patch = patch.object(auth, "SessionLocal", self.sessions)
        self.patch.start()
        self.limit_patch = patch.object(limiter, "enabled", False)
        self.limit_patch.start()
        app = FastAPI()
        app.state.limiter = limiter
        app.include_router(auth_router.router)

        def get_test_db():
            with self.sessions() as db:
                yield db

        app.dependency_overrides[get_db] = get_test_db
        self.client = TestClient(app)

    def tearDown(self):
        self.patch.stop()
        self.limit_patch.stop()

    def test_registration_requires_bootstrap_secret(self):
        body = {"name": "Admin", "email": "admin@example.com", "password": "password123"}
        self.assertEqual(self.client.post("/auth/register", json=body).status_code, 401)
        self.assertEqual(
            self.client.post("/auth/register", json=body, headers={"X-Bootstrap-Secret": "wrong"}).status_code, 401
        )
        with patch.dict(os.environ, {"BOOTSTRAP_SECRET": ""}):
            self.assertEqual(
                self.client.post("/auth/register", json=body, headers={"X-Bootstrap-Secret": "anything"}).status_code,
                401,
            )
        self.assertEqual(
            self.client.post(
                "/auth/register", json=body, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]}
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/auth/register", json=body, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]}
            ).status_code,
            403,
        )

    def test_password_change_invalidates_existing_sessions(self):
        body = {"name": "Admin", "email": "admin@example.com", "password": "password123"}
        registered = self.client.post(
            "/auth/register", json=body, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]}
        ).json()
        login = self.client.post("/auth/login", json={"email": body["email"], "password": body["password"]}).json()
        headers = {"Authorization": "Bearer " + registered["access_token"]}
        changed = self.client.post(
            "/auth/change-password",
            headers=headers,
            json={"current_password": body["password"], "new_password": "new-password123"},
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(self.client.get("/auth/me", headers=headers).status_code, 401)
        self.assertEqual(
            self.client.post("/auth/refresh", json={"refresh_token": login["refresh_token"]}).status_code, 401
        )
        self.assertEqual(
            self.client.post("/auth/login", json={"email": body["email"], "password": "new-password123"}).status_code,
            200,
        )

    def test_logout_revokes_refresh_token(self):
        body = {"name": "Admin", "email": "admin@example.com", "password": "password123"}
        tokens = self.client.post(
            "/auth/register", json=body, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]}
        ).json()
        self.assertEqual(
            self.client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]}).status_code, 200
        )
        self.assertEqual(
            self.client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code, 401
        )

    def test_admin_password_reset_invalidates_sessions(self):
        from scripts import reset_admin_password

        body = {"name": "Admin", "email": "admin@example.com", "password": "password123"}
        tokens = self.client.post(
            "/auth/register", json=body, headers={"X-Bootstrap-Secret": os.environ["BOOTSTRAP_SECRET"]}
        ).json()
        with (
            patch.object(reset_admin_password, "SessionLocal", self.sessions),
            patch.dict(os.environ, {"EMAIL": body["email"], "PASSWORD": "replacement-password"}),
        ):
            self.assertEqual(reset_admin_password.main(), 0)
        self.assertEqual(
            self.client.get("/auth/me", headers={"Authorization": "Bearer " + tokens["access_token"]}).status_code, 401
        )
        self.assertEqual(
            self.client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code, 401
        )


if __name__ == "__main__":
    unittest.main()
