import secrets
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

import CyberGuardAI as server
import cyberguard.auth.router as auth_router
import cyberguard.auth.security as auth_security
import cyberguard.db.session as database
from cyberguard.core.config import settings as app_settings
from cyberguard.db.models import User


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)

        database_file = Path(self.temp_directory.name) / "auth-tests.sqlite3"
        self.engine = database.create_database_engine(
            "sqlite:///{}".format(database_file.as_posix())
        )
        self.addCleanup(self.engine.dispose)

        session_factory = sessionmaker(
            bind=self.engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
        self.session_factory = session_factory
        self.session_factory_patch = patch.object(database, "SessionLocal", session_factory)
        self.session_factory_patch.start()
        self.addCleanup(self.session_factory_patch.stop)

        self.initialize_patch = patch.object(
            server,
            "initialize_database",
            side_effect=lambda: database.initialize_database(self.engine),
        )
        self.initialize_patch.start()
        self.addCleanup(self.initialize_patch.stop)

        self.dispose_patch = patch.object(server, "dispose_database", self.engine.dispose)
        self.dispose_patch.start()
        self.addCleanup(self.dispose_patch.stop)

        self.csv_file_patch = patch.object(
            server, "CSV_FILE", str(Path(self.temp_directory.name) / "scan_history.csv")
        )
        self.csv_file_patch.start()
        self.addCleanup(self.csv_file_patch.stop)

        self.client_patch = patch.object(server, "client", None)
        self.client_patch.start()
        self.addCleanup(self.client_patch.stop)

        test_settings = replace(
            app_settings,
            jwt_secret_key=secrets.token_urlsafe(48),
        )
        self.security_settings_patch = patch.object(auth_security, "settings", test_settings)
        self.security_settings_patch.start()
        self.addCleanup(self.security_settings_patch.stop)

        self.router_settings_patch = patch.object(auth_router, "settings", test_settings)
        self.router_settings_patch.start()
        self.addCleanup(self.router_settings_patch.stop)

        self.http = TestClient(server.app)
        self.http.__enter__()
        self.addCleanup(self.http.__exit__, None, None, None)

    def register(self, username="alice", email="alice@example.com", password="correct-horse-battery"):
        return self.http.post(
            "/auth/register",
            json={"username": username, "email": email, "password": password},
        )

    def login(self, email="alice@example.com", password="correct-horse-battery"):
        return self.http.post("/auth/login", json={"email": email, "password": password})

    def authorization(self):
        response = self.login()
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": "Bearer " + response.json()["access_token"]}

    def test_registration_returns_safe_user_profile(self):
        response = self.register()

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["username"], "alice")
        self.assertEqual(response.json()["email"], "alice@example.com")
        self.assertEqual(response.json()["role"], "user")
        self.assertNotIn("password_hash", response.json())
        self.assertNotIn("password", response.json())

    def test_duplicate_registration_is_rejected_case_insensitively(self):
        self.assertEqual(self.register().status_code, 201)

        duplicate = self.register(username="another", email="ALICE@example.com")

        self.assertEqual(duplicate.status_code, 409)

    def test_registration_validates_password_username_and_email(self):
        short_password = self.register(password="short")
        invalid_username = self.register(username="bad name")
        invalid_email = self.register(email="not-an-email")

        self.assertEqual(short_password.status_code, 422)
        self.assertEqual(invalid_username.status_code, 422)
        self.assertEqual(invalid_email.status_code, 422)

    def test_invalid_login_returns_generic_unauthorized(self):
        self.register()

        response = self.login(password="wrong-password-value")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid email or password."})

    def test_successful_login_returns_bearer_token(self):
        self.register()

        response = self.login()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["token_type"], "bearer")
        self.assertGreater(response.json()["expires_in"], 0)
        self.assertTrue(response.json()["access_token"])

    def test_protected_endpoints_reject_requests_without_token(self):
        results = [
            self.http.get("/api/history"),
            self.http.get("/api/stats"),
            self.http.post("/api/scan/url", json={"url": "https://example.com"}),
            self.http.post("/api/scan/email", json={"content": "suspicious email"}),
            self.http.post("/api/scan/tip", json={"topic": "passwords"}),
        ]

        self.assertEqual([response.status_code for response in results], [401] * 5)

    def test_valid_token_allows_protected_endpoint_and_me_excludes_hash(self):
        self.register()
        headers = self.authorization()

        stats = self.http.get("/api/stats", headers=headers)
        profile = self.http.get("/auth/me", headers=headers)

        self.assertEqual(stats.status_code, 200)
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.json()["email"], "alice@example.com")
        self.assertEqual(profile.json()["role"], "user")
        self.assertNotIn("password_hash", profile.json())

    def test_database_stores_only_password_hash(self):
        self.register(password="correct-horse-battery")

        with self.session_factory() as db:
            user = db.query(User).filter(User.email == "alice@example.com").one()
            stored_hash = user.password_hash

        self.assertNotEqual(stored_hash, "correct-horse-battery")
        self.assertTrue(auth_security.verify_password("correct-horse-battery", stored_hash))

    def test_logout_revokes_current_session(self):
        self.register()
        headers = self.authorization()

        logout = self.http.post("/auth/logout", headers=headers)
        profile = self.http.get("/auth/me", headers=headers)

        self.assertEqual(logout.status_code, 204)
        self.assertEqual(profile.status_code, 401)


if __name__ == "__main__":
    unittest.main()
