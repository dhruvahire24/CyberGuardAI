import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

import CyberGuardAI as server
from cyberguard.core.config import Settings
from cyberguard.db import Base
from cyberguard.db import session as database


class SettingsTests(unittest.TestCase):
    def test_development_defaults_to_local_sqlite_without_secrets(self):
        settings = Settings.from_env({"CYBERGUARD_ENV": "development"})

        self.assertEqual(settings.database_url, "sqlite:///./cyberguard.db")
        self.assertEqual(settings.cors_origins[0], "http://localhost:3000")
        self.assertGreaterEqual(len(settings.jwt_secret_key.encode("utf-8")), 32)
        self.assertNotIn("GEMINI", repr(settings))
        self.assertNotIn("DATABASE_URL", repr(settings))

    def test_development_generates_ephemeral_jwt_secrets(self):
        first = Settings.from_env({"CYBERGUARD_ENV": "development"})
        second = Settings.from_env({"CYBERGUARD_ENV": "development"})

        self.assertNotEqual(first.jwt_secret_key, second.jwt_secret_key)
        self.assertNotIn(first.jwt_secret_key, repr(first))

    def test_short_configured_jwt_secret_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "JWT_SECRET_KEY"):
            Settings.from_env(
                {
                    "CYBERGUARD_ENV": "development",
                    "JWT_SECRET_KEY": "too-short",
                }
            )

    def test_production_requires_postgresql_and_https_cors_origins(self):
        with self.assertRaisesRegex(ValueError, "PostgreSQL"):
            Settings.from_env({"CYBERGUARD_ENV": "production"})

        with self.assertRaisesRegex(ValueError, "JWT_SECRET_KEY"):
            Settings.from_env(
                {
                    "CYBERGUARD_ENV": "production",
                    "DATABASE_URL": "postgresql://user:secret@db.example/cyberguard",
                    "JWT_SECRET_KEY": "replace_with_a_random_secret_at_least_32_bytes",
                    "CYBERGUARD_CORS_ORIGINS": "https://dashboard.example",
                }
            )

        with self.assertRaisesRegex(ValueError, "valid origins"):
            Settings.from_env(
                {
                    "CYBERGUARD_ENV": "production",
                    "DATABASE_URL": "postgresql://user:secret@db.example/cyberguard",
                    "JWT_SECRET_KEY": "test-only-secret-value-with-at-least-32-bytes",
                    "CYBERGUARD_CORS_ORIGINS": "http://dashboard.example",
                }
            )

    def test_production_normalizes_postgresql_url_and_hides_credentials(self):
        settings = Settings.from_env(
            {
                "CYBERGUARD_ENV": "production",
                "DATABASE_URL": "postgresql://user:secret@db.example/cyberguard",
                "JWT_SECRET_KEY": "test-only-secret-value-with-at-least-32-bytes",
                "GEMINI_API_KEY": "test-gemini-key",
                "CYBERGUARD_CORS_ORIGINS": "https://dashboard.example",
            }
        )

        self.assertEqual(
            settings.database_url,
            "postgresql+psycopg://user:secret@db.example/cyberguard",
        )
        self.assertNotIn("secret", repr(settings))
        self.assertNotIn("test-gemini-key", repr(settings))


class DatabaseFoundationTests(unittest.TestCase):
    def test_app_lifespan_initializes_and_disposes_database(self):
        with patch.object(server, "initialize_database") as initialize:
            with patch.object(server, "dispose_database") as dispose:
                with TestClient(server.app) as http:
                    self.assertEqual(http.get("/").status_code, 200)

        initialize.assert_called_once_with()
        dispose.assert_called_once_with()

    def test_sqlite_connection_initializes_auth_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            database_file = Path(directory) / "foundation.sqlite3"
            engine = database.create_database_engine("sqlite:///{}".format(database_file))
            try:
                database.initialize_database(engine)

                self.assertTrue(database_file.exists())
                self.assertEqual(
                    set(Base.metadata.tables),
                    {"users", "user_sessions"},
                )
            finally:
                engine.dispose()

    def test_session_dependency_closes_session(self):
        session = Mock()
        with patch.object(database, "SessionLocal", return_value=session):
            dependency = database.get_db()
            self.assertIs(next(dependency), session)
            with self.assertRaises(StopIteration):
                next(dependency)

        session.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
