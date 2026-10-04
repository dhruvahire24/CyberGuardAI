import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

import CyberGuardAI as server


class ExistingAPIContractTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)

        original_csv_file = server.CSV_FILE
        server.CSV_FILE = str(Path(self.temp_directory.name) / "scan_history.csv")
        self.addCleanup(setattr, server, "CSV_FILE", original_csv_file)

        original_client = server.client
        server.client = None
        self.addCleanup(setattr, server, "client", original_client)

        self.http = TestClient(server.app)

    @staticmethod
    def mocked_gemini(payload):
        gemini_client = Mock()
        gemini_client.models.generate_content.return_value = SimpleNamespace(
            text=json.dumps(payload)
        )
        return gemini_client

    def test_url_scan_preserves_response_contract_and_updates_history(self):
        result = {
            "risk_score": 2,
            "verdict": "Safe",
            "reasoning": "No notable indicators.",
            "recommendations": ["Continue to verify the domain."],
        }
        with patch.object(server, "get_gemini_client", return_value=self.mocked_gemini(result)):
            response = self.http.post("/api/scan/url", json={"url": "https://example.com"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), result)

        history = self.http.get("/api/history")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json()[0]["scan_type"], "URL")
        self.assertEqual(history.json()[0]["verdict"], "Safe")

        stats = self.http.get("/api/stats")
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(stats.json()["total_scans"], 1)
        self.assertEqual(stats.json()["safe_count"], 1)

    def test_email_and_tip_scan_response_contracts(self):
        email_result = {
            "risk_score": 8,
            "verdict": "Phishing",
            "phishing_indicators": ["Urgent credential request"],
            "reasoning": "The email requests account credentials.",
            "recommendations": ["Do not follow its links."],
        }
        tip_result = {
            "topic": "Account security",
            "headline": "Use multifactor authentication",
            "explanation": "It adds a second verification step.",
            "action_items": ["Enable MFA on important accounts."],
        }
        with patch.object(server, "get_gemini_client", return_value=self.mocked_gemini(email_result)):
            email_response = self.http.post(
                "/api/scan/email", json={"content": "Please verify your account now."}
            )
        with patch.object(server, "get_gemini_client", return_value=self.mocked_gemini(tip_result)):
            tip_response = self.http.post("/api/scan/tip", json={"topic": "Account security"})

        self.assertEqual(email_response.status_code, 200)
        self.assertEqual(email_response.json(), email_result)
        self.assertEqual(tip_response.status_code, 200)
        self.assertEqual(tip_response.json(), tip_result)

    def test_validation_rejects_empty_and_oversized_scan_inputs(self):
        with patch.object(server, "get_gemini_client") as get_client:
            empty_url = self.http.post("/api/scan/url", json={"url": "  "})
            empty_email = self.http.post("/api/scan/email", json={"content": "  "})
            long_url = self.http.post("/api/scan/url", json={"url": "x" * 2049})
            long_topic = self.http.post("/api/scan/tip", json={"topic": "x" * 501})

        self.assertEqual(empty_url.status_code, 400)
        self.assertEqual(empty_email.status_code, 400)
        self.assertEqual(long_url.status_code, 422)
        self.assertEqual(long_topic.status_code, 422)
        self.assertEqual(long_url.json(), {"detail": "Invalid request input."})
        self.assertEqual(long_topic.json(), {"detail": "Invalid request input."})
        get_client.assert_not_called()

    def test_api_request_body_limit(self):
        response = self.http.post(
            "/api/scan/url",
            json={"url": "https://example.com", "unused": "x" * (256 * 1024)},
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json(), {"detail": "Request body is too large."})

    def test_provider_errors_are_sanitized(self):
        gemini_client = Mock()
        gemini_client.models.generate_content.side_effect = RuntimeError("private-api-secret")
        with patch.object(server, "get_gemini_client", return_value=gemini_client):
            response = self.http.post("/api/scan/url", json={"url": "https://example.com"})

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {"detail": "Gemini API scan failed. Please try again."},
        )
        self.assertNotIn("private-api-secret", response.text)

    def test_empty_history_and_stats_keep_existing_shapes(self):
        history = self.http.get("/api/history")
        stats = self.http.get("/api/stats")

        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json(), [])
        self.assertEqual(
            stats.json(),
            {
                "total_scans": 0,
                "safe_count": 0,
                "suspicious_count": 0,
                "threat_count": 0,
                "average_risk": 0.0,
            },
        )

    def test_security_headers_and_frontend_route(self):
        response = self.http.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/static/app.js", response.text)
        self.assertEqual(self.http.get("/static/app.js").status_code, 200)
        self.assertEqual(self.http.get("/static/style.css").status_code, 200)
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertIn("content-security-policy", response.headers)

    def test_cors_allows_local_development_origin_but_not_arbitrary_origins(self):
        allowed = self.http.get("/api/stats", headers={"Origin": "http://localhost:5173"})
        denied = self.http.get("/api/stats", headers={"Origin": "https://untrusted.example"})
        preflight = self.http.options(
            "/api/scan/url",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

        self.assertEqual(allowed.headers.get("access-control-allow-origin"), "http://localhost:5173")
        self.assertIsNone(denied.headers.get("access-control-allow-origin"))
        self.assertEqual(preflight.status_code, 200)
        self.assertNotIn("access-control-allow-credentials", preflight.headers)
        self.assertFalse(server.get_cors_origins("production", None))
        with self.assertRaises(ValueError):
            server.get_cors_origins("production", "*")


if __name__ == "__main__":
    unittest.main()
