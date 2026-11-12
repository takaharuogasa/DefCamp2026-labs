#!/usr/bin/env python3
"""Standard-library functional checks for the isolated Email Hunt Lab."""

from __future__ import annotations

import http.cookiejar
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener

import app


class QuietHandler(app.Handler):
    def log_message(self, fmt, *args):
        pass


class EmailHuntFunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="email-hunt-functional-")
        app.DATA_DIR = Path(cls.temp_dir.name)
        app.DB_PATH = app.DATA_DIR / "functional-test.sqlite3"
        app.initialize_database()
        cls.initial_event_count = app.count_rows("events")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)
        cls.temp_dir.cleanup()

    def setUp(self):
        app.reset_database()
        with app.SESSIONS_LOCK:
            app.SESSIONS.clear()
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, method="GET", form=None):
        data = urlencode(form).encode("utf-8") if form is not None else None
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {},
        )
        return self.opener.open(request, timeout=5)

    def login(self, username=app.DEFAULT_USERNAME, password=app.DEFAULT_PASSWORD):
        return self.request("/login", method="POST", form={"username": username, "password": password})

    def test_health_and_sign_in_page(self):
        health = self.request("/health")
        self.assertEqual(json.loads(health.read()), {"status": "ok", "lab": "email-hunt"})

        response = self.request("/")
        body = response.read().decode()
        self.assertIn("Sign in to the responder workspace", body)
        self.assertIn(app.DEFAULT_USERNAME, body)
        self.assertIn(app.DEFAULT_PASSWORD, body)

    def test_default_credentials_open_protected_workspace(self):
        response = self.login()
        body = response.read().decode()
        self.assertEqual(urlparse(response.geturl()).path, "/dashboard")
        self.assertIn("Five proposed hunts", body)

        events = self.request("/api/events?event_type=auth.session_created")
        sessions = json.loads(events.read())["events"]
        self.assertTrue(any(
            event["actor_id"] == app.DEFAULT_USERNAME
            and event["outcome"] == "authenticated"
            and event["session_id"].startswith("LIVE-")
            for event in sessions
        ))

    def test_invalid_credentials_do_not_open_workspace(self):
        response = self.login(password="incorrect-training-password")
        body = response.read().decode()
        self.assertIn("Sign-in failed", body)
        self.assertEqual(urlparse(response.geturl()).path, "/login")

        response = self.request("/dashboard")
        self.assertEqual(urlparse(response.geturl()).path, "/login")

    def test_login_username_parameter_has_the_intended_sql_injection(self):
        response = self.login(username="analyst' OR 1=1-- -", password="incorrect-training-password")
        body = response.read().decode()
        self.assertEqual(urlparse(response.geturl()).path, "/dashboard")
        self.assertIn("Five proposed hunts", body)

        events = self.request("/api/events?event_type=auth.login_attempt")
        login_events = json.loads(events.read())["events"]
        self.assertTrue(any(
            event["details"].get("username_input") == "analyst' OR 1=1-- -"
            and event["outcome"] == "accepted"
            for event in login_events
        ))

    def test_seeded_h03_pivot_reaches_exports_and_active_session(self):
        self.login().read()
        response = self.request("/api/events?source_ip=198.51.100.23")
        events = json.loads(response.read())["events"]
        self.assertTrue(any(
            event["event_type"] == "mail.received" and event["message_id"] == "MSG-303"
            for event in events
        ))
        self.assertTrue(any(
            event["event_type"] == "auth.login_attempt" and "sqlmap" in event["user_agent"]
            for event in events
        ))
        self.assertEqual(sum(event["event_type"] == "data.export" for event in events), 2)
        self.assertTrue(any(
            event["event_type"] == "auth.session_status"
            and event["outcome"] == "active_at_collection"
            and event["session_id"] == "SESS-ATTACK-441"
            for event in events
        ))

    def test_all_five_training_fixtures_write_expected_events(self):
        self.login().read()
        for scenario in ("replay", "spoof", "cross_customer", "review_bypass", "mime"):
            response = self.request("/run-scenario", method="POST", form={"scenario": scenario})
            self.assertEqual(urlparse(response.geturl()).path, "/events")

        response = self.request("/api/events")
        event_types = {event["event_type"] for event in json.loads(response.read())["events"]}
        self.assertTrue({
            "receipt.notification",
            "identity.case_resolution",
            "customer.lookup",
            "review.decision",
            "mime.parse",
        }.issubset(event_types))

    def test_jsonl_export_and_reset_restore_seed_timeline(self):
        self.login().read()
        self.request("/run-scenario", method="POST", form={"scenario": "mime"}).read()

        export = self.request("/exports/events.jsonl")
        lines = export.read().decode().splitlines()
        self.assertGreater(len(lines), self.initial_event_count)
        parsed = [json.loads(line) for line in lines]
        self.assertTrue(any(event["event_type"] == "agent.render" for event in parsed))

        response = self.request("/reset", method="POST")
        self.assertEqual(urlparse(response.geturl()).path, "/login")
        self.assertEqual(app.count_rows("events"), self.initial_event_count)
        response = self.request("/dashboard")
        self.assertEqual(urlparse(response.geturl()).path, "/login")


if __name__ == "__main__":
    unittest.main(verbosity=2)
