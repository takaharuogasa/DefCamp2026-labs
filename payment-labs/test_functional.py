#!/usr/bin/env python3
"""Functional checks for the Payment Hunt Lab HTTP application."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


LAB_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB_DIR))

import app as payment_app  # noqa: E402


class PaymentHuntFunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.TemporaryDirectory(prefix="payment-hunt-functional-")
        payment_app.DATA_DIR = Path(cls.data_dir.name)
        payment_app.DB_PATH = payment_app.DATA_DIR / "payment-lab.sqlite3"
        payment_app.reset_database()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), payment_app.Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)
        cls.data_dir.cleanup()

    def request(self, path, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    def test_all_five_customer_profiles_are_available(self):
        with urlopen(self.base_url + "/", timeout=3) as response:
            page = response.read().decode("utf-8")
        for user, name in (("alice", "Alice"), ("bob", "Bob"), ("charlie", "Charlie"),
                           ("dean", "Dean"), ("elaina", "Elaina")):
            self.assertIn(f'value="{user}">{name} (customer)', page)
            status, result = self.request("/api/orders?" + urlencode({"user": user}))
            self.assertEqual(status, 200, result)
            self.assertIsInstance(result["orders"], list)
        status, result = self.request("/api/orders?user=unknown")
        self.assertEqual(status, 400)

    def test_discount_validation_and_server_calculated_quotes(self):
        cases = (
            ({"user": "charlie", "product_id": "course", "quantity": 1, "discount_code": "welcome10"},
             "applied", 4900, 490, 4410),
            ({"user": "dean", "product_id": "book", "quantity": 1, "discount_code": "STUDENT5"},
             "applied", 3200, 500, 2700),
            ({"user": "elaina", "product_id": "mug", "quantity": 1, "discount_code": "STUDENT5"},
             "minimum_not_met", 1500, 0, 1500),
            ({"user": "charlie", "product_id": "course", "quantity": 1, "discount_code": "EXPIRED50"},
             "expired", 4900, 0, 4900),
            ({"user": "charlie", "product_id": "course", "quantity": 1, "discount_code": "NOTREAL"},
             "invalid", 4900, 0, 4900),
        )
        for payload, expected_status, subtotal, discount, total in cases:
            status, quote = self.request("/api/discount/preview", "POST", payload)
            self.assertEqual(status, 200, quote)
            self.assertEqual(quote["discount_status"], expected_status)
            self.assertEqual(quote["subtotal_minor"], subtotal)
            self.assertEqual(quote["discount_minor"], discount)
            self.assertEqual(quote["amount_minor"], total)

    def test_checkout_retry_access_provider_state_and_fulfillment(self):
        status, order = self.request("/api/checkout", "POST", {
            "user": "charlie", "product_id": "course", "quantity": 1,
            "discount_code": "WELCOME10", "client_total_minor": 4410,
        })
        self.assertEqual(status, 201, order)
        self.assertEqual(order["amount_minor"], 4410)
        self.assertEqual(order["discount_status"], "applied")
        order_id = order["order_id"]
        intent_id = order["payment_intent_id"]

        status, orders = self.request("/api/orders?user=charlie")
        self.assertEqual(status, 200)
        self.assertTrue(any(item["order_id"] == order_id and item["amount_minor"] == 4410
                            for item in orders["orders"]))

        status, retry = self.request(f"/api/orders/{order_id}/retry", "POST", {"user": "charlie"})
        self.assertEqual(status, 200, retry)
        self.assertTrue(retry["reused"])
        self.assertEqual(retry["payment_intent_id"], intent_id)

        status, own_order = self.request(f"/api/orders/{order_id}?user=charlie")
        self.assertEqual(status, 200, own_order)
        status, _ = self.request(f"/api/orders/{order_id}?user=dean")
        self.assertEqual(status, 403)

        status, provider = self.request(f"/api/mock-provider/{intent_id}/confirm", "POST", {
            "user": "charlie", "status": "processing",
        })
        self.assertEqual(status, 200, provider)
        status, result = self.request(f"/api/orders/{order_id}/fulfill", "POST", {
            "user": "charlie", "client_reported_status": "succeeded",
        })
        self.assertEqual(status, 200, result)
        self.assertEqual(result["decision"], "blocked")
        self.assertEqual(result["provider_status"], "processing")

        status, provider = self.request(f"/api/mock-provider/{intent_id}/confirm", "POST", {
            "user": "charlie", "status": "succeeded",
        })
        self.assertEqual(status, 200, provider)
        status, result = self.request(f"/api/orders/{order_id}/fulfill", "POST", {
            "user": "charlie", "client_reported_status": "succeeded",
        })
        self.assertEqual(status, 200, result)
        self.assertEqual(result["decision"], "fulfilled")

        status, mismatch = self.request("/api/checkout", "POST", {
            "user": "dean", "product_id": "course", "quantity": 1,
            "discount_code": "STUDENT5", "client_total_minor": 1,
        })
        self.assertEqual(status, 409, mismatch)
        self.assertEqual(mismatch["authoritative_total_minor"], 4400)

        status, no_discount = self.request("/api/checkout", "POST", {
            "user": "elaina", "product_id": "mug", "quantity": 1,
            "discount_code": "NOTREAL", "client_total_minor": 1500,
        })
        self.assertEqual(status, 201, no_discount)
        self.assertEqual(no_discount["discount_status"], "invalid")
        self.assertEqual(no_discount["discount_minor"], 0)
        self.assertEqual(no_discount["amount_minor"], 1500)

        status, events = self.request("/api/events?" + urlencode({
            "event_type": "discount.code_validation", "order_id": no_discount["order_id"],
        }))
        self.assertEqual(status, 200)
        self.assertEqual(len(events["events"]), 1)
        self.assertEqual(events["events"][0]["status"], "invalid")


if __name__ == "__main__":
    unittest.main(verbosity=2)
