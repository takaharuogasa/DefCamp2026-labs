#!/usr/bin/env python3
"""Single-container email responder hunt lab with a deliberately vulnerable login."""

from __future__ import annotations

import hashlib
import html
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from seed_data import CASES, CUSTOMERS, DEFAULT_PASSWORD, DEFAULT_USERNAME, MESSAGES, seed_events


HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
DATA_DIR = Path(os.environ.get("LAB_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "email-hunt.sqlite3"
MAX_BODY_BYTES = 1_000_000
SESSION_SECONDS = 60 * 60
SESSIONS: dict[str, dict[str, str]] = {}
SESSIONS_LOCK = threading.Lock()

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
  customer_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  email TEXT NOT NULL,
  service_tier TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  status TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  FOREIGN KEY(customer_id) REFERENCES customers(customer_id)
);
CREATE TABLE IF NOT EXISTS messages (
  message_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  reply_to TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_time TEXT NOT NULL,
  event_type TEXT NOT NULL,
  source_ip TEXT,
  user_agent TEXT,
  actor_id TEXT,
  session_id TEXT,
  message_id TEXT,
  case_id TEXT,
  customer_id TEXT,
  outcome TEXT,
  details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, event_time);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_message ON events(message_id);
"""


CSS = """
:root{color-scheme:light;--ink:#172b3b;--muted:#526779;--line:#d5e0e8;--navy:#102c42;--blue:#145d8c;--pale:#edf5fa;--amber:#fff5d9;--red:#9b3d32;--green:#17664f}
*{box-sizing:border-box}body{margin:0;background:#f3f7fa;color:var(--ink);font:15px/1.52 system-ui,-apple-system,sans-serif}
header{background:var(--navy);color:white;padding:16px max(18px,calc((100% - 1160px)/2));display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}
header h1{font-size:1.15rem;margin:0}header a{color:#d8efff}nav{display:flex;gap:13px;flex-wrap:wrap;align-items:center}
main{max-width:1160px;margin:24px auto;padding:0 18px}footer{max-width:1160px;margin:26px auto;padding:0 18px 30px;color:var(--muted)}
.panel,.notice,.card{background:white;border:1px solid var(--line);border-radius:11px;padding:17px;margin-bottom:16px}
.notice{background:var(--amber);border-color:#e9d99c}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:15px}
h2{font-size:1.16rem;margin:0 0 9px}h3{font-size:1rem;margin:0 0 7px}p{color:var(--muted);margin:5px 0 10px}
label{font-weight:650;display:block;margin:9px 0 4px}input,select,textarea{font:inherit;padding:8px 9px;border:1px solid #9badbb;border-radius:6px;max-width:100%}
input:focus,select:focus,textarea:focus,button:focus,a:focus{outline:3px solid #9ad5f6;outline-offset:2px}
button,.button{font:inherit;color:white;background:var(--blue);border:0;border-radius:6px;padding:8px 12px;cursor:pointer;text-decoration:none;display:inline-block;margin:4px 5px 2px 0}
button.secondary,.button.secondary{background:#536b7b}button.warn{background:#8d4934}
.row{display:flex;gap:13px;flex-wrap:wrap;align-items:end}.row>div{min-width:180px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px}
.stat{border:1px solid var(--line);background:#f8fbfd;border-radius:8px;padding:12px}.stat strong{font-size:1.3rem;display:block}
.card{padding:13px;margin:10px 0}.pill{display:inline-block;border-radius:18px;background:var(--pale);padding:2px 8px;font-size:.86rem}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.small{font-size:.88rem}.good{color:var(--green)}.bad{color:var(--red)}
.tablewrap{overflow:auto;max-height:72vh;border:1px solid var(--line);border-radius:7px}table{width:100%;border-collapse:collapse;background:white;font-size:.86rem}
th,td{padding:7px 9px;border-bottom:1px solid #e1e8ee;text-align:left;vertical-align:top}th{position:sticky;top:0;background:#edf5fa;z-index:1}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;max-width:340px}.filter{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
.login{max-width:470px;margin:7vh auto}.credential{background:#f2f6f9;border-radius:7px;padding:10px;margin-top:12px}
@media(max-width:680px){header{align-items:flex-start}nav{gap:8px}}
"""


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=8)
    connection.row_factory = sqlite3.Row
    return connection


def password_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def initialize_database() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = connect()
    try:
        connection.executescript(SCHEMA)
        existing = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing:
            return
        connection.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
            (DEFAULT_USERNAME, password_hash(DEFAULT_PASSWORD), "analyst"),
        )
        connection.executemany(
            "INSERT INTO customers(customer_id,display_name,email,service_tier) VALUES(?,?,?,?)",
            CUSTOMERS,
        )
        connection.executemany(
            "INSERT INTO cases(case_id,customer_id,subject,status,sensitivity) VALUES(?,?,?,?,?)",
            CASES,
        )
        connection.executemany(
            """INSERT INTO messages
               (message_id,customer_id,case_id,sender,reply_to,subject,body,source_ip,received_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            MESSAGES,
        )
        for event in seed_events():
            insert_event(connection, event)
        connection.commit()
    finally:
        connection.close()


def insert_event(connection: sqlite3.Connection, event: dict) -> None:
    connection.execute(
        """INSERT INTO events
           (event_time,event_type,source_ip,user_agent,actor_id,session_id,message_id,
            case_id,customer_id,outcome,details_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            event.get("event_time", utc_now()),
            event["event_type"],
            event.get("source_ip"),
            event.get("user_agent"),
            event.get("actor_id"),
            event.get("session_id"),
            event.get("message_id"),
            event.get("case_id"),
            event.get("customer_id"),
            event.get("outcome"),
            json.dumps(event.get("details", {}), sort_keys=True),
        ),
    )


def record_event(event_type: str, *, source_ip: str, user_agent: str, actor_id=None,
                 session_id=None, message_id=None, case_id=None, customer_id=None,
                 outcome=None, details=None, event_time=None) -> None:
    connection = connect()
    try:
        insert_event(
            connection,
            {
                "event_time": event_time or utc_now(),
                "event_type": event_type,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "actor_id": actor_id,
                "session_id": session_id,
                "message_id": message_id,
                "case_id": case_id,
                "customer_id": customer_id,
                "outcome": outcome,
                "details": details or {},
            },
        )
        connection.commit()
    finally:
        connection.close()


def fetch_all(sql: str, parameters=()) -> list[sqlite3.Row]:
    connection = connect()
    try:
        return connection.execute(sql, parameters).fetchall()
    finally:
        connection.close()


def count_rows(table: str) -> int:
    if table not in {"customers", "cases", "messages", "events"}:
        return 0
    row = fetch_all(f"SELECT COUNT(*) AS n FROM {table}")[0]
    return int(row["n"])


def escape(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def safe_json(details_json: str) -> str:
    try:
        return json.dumps(json.loads(details_json or "{}"), indent=2, sort_keys=True)
    except (TypeError, json.JSONDecodeError):
        return details_json or "{}"


def page_shell(title: str, content: str, username: str) -> str:
    nav = (
        '<a href="/dashboard">Dashboard</a><a href="/inbox">Inbox</a>'
        '<a href="/cases">Cases</a><a href="/review">Review queue</a>'
        '<a href="/outbox">Simulated replies</a><a href="/events">Analyst events</a>'
        '<form method="post" action="/logout" style="display:inline"><button class="secondary" type="submit">Sign out</button></form>'
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{escape(title)} · Northstar Email Hunt Lab</title><style>{CSS}</style></head>
<body><header><h1>Northstar Customer Care · Email Hunt Lab</h1><nav>{nav}</nav></header>
<main><p class="small">Signed in as <strong>{escape(username)}</strong></p>{content}</main>
<footer>Fictional training service. All customer records and events are synthetic; outbound mail is simulated.</footer>
</body></html>"""


def login_page(message: str = "") -> str:
    message_html = f'<p class="bad" role="alert">{escape(message)}</p>' if message else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Sign in · Northstar Email Hunt Lab</title><style>{CSS}</style></head>
<body><header><h1>Northstar Customer Care · Email Hunt Lab</h1></header>
<main class="login"><section class="panel">
<h2>Sign in to the responder workspace</h2>
<p>Use the shared training account to review the fictional support-email workflow.</p>
{message_html}
<form method="post" action="/login">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<p><button type="submit">Sign in</button></p></form>
<div class="credential"><strong>Default training credentials</strong><br>
Username: <code>{escape(DEFAULT_USERNAME)}</code><br>Password: <code>{escape(DEFAULT_PASSWORD)}</code>
</div>
<p class="small">Local training only. Do not reuse these credentials elsewhere.</p>
</section></main><footer>Northstar Customer Care is a fictional service. No real email is sent.</footer></body></html>"""


def dashboard_page(username: str) -> str:
    message_count = count_rows("messages")
    case_count = count_rows("cases")
    event_count = count_rows("events")
    exercises = [
        ("H01", "Receipt replay or pointer mismatch",
         "Compare receipt attempts, message identity, processing runs, and simulated replies.",
         "replay"),
        ("H02", "Sender identity and reply misrouting",
         "Compare From, Reply-To, authentication, resolved case identity, and recipient.",
         "spoof"),
        ("H03", "Cross-customer lookup from untrusted identifiers",
         "Compare the authenticated customer with identifiers supplied inside the message and records returned.",
         "cross_customer"),
        ("H04", "Decision or review-gate bypass",
         "Check whether an ambiguous, high-impact request reached the simulated outbound ledger without review.",
         "review_bypass"),
        ("H05", "MIME parsing and rendering boundary",
         "Inspect how the responder handled a benign parser-boundary fixture.",
         "mime"),
    ]
    cards = "".join(
        f"""<article class="card"><span class="pill">{code}</span><h3>{escape(title)}</h3>
<p>{escape(description)}</p><form method="post" action="/run-scenario">
<input type="hidden" name="scenario" value="{slug}">
<button type="submit">Run training fixture</button></form></article>"""
        for code, title, description, slug in exercises
    )
    content = f"""<section class="notice"><strong>Training environment:</strong> this one-container app represents the responder workflow locally.
All activity is synthetic. It does not connect to AWS, call an external model, or send email.
Follow evidence beyond the five proposed hunts when it supports a new hypothesis.</section>
<section class="panel"><h2>Support operations</h2>
<p>Northstar Customer Care receives customer email, associates it with an account and case, uses a local decision simulator to suggest a response, and either routes it to an agent or records a simulated reply.</p>
<div class="stats"><div class="stat"><strong>{message_count}</strong>training messages</div>
<div class="stat"><strong>{case_count}</strong>synthetic cases</div><div class="stat"><strong>{event_count}</strong>event records</div></div>
<p class="small">Timeline window: 2026-10-20 08:00–08:31 UTC. Compare events by message ID, case ID, customer ID, source IP, session ID, and event time.</p>
</section>
<section class="panel"><h2>Five proposed hunts</h2><p>Run a fixture to add controlled activity, then inspect the shared event ledger.</p><div class="grid">{cards}</div></section>
<section class="panel"><h2>Workflow map</h2><p class="mono">Inbox → receipt event → case/customer lookup → decision simulator → agent review or simulated reply → analyst event ledger</p>
<p>The labels represent logical boundaries in the AWS source model. The app uses one Python process and SQLite database inside this container.</p></section>
<section class="panel"><form method="post" action="/reset" onsubmit="return confirm('Restore the synthetic seed data and remove interactive activity?')">
<h2>Training data</h2><p>Reset returns the database to its initial timeline and clears interactive activity.</p>
<button class="secondary" type="submit">Reset training data</button></form></section>"""
    return page_shell("Dashboard", content, username)


def data_table(headers: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return f'<p>{escape(empty)}</p>'
    head = "".join(f"<th>{escape(value)}</th>" for value in headers)
    body = "".join("<tr>" + "".join(f"<td>{value}</td>" for value in row) + "</tr>" for row in rows)
    return f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def inbox_page(username: str) -> str:
    messages = fetch_all(
        """SELECT message_id,received_at,sender,reply_to,subject,customer_id,case_id,source_ip
           FROM messages ORDER BY received_at"""
    )
    rows = [[
        f'<span class="mono">{escape(m["message_id"])}</span>',
        escape(m["received_at"]),
        escape(m["sender"]),
        escape(m["reply_to"]),
        escape(m["subject"]),
        escape(m["customer_id"]),
        escape(m["case_id"]),
        escape(m["source_ip"]),
    ] for m in messages]
    content = f"""<section class="panel"><h2>Inbox</h2><p>Message bodies and headers are synthetic. Compare sender identity with the associated customer and case.</p>
{data_table(["Message", "Received", "From", "Reply-To", "Subject", "Customer", "Case", "Source IP"], rows, "No messages.")}</section>"""
    return page_shell("Inbox", content, username)


def cases_page(username: str) -> str:
    rows_db = fetch_all(
        """SELECT c.case_id,c.customer_id,u.display_name,c.subject,c.status,c.sensitivity
           FROM cases c JOIN customers u ON u.customer_id=c.customer_id ORDER BY c.case_id"""
    )
    rows = [[
        f'<span class="mono">{escape(r["case_id"])}</span>', escape(r["customer_id"]),
        escape(r["display_name"]), escape(r["subject"]), escape(r["status"]), escape(r["sensitivity"]),
    ] for r in rows_db]
    content = f"""<section class="panel"><h2>Case register</h2><p>Customer and case records are synthetic. The authorized owner is recorded separately from identifiers appearing in message text.</p>
{data_table(["Case", "Customer", "Customer name", "Subject", "Status", "Sensitivity"], rows, "No cases.")}</section>"""
    return page_shell("Cases", content, username)


def review_page(username: str) -> str:
    rows_db = fetch_all(
        """SELECT event_time,event_type,source_ip,message_id,case_id,customer_id,outcome,details_json
           FROM events WHERE event_type IN ('review.decision','decision.recommended','identity.case_resolution','mime.parse')
           ORDER BY event_time DESC"""
    )
    rows = [[
        escape(r["event_time"]), escape(r["event_type"]), escape(r["message_id"]),
        escape(r["case_id"]), escape(r["customer_id"]), escape(r["outcome"]),
        f"<pre>{escape(safe_json(r['details_json']))}</pre>",
    ] for r in rows_db]
    content = f"""<section class="panel"><h2>Agent review queue and decision history</h2>
<p>Review decisions are synthetic event records. Check required review against the actual reviewer and outbound-reply record.</p>
{data_table(["Time", "Event", "Message", "Case", "Customer", "Outcome", "Decision details"], rows, "No review events.")}</section>"""
    return page_shell("Review queue", content, username)


def outbox_page(username: str) -> str:
    rows_db = fetch_all(
        """SELECT event_time,event_type,source_ip,message_id,case_id,customer_id,outcome,details_json
           FROM events WHERE event_type='reply.sent' ORDER BY event_time DESC"""
    )
    rows = [[
        escape(r["event_time"]), escape(r["message_id"]), escape(r["case_id"]),
        escape(r["customer_id"]), escape(r["outcome"]), f"<pre>{escape(safe_json(r['details_json']))}</pre>",
    ] for r in rows_db]
    content = f"""<section class="panel"><h2>Simulated outbound replies</h2>
<p>No message leaves the container. Compare the destination, identity check, and review state for each recorded reply.</p>
{data_table(["Time", "Message", "Case", "Customer", "Outcome", "Reply details"], rows, "No simulated replies.")}</section>"""
    return page_shell("Simulated replies", content, username)


def event_filters(query: dict[str, list[str]]) -> dict[str, str]:
    keys = ("event_type", "source_ip", "session_id", "message_id", "case_id", "customer_id")
    return {key: query.get(key, [""])[0][:200] for key in keys}


def events_page(username: str, query: dict[str, list[str]]) -> str:
    filters = event_filters(query)
    conditions = []
    parameters: list[str] = []
    for key in ("event_type", "source_ip", "session_id", "message_id", "case_id", "customer_id"):
        if filters[key]:
            conditions.append(f"{key} = ?")
            parameters.append(filters[key])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    rows_db = fetch_all(
        """SELECT event_id,event_time,event_type,source_ip,user_agent,actor_id,session_id,
                  message_id,case_id,customer_id,outcome,details_json
           FROM events""" + where + " ORDER BY event_time DESC,event_id DESC LIMIT 500",
        parameters,
    )
    rows = []
    for row in rows_db:
        source_link = (
            f'<a class="mono" href="/events?{urlencode({"source_ip": row["source_ip"]})}">{escape(row["source_ip"])}</a>'
            if row["source_ip"] else ""
        )
        session_link = (
            f'<a class="mono" href="/events?{urlencode({"session_id": row["session_id"]})}">{escape(row["session_id"])}</a>'
            if row["session_id"] else ""
        )
        rows.append([
            escape(row["event_time"]),
            f'<span class="mono">{escape(row["event_type"])}</span>',
            source_link,
            escape(row["user_agent"]),
            escape(row["actor_id"]),
            session_link,
            escape(row["message_id"]),
            escape(row["case_id"]),
            escape(row["customer_id"]),
            escape(row["outcome"]),
            f"<pre>{escape(safe_json(row['details_json']))}</pre>",
        ])
    table = data_table(
        ["Time", "Event", "Source IP", "User agent", "Actor", "Session", "Message", "Case", "Customer", "Outcome", "Details"],
        rows,
        "No event records match these filters.",
    )
    filter_inputs = "".join(
        f'<div><label for="{key}">{escape(key.replace("_", " ").title())}</label>'
        f'<input id="{key}" name="{key}" value="{escape(value)}"></div>'
        for key, value in filters.items()
    )
    content = f"""<section class="panel"><h2>Analyst event explorer</h2>
<p>Search and correlate the synthetic timeline. Follow source IPs and session IDs into adjacent activity; a lead may support an additional hypothesis.</p>
<form method="get" action="/events" class="filter">{filter_inputs}<button type="submit">Filter events</button>
<a class="button secondary" href="/events">Clear filters</a></form>
<p><a href="/exports/events.jsonl">Download all events as JSONL</a></p>
<p class="small">Showing {len(rows_db)} event(s). Results are newest first, up to 500 records.</p></section>
<section class="panel"><div class="tablewrap">{table}</div></section>"""
    return page_shell("Analyst events", content, username)


def parse_body(handler: BaseHTTPRequestHandler) -> tuple[dict[str, list[str]], bytes]:
    length = min(int(handler.headers.get("Content-Length", "0") or "0"), MAX_BODY_BYTES)
    raw = handler.rfile.read(length)
    content_type = handler.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            obj = json.loads(raw.decode("utf-8") or "{}")
            return {str(k): [str(v)] for k, v in obj.items()}, raw
        except (ValueError, AttributeError):
            return {}, raw
    return parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True), raw


class Handler(BaseHTTPRequestHandler):
    server_version = "NorthstarEmailHunt/1.0"

    def log_message(self, fmt, *args):
        # Keep request bodies and credentials out of the container console.
        super().log_message(fmt, *args)

    def send_bytes(self, status: int, body: bytes, content_type: str, extra_headers=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, body: str, status: int = 200, extra_headers=None) -> None:
        self.send_bytes(status, body.encode("utf-8"), "text/html; charset=utf-8", extra_headers)

    def send_json(self, obj, status: int = 200) -> None:
        self.send_bytes(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def redirect(self, location: str, extra_headers=None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.end_headers()

    def client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def user_agent(self) -> str:
        return self.headers.get("User-Agent", "")[:300]

    def current_session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None, None
        morsel = cookie.get("lab_session")
        token = morsel.value if morsel else None
        if not token:
            return None, None
        with SESSIONS_LOCK:
            session = SESSIONS.get(token)
        if not session:
            return None, None
        if datetime.now(timezone.utc).timestamp() > float(session["expires_epoch"]):
            with SESSIONS_LOCK:
                SESSIONS.pop(token, None)
            return None, None
        return token, session

    def require_session(self, path: str) -> tuple[str | None, dict | None]:
        token, session = self.current_session()
        if session:
            return token, session
        self.redirect("/login?next=" + urlencode({"path": path}))
        return None, None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        if path == "/health":
            self.send_json({"status": "ok", "lab": "email-hunt"})
            return
        if path in {"/", "/login"}:
            _, session = self.current_session()
            if session:
                self.redirect("/dashboard")
            else:
                self.send_html(login_page("Training data has been reset. Please sign in again." if query.get("reset") else ""))
            return
        token, session = self.require_session(path)
        if not session:
            return
        username = session["username"]
        if path == "/dashboard":
            self.send_html(dashboard_page(username))
        elif path == "/inbox":
            self.send_html(inbox_page(username))
        elif path == "/cases":
            self.send_html(cases_page(username))
        elif path == "/review":
            self.send_html(review_page(username))
        elif path == "/outbox":
            self.send_html(outbox_page(username))
        elif path == "/events":
            self.send_html(events_page(username, query))
        elif path == "/api/events":
            self.send_json(self.get_event_rows(query))
        elif path == "/exports/events.jsonl":
            self.export_events()
        else:
            self.send_html(page_shell("Not found", "<section class='panel'><h2>Page not found</h2></section>", username), 404)

    def get_event_rows(self, query):
        filters = event_filters(query)
        conditions = []
        params = []
        for key, value in filters.items():
            if value:
                conditions.append(f"{key} = ?")
                params.append(value)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = fetch_all(
            """SELECT event_id,event_time,event_type,source_ip,user_agent,actor_id,session_id,
                      message_id,case_id,customer_id,outcome,details_json
               FROM events""" + where + " ORDER BY event_time DESC,event_id DESC LIMIT 500",
            params,
        )
        return {"events": [self.event_object(row) for row in rows]}

    @staticmethod
    def event_object(row) -> dict:
        try:
            details = json.loads(row["details_json"] or "{}")
        except json.JSONDecodeError:
            details = {}
        return {
            "event_id": row["event_id"],
            "event_time": row["event_time"],
            "event_type": row["event_type"],
            "source_ip": row["source_ip"],
            "user_agent": row["user_agent"],
            "actor_id": row["actor_id"],
            "session_id": row["session_id"],
            "message_id": row["message_id"],
            "case_id": row["case_id"],
            "customer_id": row["customer_id"],
            "outcome": row["outcome"],
            "details": details,
        }

    def export_events(self):
        rows = fetch_all(
            """SELECT event_id,event_time,event_type,source_ip,user_agent,actor_id,session_id,
                      message_id,case_id,customer_id,outcome,details_json
               FROM events ORDER BY event_time,event_id"""
        )
        body = "".join(json.dumps(self.event_object(row), ensure_ascii=False) + "\n" for row in rows).encode("utf-8")
        self.send_bytes(
            200,
            body,
            "application/x-ndjson; charset=utf-8",
            [("Content-Disposition", 'attachment; filename="email-hunt-events.jsonl"')],
        )

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        form, _ = parse_body(self)
        if path == "/login":
            self.login(form)
            return
        token, session = self.current_session()
        if path == "/logout":
            if token:
                with SESSIONS_LOCK:
                    SESSIONS.pop(token, None)
            self.redirect("/login", [("Set-Cookie", "lab_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")])
            return
        if not session:
            self.redirect("/login")
            return
        if path == "/run-scenario":
            self.run_scenario(form.get("scenario", [""])[0], session)
        elif path == "/reset":
            reset_database()
            with SESSIONS_LOCK:
                SESSIONS.clear()
            self.redirect("/login?reset=1", [("Set-Cookie", "lab_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")])
        else:
            self.send_html(page_shell("Not found", "<section class='panel'><h2>Page not found</h2></section>", session["username"]), 404)

    def login(self, form: dict[str, list[str]]) -> None:
        username = form.get("username", [""])[0][:1000]
        password = form.get("password", [""])[0][:500]
        hashed = password_hash(password)
        outcome = "rejected"
        error_text = None
        found = None
        connection = connect()
        try:
            # INTENTIONALLY VULNERABLE training fixture: username is interpolated into SQL.
            # This endpoint must remain bound to localhost by the Compose port mapping.
            query = (
                "SELECT username, role FROM users "
                f"WHERE username = '{username}' AND password_hash = '{hashed}' LIMIT 1"
            )
            found = connection.execute(query).fetchone()
            if found:
                outcome = "accepted"
        except sqlite3.Error as exc:
            error_text = str(exc)[:180]
        finally:
            connection.close()
        details = {
            "method": "POST",
            "path": "/login",
            "parameter": "username",
            "username_input": username[:500],
            "authentication": "success" if found else "failed",
        }
        if error_text:
            details["database_error"] = error_text
        record_event(
            "auth.login_attempt",
            source_ip=self.client_ip(),
            user_agent=self.user_agent(),
            actor_id=found["username"] if found else "unknown",
            outcome=outcome,
            details=details,
        )
        if not found:
            self.send_html(login_page("Sign-in failed. Check the training credentials."), 200)
            return
        now = datetime.now(timezone.utc)
        token = secrets.token_urlsafe(24)
        session_id = "LIVE-" + secrets.token_hex(6)
        user = {"username": str(found["username"]), "role": str(found["role"])}
        with SESSIONS_LOCK:
            SESSIONS[token] = {
                **user,
                "session_id": session_id,
                "expires_epoch": str(now.timestamp() + SESSION_SECONDS),
            }
        record_event(
            "auth.session_created",
            source_ip=self.client_ip(),
            user_agent=self.user_agent(),
            actor_id=user["username"],
            session_id=session_id,
            outcome="authenticated",
            details={"auth_method": "login_query", "role": user["role"], "expires_at": (now + timedelta(seconds=SESSION_SECONDS)).isoformat()},
        )
        cookie = f"lab_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECONDS}"
        self.redirect("/dashboard", [("Set-Cookie", cookie)])

    def run_scenario(self, scenario: str, session: dict[str, str]) -> None:
        ip = self.client_ip()
        agent = "LocalTrainingFixture/1.0"
        actor = session["username"]
        generated_message = "LIVE-" + secrets.token_hex(4).upper()
        actions = {
            "replay": [
                ("receipt.notification", "duplicate_processing", "MSG-101", "CASE-1042", "CUST-ALPHA",
                 {"attempt": 2, "object_location": "/synthetic-mail/MSG-101.eml", "deduplication": "not_applied"}),
                ("workflow.processed", "completed_twice", "MSG-101", "CASE-1042", "CUST-ALPHA",
                 {"attempt": 2, "response_id": "RSP-LIVE-DUPLICATE"}),
                ("reply.sent", "sent", "MSG-101", "CASE-1042", "CUST-ALPHA",
                 {"response_id": "RSP-LIVE-DUPLICATE", "reason": "replayed_receipt"}),
            ],
            "spoof": [
                ("mail.received", "accepted", generated_message, "CASE-2048", "CUST-BRAVO",
                 {"from": "billing@northstar.test", "reply_to": "capture@outside.test", "authentication": "dmarc_fail"}),
                ("identity.case_resolution", "identity_conflict", generated_message, "CASE-2048", "CUST-BRAVO",
                 {"review_required": True, "customer_record": "CUST-BRAVO"}),
                ("reply.sent", "sent", generated_message, "CASE-2048", "CUST-BRAVO",
                 {"recipient": "capture@outside.test", "recipient_validation": "not_applied"}),
            ],
            "cross_customer": [
                ("mail.received", "accepted", generated_message, "CASE-1042", "CUST-ALPHA",
                 {"from": "avery@northstar.test", "body_customer_id": "CUST-BRAVO", "source_ip": "198.51.100.23"}),
                ("customer.lookup", "allowed", generated_message, "CASE-1042", "CUST-ALPHA",
                 {"authenticated_customer": "CUST-ALPHA", "message_supplied_customer": "CUST-BRAVO",
                  "returned_record_owner": "CUST-BRAVO", "authorization": "not_customer_scoped"}),
            ],
            "review_bypass": [
                ("decision.recommended", "high_impact_ambiguous", generated_message, "CASE-3003", "CUST-CHARLIE",
                 {"intent": "refund_and_account_change", "confidence_fixture": 0.64, "review_required": True}),
                ("review.decision", "bypassed", generated_message, "CASE-3003", "CUST-CHARLIE",
                 {"reviewer": None, "bypass_reason": "automatic_reply_path"}),
                ("reply.sent", "sent", generated_message, "CASE-3003", "CUST-CHARLIE",
                 {"recipient": "casey@northstar.test", "review_decision": "bypassed"}),
            ],
            "mime": [
                ("mime.parse", "limit_exceeded", generated_message, "CASE-4014", "CUST-DELTA",
                 {"fixture": "benign_parser_boundary", "declared_size_bytes": 25000000,
                  "configured_limit_bytes": 10000000, "nesting_depth": 18, "action": "quarantined"}),
                ("agent.render", "blocked", generated_message, "CASE-4014", "CUST-DELTA",
                 {"queue_visible": False, "render_mode": "sanitized_text_only", "executable_content": False}),
            ],
        }
        if scenario not in actions:
            self.redirect("/dashboard")
            return
        for event_type, outcome, message_id, case_id, customer_id, details in actions[scenario]:
            record_event(
                event_type,
                source_ip=ip,
                user_agent=agent,
                actor_id=actor,
                session_id=session["session_id"],
                message_id=message_id,
                case_id=case_id,
                customer_id=customer_id,
                outcome=outcome,
                details={**details, "origin": "interactive_fixture"},
            )
        self.redirect("/events")


def reset_database() -> None:
    connection = connect()
    try:
        connection.execute("DELETE FROM events")
        connection.execute("DELETE FROM messages")
        connection.execute("DELETE FROM cases")
        connection.execute("DELETE FROM customers")
        connection.execute("DELETE FROM users")
        connection.commit()
    finally:
        connection.close()
    initialize_database()


def main() -> None:
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Email Hunt Lab listening on {HOST}:{PORT}; published host port should be localhost-only.")
    server.serve_forever()


if __name__ == "__main__":
    main()
