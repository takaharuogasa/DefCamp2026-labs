#!/usr/bin/env python3
"""Single-container, standard-library payment threat-hunting training app."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from seed_data import DELEGATIONS, INTENTS, ORDERS, seed_events


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))
DATA_DIR = Path(os.environ.get("LAB_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "payment-lab.sqlite3"
PRODUCTS = {
    "course": {"name": "Security training course", "amount_minor": 4900, "currency": "SGD"},
    "book": {"name": "Threat hunting field guide", "amount_minor": 3200, "currency": "SGD"},
    "mug": {"name": "Merchant demo mug", "amount_minor": 1500, "currency": "SGD"},
}
USERS = {"alice", "bob", "charlie", "dean", "elaina"}
PROVIDER_STATES = {"succeeded", "processing", "requires_payment_method"}
DISCOUNT_CODES = {
    "WELCOME10": {"kind": "percent", "value": 10, "minimum_minor": 0},
    "STUDENT5": {"kind": "fixed", "value_minor": 500, "minimum_minor": 2500},
    "EXPIRED50": {"kind": "expired"},
}


HOME_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Northstar Market | Payment Hunt Lab</title>
<style>
:root{color-scheme:light;--ink:#182634;--muted:#526577;--line:#d7e0e8;--blue:#145d8c;--pale:#edf5fa;--warn:#fff5d8}
*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font:16px/1.5 system-ui,-apple-system,sans-serif}
header{background:#10283b;color:#fff;padding:22px max(20px,calc((100% - 1080px)/2));display:flex;justify-content:space-between;gap:20px;align-items:center}
header h1{font-size:1.35rem;margin:0}header a{color:#d5edff}main{max-width:1080px;margin:24px auto;padding:0 20px}
.notice,.panel{border:1px solid var(--line);border-radius:12px;background:#fff;padding:20px;margin-bottom:18px}
.notice{background:var(--warn);border-color:#ead99d}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}
h2{margin:0 0 10px;font-size:1.18rem}h3{margin:16px 0 6px;font-size:1rem}p{margin:7px 0;color:var(--muted)}
label{display:block;font-weight:650;margin:12px 0 4px}input,select{font:inherit;padding:9px;border:1px solid #9db0c0;border-radius:7px;max-width:100%}
button{font:inherit;color:#fff;background:var(--blue);border:0;border-radius:7px;padding:9px 13px;cursor:pointer;margin:7px 6px 2px 0}
button.secondary{background:#526577}button:focus,input:focus,select:focus{outline:3px solid #a4d8f5;outline-offset:1px}
.row{display:flex;flex-wrap:wrap;gap:12px;align-items:end}.row>div{min-width:145px}.card{border:1px solid var(--line);border-radius:8px;padding:12px;margin:9px 0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.result{white-space:pre-wrap;background:#f4f7fa;padding:12px;border-radius:7px;min-height:36px}
.pill{display:inline-block;border-radius:20px;padding:2px 9px;background:var(--pale);font-size:.88rem}.small{font-size:.9rem}
footer{max-width:1080px;margin:28px auto;padding:0 20px 30px;color:var(--muted)}
</style></head>
<body><header><h1>Northstar Market · Payment Hunt Lab</h1><nav><a href="/analyst">Analyst event explorer</a></nav></header>
<main>
<section class="notice"><strong>Training environment:</strong> all accounts, orders, payment intents, and secret fingerprints are synthetic.
This local mock does not collect card data, contact Stripe, or send traffic to external services.</section>
<section class="panel"><h2>Customer checkout</h2>
<p>Follow a normal order through the merchant API and local payment-provider simulation. No card form is used.</p>
<div class="row">
<div><label for="customer">Training customer</label><select id="customer"><option value="alice">Alice (customer)</option><option value="bob">Bob (customer)</option><option value="charlie">Charlie (customer)</option><option value="dean">Dean (customer)</option><option value="elaina">Elaina (customer)</option></select></div>
<div><label for="product">Product</label><select id="product"><option value="course">Security training course — SGD 49.00</option><option value="book">Threat hunting field guide — SGD 32.00</option><option value="mug">Merchant demo mug — SGD 15.00</option></select></div>
<div><label for="quantity">Quantity</label><input id="quantity" type="number" min="1" max="5" value="1"></div>
<div><label for="discount-code">Discount code</label><input id="discount-code" type="text" maxlength="40" autocomplete="off" placeholder="Optional code"></div>
</div>
<button class="secondary" id="apply-discount" type="button">Apply code</button>
<div id="price-summary" class="result" aria-live="polite">Calculating order total…</div>
<button id="checkout">Create training order</button>
<div id="checkout-result" class="result" aria-live="polite">No order created yet.</div>
</section>
<div class="grid">
<section class="panel"><h2>My orders</h2><p>Retry is idempotent. The provider outcome selector is a local simulation.</p><div id="orders">Loading orders…</div></section>
<section class="panel"><h2>Object access check</h2>
<p>Try viewing an order as the selected customer. The merchant checks owner and recorded support delegation.</p>
<label for="order-id">Order ID</label><input id="order-id" placeholder="for example, ord-seed-h11-bob">
<button id="view-order">Request order</button><div id="access-result" class="result" aria-live="polite">No request made yet.</div>
</section></div>
<section class="panel"><h2>What the application records</h2>
<p>The event ledger records order snapshots, payment-intent requests, provider state changes, object-access decisions, fulfillment decisions, and synthetic client-secret fingerprints. Analysts can inspect the same ledger in the <a href="/analyst">event explorer</a>.</p>
<button class="secondary" id="reset">Reset training data</button><span id="reset-result" class="small"></span>
</section></main>
<footer>Northstar Market is a fictional training app. The provider boundary is represented by local API behavior inside this one container.</footer>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function call(path,method="GET",body=null){
  const r=await fetch(path,{method,headers:body?{"Content-Type":"application/json"}:{},body:body?JSON.stringify(body):undefined});
  let data={};try{data=await r.json()}catch{}
  return {ok:r.ok,status:r.status,data};
}
function money(minor,currency){return currency+" "+(Number(minor)/100).toFixed(2)}
function orderQuoteInput(){
  return {user:$('customer').value,product_id:$('product').value,
    quantity:Math.min(5,Math.max(1,Number($('quantity').value)||1)),
    discount_code:$('discount-code').value,session_id:'sess-live-'+$('customer').value};
}
function showQuote(q){
  const label=q.discount_code?('Code '+q.discount_code+': '+q.discount_message):'No discount code applied.';
  $('price-summary').textContent='Subtotal: '+money(q.subtotal_minor,q.currency)
    +' · Discount: −'+money(q.discount_minor,q.currency)+' · Total: '+money(q.amount_minor,q.currency)
    +'\n'+label;
}
async function refreshQuote(input=orderQuoteInput()){
  const r=await call('/api/discount/preview','POST',input);
  if(!r.ok){$('price-summary').textContent='Could not calculate price: '+(r.data.error||'request rejected');return null}
  showQuote(r.data);return r.data;
}
async function refreshOrders(){
  const u=$("customer").value;
  const r=await call("/api/orders?user="+encodeURIComponent(u));
  if(!r.ok){$("orders").textContent="Could not load orders.";return}
  if(!r.data.orders.length){$("orders").innerHTML="<p>No orders yet.</p>";return}
  $("orders").innerHTML=r.data.orders.map(function(o){
    const id=esc(o.order_id), pi=esc(o.payment_intent_id||"");
    return '<article class="card"><div><strong class="mono">'+id+'</strong> <span class="pill">'+esc(o.provider_status||"no intent")+'</span></div>'
      + '<p>'+esc(money(o.amount_minor,o.currency))+' · owner '+esc(o.owner_id)+' · version '+esc(o.version)+'</p>'
      + '<p>PaymentIntent: <span class="mono">'+(pi||"not created")+'</span></p>'
      + '<button class="secondary" data-action="retry" data-order="'+id+'">Retry with same idempotency key</button>'
      + '<select id="state-'+id+'"><option>succeeded</option><option>processing</option><option>requires_payment_method</option></select>'
      + '<button data-action="confirm" data-order="'+id+'" data-intent="'+pi+'">Set mock provider outcome</button>'
      + '<button class="secondary" data-action="fulfill" data-order="'+id+'">Submit browser “success” claim</button></article>';
  }).join("");
  document.querySelectorAll("[data-action]").forEach(function(button){
    button.addEventListener("click",function(){
      const action=button.dataset.action, order=button.dataset.order;
      if(action==="retry")retryOrder(order);
      if(action==="confirm")confirmPayment(order,button.dataset.intent);
      if(action==="fulfill")fulfillOrder(order);
    });
  });
}
async function checkout(){
  const input=orderQuoteInput(), quote=await refreshQuote(input);
  if(!quote)return;
  const result=await call('/api/checkout','POST',{...input,client_total_minor:quote.amount_minor});
  $("checkout-result").textContent=result.ok
    ? "Created "+result.data.order_id+" with "+result.data.payment_intent_id+". Subtotal: "+money(result.data.subtotal_minor,result.data.currency)+"; discount: −"+money(result.data.discount_minor,result.data.currency)+"; server total: "+money(result.data.amount_minor,result.data.currency)+"."
    : "Request "+result.status+": "+(result.data.error||"request rejected")+(result.data.authoritative_total_minor!==undefined?"; server total is "+money(result.data.authoritative_total_minor,result.data.currency):"");
  await refreshOrders();
}
async function retryOrder(orderId){
  const user=$("customer").value;
  const r=await call("/api/orders/"+encodeURIComponent(orderId)+"/retry","POST",{user,request_id:"req-live-retry-"+crypto.randomUUID()});
  $("checkout-result").textContent=r.ok?"Retry returned "+r.data.payment_intent_id+"; idempotent reuse: "+r.data.reused+".":"Request "+r.status+": "+r.data.error;
  await refreshOrders();
}
async function confirmPayment(orderId,intentId){
  if(!intentId){$("checkout-result").textContent="This order has no payment intent.";return}
  const state=$("state-"+orderId).value;
  const r=await call("/api/mock-provider/"+encodeURIComponent(intentId)+"/confirm","POST",{user:$("customer").value,status:state,request_id:"req-live-provider-"+crypto.randomUUID()});
  $("checkout-result").textContent=r.ok?"Local provider state is now "+r.data.status+".":"Request "+r.status+": "+r.data.error;
  await refreshOrders();
}
async function fulfillOrder(orderId){
  const r=await call("/api/orders/"+encodeURIComponent(orderId)+"/fulfill","POST",{user:$("customer").value,client_reported_status:"succeeded",request_id:"req-live-fulfill-"+crypto.randomUUID()});
  $("checkout-result").textContent=r.ok?"Fulfillment "+r.data.decision+": "+r.data.reason+".":"Request "+r.status+": "+r.data.error;
  await refreshOrders();
}
$("checkout").addEventListener("click",checkout);
$("apply-discount").addEventListener("click",()=>refreshQuote());
$("product").addEventListener("change",()=>refreshQuote());
$("quantity").addEventListener("change",()=>refreshQuote());
$("customer").addEventListener("change",function(){refreshOrders();refreshQuote()});
$("view-order").addEventListener("click",async function(){
  const id=$("order-id").value.trim(), user=$("customer").value;
  if(!id){$("access-result").textContent="Enter an order ID.";return}
  const r=await call("/api/orders/"+encodeURIComponent(id)+"?user="+encodeURIComponent(user));
  $("access-result").textContent=r.ok?JSON.stringify(r.data,null,2):"Request "+r.status+": "+r.data.error;
});
$("reset").addEventListener("click",async function(){
  if(!confirm("Restore the seeded training dataset and clear interactive lab activity?"))return;
  const r=await call("/api/reset","POST",{});
  $("reset-result").textContent=r.ok?" Seeded data restored.":" Reset failed.";
  await refreshOrders();
});
refreshOrders();
refreshQuote();
</script></body></html>"""


ANALYST_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Analyst Event Explorer</title><style>
body{margin:0;background:#f4f7fa;color:#182634;font:15px/1.45 system-ui,-apple-system,sans-serif}
header{background:#10283b;color:#fff;padding:18px max(18px,calc((100% - 1240px)/2));display:flex;justify-content:space-between}
header a{color:#d5edff}main{max-width:1240px;margin:20px auto;padding:0 18px}.panel{background:white;border:1px solid #d7e0e8;border-radius:10px;padding:16px;margin-bottom:16px}
h1{font-size:1.3rem;margin:0}h2{font-size:1.05rem;margin:0 0 8px}p{color:#526577;margin:5px 0}
label{font-weight:650}input{font:inherit;padding:8px;border:1px solid #9db0c0;border-radius:6px;margin:4px 12px 4px 4px}
button{font:inherit;background:#145d8c;color:white;border:0;border-radius:6px;padding:8px 12px;cursor:pointer}
.links a{margin-right:15px;white-space:nowrap}.tablewrap{overflow:auto;max-height:70vh;border:1px solid #d7e0e8}
table{border-collapse:collapse;width:100%;font-size:.86rem;background:#fff}th,td{padding:7px 9px;border-bottom:1px solid #e1e8ee;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:#edf5fa;z-index:1}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
pre{white-space:pre-wrap;max-width:330px;margin:0}.muted{color:#526577}.notice{background:#fff5d8;padding:10px;border-radius:7px;margin-bottom:12px}
</style></head><body><header><h1>Analyst event explorer</h1><nav><a href="/">Back to storefront</a></nav></header>
<main><section class="panel"><h2>Search the synthetic event ledger</h2>
<div class="notice">Training records only. Secret material is represented by a synthetic fingerprint; no raw client secret or card data is stored.</div>
<label>Event type <input id="eventType" placeholder="payment.intent.create"></label>
<label>Actor <input id="actor" placeholder="alice"></label>
<label>Order ID <input id="order" placeholder="ord-seed-h04-1002"></label>
<button id="search">Search</button><p id="count" class="muted"></p>
<div class="links"><a href="/exports/events.jsonl">Download events JSONL</a><a href="/exports/h04_orders.csv">H04 order snapshots CSV</a><a href="/exports/h04_payment_requests.csv">H04 provider requests CSV</a><a href="/exports/h04_mapping.json">H04 mapping JSON</a></div>
</section><section class="panel"><div class="tablewrap"><table><thead><tr>
<th>Time</th><th>Event</th><th>Actor / owner</th><th>Order / version</th><th>Request / intent</th><th>Idempotency key</th><th>Amount</th><th>Status / source</th><th>Decision</th><th>Secret fingerprint</th><th>Context</th>
</tr></thead><tbody id="rows"></tbody></table></div></section></main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function load(){
 const p=new URLSearchParams();
 for(const [id,key] of [["eventType","event_type"],["actor","actor_id"],["order","order_id"]])if($(id).value.trim())p.set(key,$(id).value.trim());
 const r=await fetch("/api/events?"+p.toString());const d=await r.json();
 $("count").textContent="Showing "+d.events.length+" event records (newest first).";
 $("rows").innerHTML=d.events.map(function(e){
   return "<tr><td class=\"mono\">"+esc(e.event_time)+"</td><td class=\"mono\">"+esc(e.event_type)+"</td>"
    +"<td>"+esc(e.actor_id)+"<br><span class=\"muted\">owner "+esc(e.owner_id)+"</span></td>"
    +"<td class=\"mono\">"+esc(e.order_id)+"<br><span class=\"muted\">v"+esc(e.order_version)+"</span></td>"
    +"<td class=\"mono\">"+esc(e.request_id)+"<br>"+esc(e.payment_intent_id)+"</td>"
    +"<td class=\"mono\">"+esc(e.idempotency_key)+"</td>"
    +"<td>"+(e.amount_minor===null?"":esc(e.currency)+" "+(Number(e.amount_minor)/100).toFixed(2))+"</td>"
    +"<td>"+esc(e.status)+"<br><span class=\"muted\">"+esc(e.status_source)+"</span></td>"
    +"<td>"+esc(e.decision)+"</td><td class=\"mono\">"+esc(e.secret_fingerprint)+"</td>"
    +"<td><pre>"+esc(JSON.stringify(e.details,null,2))+"</pre></td></tr>";
 }).join("");
}
$("search").addEventListener("click",load);load();
</script></body></html>"""


SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS orders (
  order_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL, version INTEGER NOT NULL, policy TEXT NOT NULL,
  product_id TEXT, quantity INTEGER, payment_intent_id TEXT, idempotency_key TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payment_intents (
  payment_intent_id TEXT PRIMARY KEY, order_id TEXT NOT NULL, amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL, status TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  secret_fingerprint TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intents_idempotency ON payment_intents(idempotency_key);
CREATE TABLE IF NOT EXISTS delegations (
  actor_id TEXT NOT NULL, order_id TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY(actor_id, order_id)
);
CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, event_time TEXT NOT NULL,
  event_type TEXT NOT NULL, actor_id TEXT, session_id TEXT, order_id TEXT, owner_id TEXT,
  request_id TEXT, payment_intent_id TEXT, order_version INTEGER, amount_minor INTEGER,
  currency TEXT, idempotency_key TEXT, status TEXT, status_source TEXT, decision TEXT,
  resource TEXT, secret_fingerprint TEXT, details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_order ON events(order_id);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(event_type, event_time);
"""


@contextmanager
def database():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def insert_event(connection: sqlite3.Connection, data: dict) -> None:
    fields = (
        "event_time", "event_type", "actor_id", "session_id", "order_id", "owner_id",
        "request_id", "payment_intent_id", "order_version", "amount_minor", "currency",
        "idempotency_key", "status", "status_source", "decision", "resource",
        "secret_fingerprint",
    )
    values = [data.get(field) for field in fields]
    values.append(json.dumps(data.get("details", {}), separators=(",", ":"), sort_keys=True))
    placeholders = ",".join("?" for _ in range(len(fields) + 1))
    connection.execute(
        "INSERT INTO events (" + ",".join(fields) + ",details_json) VALUES (" + placeholders + ")",
        values,
    )


def reset_database() -> None:
    with database() as connection:
        for table in ("events", "delegations", "payment_intents", "orders"):
            connection.execute("DELETE FROM " + table)
        connection.execute("DELETE FROM sqlite_sequence WHERE name='events'")
        connection.executemany(
            """INSERT INTO orders
            (order_id,owner_id,amount_minor,currency,version,policy,product_id,quantity,
             payment_intent_id,idempotency_key,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ORDERS,
        )
        connection.executemany(
            """INSERT INTO payment_intents
            (payment_intent_id,order_id,amount_minor,currency,status,idempotency_key,
             secret_fingerprint,created_at) VALUES (?,?,?,?,?,?,?,?)""",
            INTENTS,
        )
        connection.executemany(
            "INSERT INTO delegations(actor_id,order_id,reason) VALUES (?,?,?)", DELEGATIONS,
        )
        for event in seed_events():
            insert_event(connection, event)


def order_dict(connection: sqlite3.Connection, row: sqlite3.Row) -> dict:
    intent = None
    if row["payment_intent_id"]:
        intent = connection.execute(
            "SELECT status FROM payment_intents WHERE payment_intent_id=?",
            (row["payment_intent_id"],),
        ).fetchone()
    return {
        "order_id": row["order_id"], "owner_id": row["owner_id"],
        "amount_minor": row["amount_minor"], "currency": row["currency"],
        "version": row["version"], "policy": row["policy"],
        "payment_intent_id": row["payment_intent_id"],
        "provider_status": intent["status"] if intent else None, "created_at": row["created_at"],
    }


def insert_or_reuse_intent(connection: sqlite3.Connection, order: sqlite3.Row, request_id: str):
    key = order["idempotency_key"]
    existing = connection.execute(
        "SELECT payment_intent_id FROM payment_intents WHERE idempotency_key=?", (key,),
    ).fetchone()
    reused = existing is not None
    if reused:
        intent_id = existing["payment_intent_id"]
    else:
        intent_id = "pi-live-" + uuid.uuid4().hex[:10]
        fingerprint = "fp_live_" + uuid.uuid4().hex[:8]
        connection.execute(
            """INSERT INTO payment_intents
            (payment_intent_id,order_id,amount_minor,currency,status,idempotency_key,
             secret_fingerprint,created_at) VALUES (?,?,?,?,?,?,?,?)""",
            (intent_id, order["order_id"], order["amount_minor"], order["currency"],
             "requires_payment_method", key, fingerprint, now_utc()),
        )
        connection.execute(
            "UPDATE orders SET payment_intent_id=? WHERE order_id=?", (intent_id, order["order_id"]),
        )
    insert_event(connection, {
        "event_time": now_utc(), "event_type": "payment_intent.create",
        "actor_id": order["owner_id"], "session_id": "sess-live-" + order["owner_id"],
        "order_id": order["order_id"], "owner_id": order["owner_id"],
        "request_id": request_id, "payment_intent_id": intent_id,
        "order_version": order["version"], "amount_minor": order["amount_minor"],
        "currency": order["currency"], "idempotency_key": key,
        "status": "reused" if reused else "created", "status_source": "merchant",
        "decision": "idempotent_reuse" if reused else "created",
        "resource": "local-provider:/v1/payment_intents", "details": {"provider": "local mock", "reused": reused},
    })
    return intent_id, reused


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def calculate_quote(product_id: str, quantity: int, discount_code: str | None) -> dict:
    product = PRODUCTS[product_id]
    subtotal = product["amount_minor"] * quantity
    code = str(discount_code or "").strip().upper()[:40]
    discount = 0
    status = "not_provided"
    message = "No discount code applied."
    if code:
        rule = DISCOUNT_CODES.get(code)
        if rule is None:
            status, message = "invalid", "Code not recognized; no discount applied."
        elif rule["kind"] == "expired":
            status, message = "expired", "Code has expired; no discount applied."
        elif subtotal < rule.get("minimum_minor", 0):
            status, message = "minimum_not_met", "Order does not meet this code's minimum; no discount applied."
        else:
            discount = subtotal * rule["value"] // 100 if rule["kind"] == "percent" else rule["value_minor"]
            status, message = "applied", "Discount applied."
    return {
        "product_id": product_id, "quantity": quantity, "discount_code": code,
        "discount_status": status, "discount_message": message,
        "subtotal_minor": subtotal, "discount_minor": discount,
        "amount_minor": subtotal - discount, "currency": product["currency"],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "NorthstarTraining/1.0"

    def log_message(self, _format, *_args):
        return

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()

    def send_bytes(self, body: bytes, content_type: str, status: int = 200, filename: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", 'attachment; filename="' + filename + '"')
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: dict, status: int = 200):
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8", status)

    def read_json(self) -> dict:
        length = safe_int(self.headers.get("Content-Length"), 0)
        if length < 0 or length > 65536:
            raise ValueError("Request body must be no larger than 64 KiB.")
        parsed = json.loads((self.rfile.read(length) if length else b"{}").decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("Request body must be a JSON object.")
        return parsed

    def event(self, connection: sqlite3.Connection, event_type: str, **fields):
        insert_event(connection, {"event_time": now_utc(), "event_type": event_type, **fields})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)
        if path == "/":
            return self.send_bytes(HOME_HTML.encode(), "text/html; charset=utf-8")
        if path == "/analyst":
            return self.send_bytes(ANALYST_HTML.encode(), "text/html; charset=utf-8")
        if path == "/api/health":
            return self.send_json({"status": "ok", "training_data": True, "provider": "local mock"})
        if path == "/api/orders":
            return self.get_orders(query)
        if path.startswith("/api/orders/"):
            return self.get_order(path.rsplit("/", 1)[-1], query)
        if path == "/api/events":
            return self.get_events(query)
        if path.startswith("/exports/"):
            return self.export(path.rsplit("/", 1)[-1])
        return self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        try:
            body = self.read_json()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.send_json({"error": str(exc)}, 400)
        if path == "/api/reset":
            reset_database()
            return self.send_json({"status": "reset"})
        if path == "/api/discount/preview":
            return self.discount_preview(body)
        if path == "/api/checkout":
            return self.checkout(body)
        if path.startswith("/api/orders/") and path.endswith("/retry"):
            return self.retry_order(path.split("/")[-2], body)
        if path.startswith("/api/mock-provider/") and path.endswith("/confirm"):
            return self.confirm_intent(path.split("/")[-2], body)
        if path.startswith("/api/orders/") and path.endswith("/fulfill"):
            return self.fulfill_order(path.split("/")[-2], body)
        return self.send_json({"error": "Not found"}, 404)

    def get_orders(self, query: dict):
        user = (query.get("user") or [""])[0]
        if user not in USERS:
            return self.send_json({"error": "Select a listed training customer."}, 400)
        with database() as connection:
            rows = connection.execute(
                "SELECT * FROM orders WHERE owner_id=? ORDER BY created_at DESC", (user,),
            ).fetchall()
            return self.send_json({"orders": [order_dict(connection, row) for row in rows]})

    def get_order(self, order_id: str, query: dict):
        user = (query.get("user") or [""])[0]
        with database() as connection:
            row = connection.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
            if row is None:
                return self.send_json({"error": "Order not found"}, 404)
            owner = row["owner_id"]
            delegated = connection.execute(
                "SELECT reason FROM delegations WHERE actor_id=? AND order_id=?", (user, order_id),
            ).fetchone() if user == "support" else None
            allowed = user == owner or delegated is not None
            status = 200 if allowed else 403
            self.event(connection, "order.object_access", actor_id=user or "unknown",
                       session_id="sess-live-" + (user or "unknown"), order_id=order_id,
                       owner_id=owner, request_id="req-live-access-" + uuid.uuid4().hex[:8],
                       status=str(status), status_source="merchant authorization",
                       decision="allowed" if allowed else "denied",
                       resource="/api/orders/" + order_id,
                       details={"delegated": bool(delegated), "http_status": status})
            if not allowed:
                return self.send_json({"error": "Order not found"}, 403)
            result = order_dict(connection, row)
            result["delegation_reason"] = delegated["reason"] if delegated else None
            return self.send_json({"order": result})

    def get_events(self, query: dict):
        clauses, values = [], []
        for param, column in (("event_type", "event_type"), ("actor_id", "actor_id"), ("order_id", "order_id")):
            value = (query.get(param) or [""])[0].strip()
            if value:
                clauses.append(column + " LIKE ?")
                values.append("%" + value + "%")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with database() as connection:
            rows = connection.execute(
                "SELECT * FROM events" + where + " ORDER BY event_time DESC,event_id DESC LIMIT 500",
                values,
            ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            events.append(item)
        return self.send_json({"events": events})

    def export(self, name: str):
        if name == "events.jsonl":
            with database() as connection:
                rows = connection.execute("SELECT * FROM events ORDER BY event_time,event_id").fetchall()
            lines = []
            for row in rows:
                item = dict(row)
                item["details"] = json.loads(item.pop("details_json"))
                lines.append(json.dumps(item, ensure_ascii=False))
            return self.send_bytes(("\n".join(lines) + "\n").encode(), "application/x-ndjson", filename=name)
        path = Path(__file__).parent / "data" / name
        if name not in {"h04_orders.csv", "h04_payment_requests.csv", "h04_mapping.json"} or not path.is_file():
            return self.send_json({"error": "Not found"}, 404)
        content_type = "application/json" if path.suffix == ".json" else "text/csv"
        return self.send_bytes(path.read_bytes(), content_type, filename=name)

    def discount_preview(self, body: dict):
        user, product_id = body.get("user"), body.get("product_id")
        quantity = safe_int(body.get("quantity"), 0)
        if user not in USERS or product_id not in PRODUCTS or not 1 <= quantity <= 5:
            return self.send_json({"error": "Use a training customer, listed product, and quantity from 1 to 5."}, 400)
        return self.send_json(calculate_quote(product_id, quantity, body.get("discount_code")))

    def checkout(self, body: dict):
        user, product_id = body.get("user"), body.get("product_id")
        quantity = safe_int(body.get("quantity"), 0)
        product = PRODUCTS.get(product_id)
        if user not in USERS or product is None or not 1 <= quantity <= 5:
            return self.send_json({"error": "Use a training customer, listed product, and quantity from 1 to 5."}, 400)
        quote = calculate_quote(product_id, quantity, body.get("discount_code"))
        authoritative = quote["amount_minor"]
        claimed = safe_int(body.get("client_total_minor"), -1)
        session_id = str(body.get("session_id") or "sess-live-" + user)[:80]
        request_id = "req-live-checkout-" + uuid.uuid4().hex[:8]
        if claimed != authoritative:
            with database() as connection:
                self.event(connection, "checkout.amount_mismatch", actor_id=user, session_id=session_id,
                           request_id=request_id, amount_minor=claimed if claimed >= 0 else None,
                           currency=product["currency"], status="rejected", status_source="customer request",
                           decision="rejected_before_provider", resource="/api/checkout",
                           details={"client_claimed_total_minor": claimed,
                                    "authoritative_total_minor": authoritative,
                                    "product_id": product_id, "quantity": quantity,
                                    "discount_code": quote["discount_code"],
                                    "discount_status": quote["discount_status"],
                                    "subtotal_minor": quote["subtotal_minor"],
                                    "discount_minor": quote["discount_minor"]})
            return self.send_json({"error": "Client total did not match the merchant calculation; no payment intent was created.",
                                   "authoritative_total_minor": authoritative, "currency": product["currency"]}, 409)
        order_id = "ord-live-" + uuid.uuid4().hex[:10]
        idempotency_key = "idem-" + order_id
        created = now_utc()
        with database() as connection:
            connection.execute(
                """INSERT INTO orders
                (order_id,owner_id,amount_minor,currency,version,policy,product_id,quantity,
                 idempotency_key,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (order_id, user, authoritative, product["currency"], 1, "succeeded_only",
                 product_id, quantity, idempotency_key, created),
            )
            self.event(connection, "order.snapshot", actor_id=user, session_id=session_id,
                       order_id=order_id, owner_id=user, request_id=request_id,
                       order_version=1, amount_minor=authoritative, currency=product["currency"],
                       status="created", status_source="merchant calculation", decision="accepted",
                       resource="/api/checkout",
                       details={"product_id": product_id, "product_name": product["name"], "quantity": quantity,
                                "subtotal_minor": quote["subtotal_minor"],
                                "discount_minor": quote["discount_minor"],
                                "discount_code": quote["discount_code"],
                                "discount_status": quote["discount_status"]})
            if quote["discount_code"]:
                self.event(connection, "discount.code_validation", actor_id=user, session_id=session_id,
                           order_id=order_id, owner_id=user, request_id=request_id,
                           order_version=1, amount_minor=authoritative, currency=product["currency"],
                           status=quote["discount_status"], status_source="merchant validation",
                           decision="discount_applied" if quote["discount_status"] == "applied" else "no_discount_applied",
                           resource="/api/checkout",
                           details={"code": quote["discount_code"],
                                    "subtotal_minor": quote["subtotal_minor"],
                                    "discount_minor": quote["discount_minor"],
                                    "total_minor": authoritative,
                                    "message": quote["discount_message"]})
            order = connection.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
            intent_id, _ = insert_or_reuse_intent(connection, order, request_id)
            fingerprint = connection.execute(
                "SELECT secret_fingerprint FROM payment_intents WHERE payment_intent_id=?", (intent_id,),
            ).fetchone()["secret_fingerprint"]
            self.event(connection, "client_secret.delivery", actor_id=user, session_id=session_id,
                       order_id=order_id, owner_id=user, request_id=request_id,
                       payment_intent_id=intent_id, status="delivered", status_source="merchant response",
                       decision="intended_session", resource="/api/checkout",
                       secret_fingerprint=fingerprint,
                       details={"raw_secret_logged": False, "recipient_session": session_id})
        return self.send_json({"order_id": order_id, "payment_intent_id": intent_id,
                               "subtotal_minor": quote["subtotal_minor"],
                               "discount_minor": quote["discount_minor"],
                               "discount_code": quote["discount_code"],
                               "discount_status": quote["discount_status"],
                               "amount_minor": authoritative, "currency": product["currency"]}, 201)

    def retry_order(self, order_id: str, body: dict):
        user = body.get("user")
        request_id = str(body.get("request_id") or ("req-live-retry-" + uuid.uuid4().hex[:8]))[:100]
        with database() as connection:
            order = connection.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
            if order is None or user != order["owner_id"]:
                return self.send_json({"error": "Order not found"}, 404)
            intent_id, reused = insert_or_reuse_intent(connection, order, request_id)
            return self.send_json({"payment_intent_id": intent_id, "reused": reused})

    def confirm_intent(self, intent_id: str, body: dict):
        user, status = body.get("user"), body.get("status")
        request_id = str(body.get("request_id") or ("req-live-state-" + uuid.uuid4().hex[:8]))[:100]
        if status not in PROVIDER_STATES:
            return self.send_json({"error": "Choose one of the listed mock provider states."}, 400)
        with database() as connection:
            intent = connection.execute(
                """SELECT p.*,o.owner_id,o.version FROM payment_intents p
                JOIN orders o ON o.order_id=p.order_id WHERE p.payment_intent_id=?""",
                (intent_id,),
            ).fetchone()
            if intent is None or user != intent["owner_id"]:
                return self.send_json({"error": "Payment intent not found"}, 404)
            connection.execute("UPDATE payment_intents SET status=? WHERE payment_intent_id=?",
                               (status, intent_id))
            self.event(connection, "payment_intent.provider_state", actor_id=user,
                       session_id="sess-live-" + user, order_id=intent["order_id"], owner_id=user,
                       request_id=request_id, payment_intent_id=intent_id,
                       order_version=intent["version"], amount_minor=intent["amount_minor"],
                       currency=intent["currency"], status=status, status_source="local provider",
                       decision="state_updated", resource="/mock-provider/v1/payment_intents/" + intent_id,
                       details={"training_simulation": True})
        return self.send_json({"payment_intent_id": intent_id, "status": status})

    def fulfill_order(self, order_id: str, body: dict):
        user = body.get("user")
        client_status = str(body.get("client_reported_status") or "")[:50]
        request_id = str(body.get("request_id") or ("req-live-fulfill-" + uuid.uuid4().hex[:8]))[:100]
        with database() as connection:
            row = connection.execute(
                """SELECT o.*,p.status AS provider_status,p.payment_intent_id
                FROM orders o LEFT JOIN payment_intents p ON p.payment_intent_id=o.payment_intent_id
                WHERE o.order_id=?""", (order_id,),
            ).fetchone()
            if row is None or user != row["owner_id"]:
                return self.send_json({"error": "Order not found"}, 404)
            allowed = row["provider_status"] == "succeeded" or (
                row["provider_status"] == "requires_capture" and row["policy"] == "authorization_allowed"
            )
            decision = "fulfilled" if allowed else "blocked"
            reason = "authoritative provider state satisfies the order policy" if allowed else "authoritative provider state does not satisfy the order policy"
            self.event(connection, "fulfillment.decision", actor_id=user,
                       session_id="sess-live-" + user, order_id=order_id, owner_id=user,
                       request_id=request_id, payment_intent_id=row["payment_intent_id"],
                       order_version=row["version"], amount_minor=row["amount_minor"],
                       currency=row["currency"], status=row["provider_status"],
                       status_source="server provider lookup", decision=decision,
                       resource="/api/orders/" + order_id + "/fulfill",
                       details={"client_reported_status": client_status,
                                "fulfillment_policy": row["policy"],
                                "browser_claim_used_as_authority": False})
        return self.send_json({"decision": decision, "reason": reason, "provider_status": row["provider_status"]})


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with database() as connection:
        count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if not count:
        reset_database()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Payment Hunt Lab listening on " + HOST + ":" + str(PORT) + "; database=" + str(DB_PATH), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
