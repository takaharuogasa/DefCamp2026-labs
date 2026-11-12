# Payment Threat-Hunting Lab

This lab turns five threats from the supplied payment CycloneDX model into a hands-on investigation in a representative local web application. It uses one container and Python's standard library. The app includes a customer storefront, a merchant API, a local mock payment-provider boundary, a SQLite event ledger, and an analyst event explorer.

Start with [BUSINESS_AND_LAB_OVERVIEW.md](BUSINESS_AND_LAB_OVERVIEW.md) for the business scenario, component roles, discount-code behavior, and an explanation of every control under **My orders**.

All customer identities, orders, payment intents, and secret fingerprints are synthetic. The lab does not collect payment-card data, use Stripe credentials, contact Stripe, or send traffic to external services.

## Application shape

The browser reaches the storefront and merchant API. The merchant API calls a local PaymentIntent-style provider endpoint. Orders, mock intents, and audit events are stored in SQLite. The analyst page reads the same event ledger and exports the training records. These are separate logical roles in one container, not a multi-container cloud stack.

~~~text
Customer browser → Storefront and merchant API → Local mock payment provider
                         │                               │
                         └────────── SQLite ledger ──────┘
                                      ↑
                              Analyst event explorer
~~~

## Start the lab

Requirements: Docker Desktop or Docker Engine with Docker Compose v2.

From this directory:

~~~sh
docker compose up --build
~~~

Open http://localhost:8080 for the storefront and http://localhost:8080/analyst for the event explorer. The host port is bound to localhost.

The container is named **payment-hunt**. Stop it with Ctrl-C, or run:

~~~sh
docker compose down
~~~

Use **Reset training data** in the storefront to restore the original dataset and clear interactive activity. To remove the lab's named data volume as well:

~~~sh
docker compose down -v
~~~

The last command deletes the lab's local database volume.

## Functional checks

With the container running, execute the standard-library functional suite:

~~~sh
docker compose exec -T payment-hunt python /app/test_functional.py
~~~

The suite starts a temporary local HTTP server and database inside the container. It checks customer selection, discount outcomes, checkout price enforcement, order ownership, retry reuse, provider-state changes, and fulfillment. Its temporary data is removed afterward; the class training volume is not changed.

## Lab flow

1. Complete one ordinary checkout and follow the order through the merchant API and local mock provider.
2. Read the supplied threat-hunt hypothesis cards in [HUNT_HYPOTHESES.md](HUNT_HYPOTHESES.md) and use [STUDENT_WORKSHEET.md](STUDENT_WORKSHEET.md) to record your reasoning.
3. Use the analyst event explorer or download its JSONL export. Correlate records by order ID, request ID, PaymentIntent ID, actor, session, and time.
4. Investigate the five leads: amount and discount integrity, repeated PaymentIntent creation, cross-customer order access, fulfillment based on browser status, and client-secret exposure.
5. For each lead, record evidence for and against the hypothesis, a benign explanation, missing data, and a conclusion of supported, refuted, or inconclusive.
6. Compare findings in the discussion. The dataset is synthetic and deterministic; a lab result is not evidence about a real payment platform.

## H04 amount-comparison helper

The existing read-only amount helper is included in the container. Run it against the synthetic order snapshots and PaymentIntent requests:

~~~sh
docker compose exec payment-hunt python /opt/payment_amount_hunt.py \
  --orders /app/data/h04_orders.csv \
  --stripe-requests /app/data/h04_payment_requests.csv \
  --mapping /app/data/h04_mapping.json \
  --since '2026-10-16T00:00:00Z' \
  --until '2026-10-17T00:00:00Z' \
  --out /tmp/h04-results.csv
~~~

The helper should report three matches, one amount mismatch, and one missing prior order snapshot. A match means only that the compared amount and currency agree with the latest earlier snapshot. A mismatch or missing join is an investigation lead, not a finding of fraud.

To inspect the output without installing tools on the host:

~~~sh
docker compose exec payment-hunt python -c "from pathlib import Path; print(Path('/tmp/h04-results.csv').read_text())"
~~~

The helper refuses to overwrite its output. Use another output name for a second run.

## Suggested student record

For every hunt, capture:

- Hypothesis: “If [behavior], then [specific evidence] should appear in [records] joined by [keys] during [time window].”
- Evidence that supports it and evidence that weakens it.
- A benign explanation and the data needed to distinguish it.
- Missing telemetry or ambiguity in the threat model.
- Assessment: supported, refuted, or inconclusive within this lab dataset.
- The next validation step and one proposed detection or control improvement.

See [FACILITATOR.md](FACILITATOR.md) for timing, expected findings, and discussion prompts. Keep that file from students until the discussion.
