# DefCamp 2026 — Threat Modelling 201 Labs

Local, hands-on security threat-hunting exercises for the **Threat Modelling 201** workshop at DefCamp 2026.

This repository contains two standalone training labs. Each provides a fictional business scenario, an application with seeded investigation events, five hunt hypotheses, a student worksheet, and functional tests. The labs use Python's standard library, SQLite, and Docker; they do not require external payment, email, or cloud services.

## Labs

| Lab | Focus | Host URL |
| --- | --- | --- |
| [Payment Threat-Hunting Lab](payment-labs/README.md) | Checkout amounts and discounts, PaymentIntent creation, order authorization, fulfillment decisions, and client-secret handling | http://localhost:8080 |
| [Email Responder Hunt](email-labs/README.md) | Duplicate processing, sender verification, customer boundaries, human-review gates, and MIME handling | http://localhost:8081 |

For business context and exercises, see each lab's `BUSINESS_AND_LAB_OVERVIEW.md`, `HUNT_HYPOTHESES.md`, and `STUDENT_WORKSHEET.md`.

## Requirements

- Git
- Docker Engine or Docker Desktop
- Docker Compose **v2** (`docker compose`)

Check Docker and Compose:

```sh
docker --version
docker compose version
```

If `docker compose` is unavailable, install Docker Compose v2 for your operating system before starting the labs.

## Quick start

Clone the repository:

```sh
git clone https://github.com/takaharuogasa/DefCamp2026-labs.git
cd DefCamp2026-labs
```

### Payment Lab

From the repository root:

```sh
cd payment-labs
docker compose up --build
```

Open the [storefront](http://localhost:8080) or [Analyst Event Explorer](http://localhost:8080/analyst).

To run the included functional tests, open another terminal in `payment-labs/` while the container is running:

```sh
docker compose exec -T payment-hunt python /app/test_functional.py
```

Full instructions: [Payment Lab README](payment-labs/README.md).

### Email Lab

From the repository root, or in another terminal if Payment Lab is running:

```sh
cd email-labs
docker compose up --build
```

Open http://localhost:8081. The training username and password are displayed on its sign-in page.

Run the included functional tests from another terminal in `email-labs/`:

```sh
docker compose run --rm --no-deps email-hunt python /app/test_functional.py
```

Full instructions: [Email Lab README](email-labs/README.md).

The labs can run simultaneously: Payment uses host port **8080**, Email uses **8081**.

## Stop or reset

In the relevant lab directory, press **Ctrl+C** to stop a foreground process, or run:

```sh
docker compose down
```

Use **Reset training data** in the app to restore the seeded records.

To also delete the lab's persistent training database volume:

```sh
docker compose down -v
```

**Warning:** `down -v` removes saved local training activity.

## Suggested exercise workflow

1. Read the lab's business overview and the five proposed hunt hypotheses.
2. Explore normal application behavior before reviewing suspicious events.
3. Correlate evidence using order, message, case, request, session, and event identifiers as appropriate.
4. Record evidence for and against each hypothesis, benign explanations, and missing telemetry.
5. Conclude whether each hypothesis is **supported**, **refuted**, or **inconclusive** in this synthetic environment.

Some events and behaviors, including intentionally insecure paths, are deliberately designed as investigation material. They are not necessarily defects in the lab.

## Security and environment boundaries

These applications are **for local training only**. The supplied Compose configurations bind host ports to `127.0.0.1`; do not expose them on a shared or public network.

- All customers, orders, payment intents, email messages, and investigation records are synthetic.
- No real card payments, outgoing email, AWS account, or Stripe credentials are needed.
- The Email Lab contains an intentionally vulnerable login path for the exercise.
- Findings are about the simulated scenarios, not production systems.

## Known documentation limitations

- The Payment Lab README refers to `/opt/payment_amount_hunt.py`, but that helper is **not included** in the current repository image. Do not attempt that command as written. You can investigate the included data in [`payment-labs/data/`](payment-labs/data/) and the Analyst Event Explorer.
- The `FACILITATOR.md` referenced in Payment Lab documentation is **not included** in this public repository. Instructor-only materials should be distributed separately.
- The Payment Lab's **H04** CSV naming refers to an amount-comparison dataset; its amount-integrity hypothesis is named **H01** in [`HUNT_HYPOTHESES.md`](payment-labs/HUNT_HYPOTHESES.md).

## Reuse and attribution

This repository currently has **no LICENSE file**. Public access does not by itself grant permission to reuse or redistribute the underlying workshop materials. Check applicable terms and permissions with the original material owners before reuse.
