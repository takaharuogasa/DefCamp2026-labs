# Lab 2 — Email Responder Hunt

Lab 2 is a local, single-container threat-hunting exercise based on the AWS Intelligent Email Responder CycloneDX model. Students investigate five proposed hunts in a fictional customer-support service, then use evidence to decide whether additional hypotheses are warranted.

## Start the lab

Requirements: Docker Desktop or Docker Engine with Docker Compose v2.

From this directory, run:

~~~
docker compose up --build
~~~

Then open **http://localhost:8081**.

Default training credentials:

- Username: **analyst**
- Password: **ResponderLab-8081!**

The same credentials are printed on the sign-in page. The service is published on the host's loopback interface. Keep this training lab on your local machine; do not port-forward or expose it to a shared or public network.

Stop it with Ctrl-C, or run:

~~~
docker compose down
~~~

## Functional checks

Run the HTTP-level functional suite in a disposable Compose container:

~~~
docker compose run --rm --no-deps email-hunt python /app/test_functional.py
~~~

The tests bind an ephemeral local port and use a temporary SQLite database. They cover sign-in, protected pages, all five training fixtures, the seeded investigation pivot, JSONL export, reset behavior, and the intentionally vulnerable login path. They do not run `sqlmap`.

Use **Reset training data** in the dashboard to restore the fixed synthetic timeline and remove interactive activity. To remove the named database volume as well:

~~~
docker compose down -v
~~~

## What students do

1. Read the [business and lab overview](BUSINESS_AND_LAB_OVERVIEW.md).
2. Review the five proposed hypotheses in [HUNT_HYPOTHESES.md](HUNT_HYPOTHESES.md).
3. Run the training fixtures, inspect Inbox, Cases, Review Queue, Simulated Replies, and Analyst Events.
4. Use the [student worksheet](STUDENT_WORKSHEET.md) to record evidence, benign explanations, gaps, and conclusions.
5. Follow useful leads beyond the five initial hypotheses and draft a follow-on hypothesis before deciding whether it is supported.
6. Take findings into the instructor-led discussion. The facilitator guide contains seeded interpretations and must be held back until then.

The event explorer supports filtering by event type, source IP, session ID, message ID, case ID, and customer ID. Students can export the synthetic ledger as JSONL for offline review.

## Lab boundaries

The container uses a Python standard-library web app and SQLite. Local modules represent the responder's logical services; there is no AWS account, AWS credential, real mail server, external model, or outbound email. Every customer, message, event, address, and export is synthetic. The app does not contact external services at runtime.

The root URL starts at the sign-in page. Port 8081 is reserved for this lab so Lab 1 can keep using port 8080.
