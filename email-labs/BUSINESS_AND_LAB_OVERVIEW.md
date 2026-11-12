# Business and Lab Overview — Northstar Customer Care

## Business use case

Northstar Customer Care is a fictional online retailer's support team. Customers email questions about refunds, account access, addresses, invoices, and order changes. The responder service receives each message, associates it with a customer and case, classifies the request, retrieves relevant case context, and either queues it for an agent or records an automatic reply.

The supplied AWS model describes this workflow with services such as SES, SNS, Lambda, Step Functions, Comprehend, Translate, SageMaker, a data lake, an agent queue, and SES outbound delivery. Lab 2 represents those boundaries with local Python modules and records in one SQLite database.

## What the lab application represents

| Lab page or module | Business role | Source-model analogy |
|---|---|---|
| Sign-in page | Authenticate a training analyst before opening the workspace | Local analyst identity boundary |
| Inbox and message intake | Receive email and retain sender, Reply-To, and message identity | Corporate exchange, SES, raw-message storage |
| Receipt-event simulator | Start work when a message arrives; record retries and message pointers | SNS notification and Lambda trigger |
| Case/customer lookup | Resolve a message to a customer and retrieve a case | Responder workflow and enterprise data lake |
| Decision simulator | Produce a fixed intent, confidence fixture, and suggested action | Comprehend, Translate, intent model, and next-best-action model |
| Review Queue | Route ambiguous or sensitive requests to a human | Agent queue and review gate |
| Simulated Replies | Record the recipient and decision for an outbound response | Workflow-to-SES and SES-to-customer |
| Analyst Events | Search the event record and correlate the workflow | Cloud and application telemetry |

These are representative application roles, not AWS emulators. The lab cannot establish whether a real AWS account has a particular IAM policy, bucket permission, mail-authentication result, model behavior, or production telemetry.

## How to work through the lab

1. Start the Docker Compose service and open **http://localhost:8081**.
2. Sign in with the default training credentials shown on the page: **analyst** / **ResponderLab-8081!**.
3. Read one normal message in Inbox and follow its customer and case into the workflow.
4. Use the five fixture buttons on the dashboard to create controlled activity for the proposed hunts.
5. Compare Inbox, Cases, Review Queue, Simulated Replies, and Analyst Events. Use stable identifiers and event time to join records.
6. Record what supports the hypothesis, what weakens it, and what benign explanation could account for the same event.
7. If an event points to activity outside the current hypothesis, write a follow-on hypothesis before following that lead. The lab is designed to reward this investigative step.
8. Discuss conclusions and missing telemetry with the instructor.

## What is synthetic

Customer names, customer IDs, .test email addresses, cases, message bodies, event timestamps, source IPs, decision scores, response IDs, and exports are fictional. No real email is sent. The decision model is deterministic and exists to create explainable event evidence; it is not a production AI service.

The scenario timeline is fixed at **2026-10-20 08:00–08:31 UTC**. Students should interpret “ongoing” relative to the simulated collection time in that timeline, not as a statement about current real-world activity.
