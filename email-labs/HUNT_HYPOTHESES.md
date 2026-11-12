# Lab 2 Hunt Hypotheses

## Scope and limits

These five hypotheses are derived from the supplied AWS Intelligent Email Responder CycloneDX model and scoped to its email-to-case workflow. They are testable against the lab's synthetic records and fixtures. They are not claims about a deployed AWS environment.

Input model: /Users/donavancheah/precogly-ics-test/aws-intelligent-email-responder-threat-enriched.cdx.json  
SHA-256: 5b869bd5f6c7cb82833479a23f5da6702d3d4747b26fdd8ad63aff57cb06ae4a  
Analysis date: 2026-10-20.  
Inventory reviewed: all 16 threat and 51 scenario records, plus the linked assets, flows, and controls used for this scope.  
Testability: all five are testable against the lab fixture. Production testability is unknown because this model does not specify deployed event schemas, retention, or implementation details.

The event fields below are lab instrumentation proposed to make the hypotheses testable. The CycloneDX source identifies the relevant data and trust boundaries but does not define production event formats. ATT&CK tags in the source model are not adopted as confirmed mappings. No live hunt has been run.

## H01 — Replayed receipt creates duplicate work

**Hypothesis:** If a receipt event is replayed without effective message-ID deduplication, the event ledger will show multiple workflow runs or simulated replies for the same message ID and object location.

- **Lab testability:** Testable with the receipt-replay fixture.
- **Evidence:** Receipt ID, message ID, object location, attempt number, deduplication decision, workflow-run ID, case ID, and reply ID. Compare receipt and workflow records by message ID and time.
- **Benign explanation:** A delivery retry is expected when it produces one effective workflow action and one response. Confirm the deduplication key and output count.
- **Model basis:** threat-event-forgery at /threats/threats/6; scenario-event-forgery-sns at /threats/scenarios/16, scenario-event-forgery-sns-to-lambda at /threats/scenarios/17, and scenario-event-forgery-lambda-to-workflow at /threats/scenarios/18; control-event-auth at /controls/3.

## H02 — Unverified sender identity misroutes a reply

**Hypothesis:** If the workflow trusts an unauthenticated From or Reply-To address, a message may be associated with a customer case and a simulated reply may go to a recipient that does not match the verified customer identity.

- **Lab testability:** Testable with the sender-mismatch fixture.
- **Evidence:** From, Reply-To, mail-authentication result, resolved customer and case IDs, review requirement, outbound recipient, and reply decision. Compare the raw headers with the customer record and reply ledger.
- **Benign explanation:** A customer may use a verified alias. Confirm the account's approved contact addresses before classifying a mismatch.
- **Model basis:** threat-spoofed-identity at /threats/threats/1; scenario-spoofed-identity-exchange-to-ses at /threats/scenarios/3, scenario-spoofed-identity-workflow at /threats/scenarios/4, and scenario-spoofed-identity-workflow-to-ses at /threats/scenarios/5; controls control-mail-auth at /controls/0, control-review-gate at /controls/5, and control-reply-scope at /controls/7.

## H03 — Message-supplied identifiers cross a customer boundary

**Hypothesis:** If the workflow treats a customer or case identifier found in email text as authority, a lookup may return a record whose customer differs from the customer established by the inbound message.

- **Lab testability:** Testable with the cross-customer lookup fixture.
- **Evidence:** Authenticated customer, message-supplied customer and case IDs, lookup request, returned record owner, authorization result, and any reply context. Compare both customer IDs and correlate by message ID, case ID, source IP, and time.
- **Benign explanation:** A support case can include a recorded delegation. The identifier's presence in a message is not itself evidence of delegation.
- **Follow-on investigation:** If source IP, session, or event time leads to related activity, record a new hypothesis before examining the adjacent records. Do not assume that a shared IP alone proves a shared actor.
- **Model basis:** threat-untrusted-parameters at /threats/threats/3 and threat-lake-overreach at /threats/threats/8; scenario-untrusted-parameters-workflow at /threats/scenarios/9, scenario-untrusted-parameters-workflow-to-lake at /threats/scenarios/10, scenario-lake-overreach-workflow-to-lake at /threats/scenarios/23, and scenario-lake-overreach-lake-to-workflow at /threats/scenarios/24; controls control-content-boundary at /controls/6 and control-lake-auth at /controls/8.

## H04 — Ambiguous or high-impact request bypasses review

**Hypothesis:** If the workflow treats a decision-engine recommendation as authorization, an ambiguous or high-impact request may reach the simulated outbound ledger even though the policy requires human review.

- **Lab testability:** Testable with the review-bypass fixture.
- **Evidence:** Message ID, intent label, synthetic confidence fixture, sensitivity or impact flag, review-required reason, reviewer identity, review decision, recipient, and outbound event. Compare the result with the stated policy; a score alone does not establish safety.
- **Benign explanation:** A complete, low-impact request may qualify for an approved template reply. Verify the policy category and required review state.
- **Model basis:** threat-model-misroute at /threats/threats/9; scenarios scenario-model-misroute-comprehend at /threats/scenarios/26, scenario-model-misroute-translate at /threats/scenarios/27, scenario-model-misroute-intent at /threats/scenarios/28, scenario-model-misroute-nba at /threats/scenarios/29, and scenario-model-misroute-workflow-to-ses at /threats/scenarios/30; controls control-model-validation at /controls/9 and control-review-gate at /controls/5.

## H05 — MIME content exceeds safe processing boundaries

**Hypothesis:** If message size, MIME nesting, or rendering limits are not enforced, a message may pass into workflow or agent display despite exceeding the configured parser boundary or failing sanitization.

- **Lab testability:** Testable with benign metadata-only parser fixtures. The lab does not include executable attachments.
- **Evidence:** Declared message and part sizes, nesting depth, parser result, reject/quarantine reason, sanitization result, queue visibility, and event time.
- **Benign explanation:** A rejected or quarantined item may be a successful protective action. Confirm that the queue did not render the content and that the reason was recorded.
- **Model basis:** threat-mime-payload at /threats/threats/2; scenario-mime-payload-raw-s3 at /threats/scenarios/6, scenario-mime-payload-s3-to-workflow at /threats/scenarios/7, and scenario-mime-payload-queue-to-agent at /threats/scenarios/8; control-mail-parse at /controls/1.

## Source and hypothesis-generation boundary

These five are starter hypotheses derived from the AWS model. The event ledger may support additional hypotheses; students should document the evidence and data joins before following those leads. Keep source-model statements separate from conclusions based on lab records.

Students investigate only this synthetic fixture. A result marked supported, refuted, or inconclusive applies to the lab data and does not establish that a production responder has the same behavior.
