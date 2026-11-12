# Payment Hunt Hypotheses

## Scope and limits

These five hypotheses are derived from the supplied CycloneDX payment model and grouped around the model's customer-to-merchant and merchant-to-provider payment flow. They are testable against the lab's synthetic records. They are not claims about a deployed system, and the seeded leads are not real incidents.

Model input: /Users/donavancheah/LLM-Threat-Hypothesis-Engine-master/payment-precogly.cdx.json  
SHA-256: 83930cbd88267040c9d2b5d87bd66871c4264540096bd9834859c6d53b3e08d6  
Analysis date: 2026-10-19.  
ATT&CK knowledge-base release checked: Enterprise ATT&CK 19.2.  
Scope read: complete tm list inventory (133 items over two pages), the selected threat and scenario records, and their referenced flow/asset links. Other threat and scenario detail records were not needed for this five-threat lab selection. The supplied DFD has no production event schema, retention period, deployment confirmation, or observations. Therefore all testability below is for the lab fixture only.

## H01 — Client-controlled total differs from the authoritative order

**Hypothesis:** If the merchant creates a provider PaymentIntent from a client-submitted total instead of the current server-calculated order total, a provider request will have a lower amount or different currency than the latest authoritative snapshot for the same order.

- **Lab testability:** Testable against the fixture; not validated for any production system.
- **Evidence:** Order snapshots and PaymentIntent create requests with order ID, calculation/request time, amount, currency, version, request ID, and intent ID. Compare the latest snapshot at or before each request.
- **Benign explanation:** An approved discount or repricing changed the order. Check the version and the order.adjustment approval reference before treating a difference as suspicious.
- **Seeded ambiguity:** One request has no matching prior order snapshot. Investigate export coverage and join keys before drawing a conclusion.
- **Model references:** threat-6-client-controlled-amount-or-order-data-could-reduce-the-payment at /threats/threats/5; scenarios scenario-6-1-client-controlled-amount-or-order-data-could-reduce-the-payment at /threats/scenarios/5 and scenario-6-2-client-controlled-amount-or-order-data-could-reduce-the-payment at /threats/scenarios/6; relevant flows at /blueprints/0/flows/3 and /blueprints/0/flows/4.
- **ATT&CK:** Deferred. The model's T1565.002 label does not establish in-transit manipulation. The lab compares application and provider-request records; it does not simulate an on-path adversary.

## H02 — Repeated create requests produce distinct PaymentIntents

**Hypothesis:** If the same unchanged order is replayed without effective idempotency, multiple create requests will be associated with distinct PaymentIntent IDs for the same order version.

- **Lab testability:** Testable against the fixture.
- **Evidence:** Order ID/version, create-request time, request ID, idempotency key, and PaymentIntent ID. Compare repeated requests and resulting provider objects.
- **Benign explanation:** A network retry may be harmless if the same idempotency key returns the same intent. An order-version change may also justify a new attempt.
- **Caution:** Distinct intents show duplicate payment attempts in the training records; they do not alone establish that two charges settled.
- **Model references:** threat-9-replayed-order-intent-requests-could-create-duplicate-payment-attempts at /threats/threats/8; scenario-9-1-replayed-order-intent-requests-could-create-duplicate-payment-attempts at /threats/scenarios/11 and scenario-9-2-replayed-order-intent-requests-could-create-duplicate-payment-attempts at /threats/scenarios/12; threat-22-replayed-create-payment-requests-could-produce-duplicates at /threats/threats/21 and scenario-22-1-replayed-create-payment-requests-could-produce-duplicates at /threats/scenarios/25.
- **ATT&CK:** Deferred. The model's denial-of-service and transmitted-data tags would need evidence of resource exhaustion or adversary manipulation to support those mappings.

## H03 — An actor accesses an order without ownership or delegation

**Hypothesis:** If an authenticated actor reads or changes an order they do not own and lack delegation to access, the merchant request log will show an actor/order-owner mismatch and an allowed response.

- **Lab testability:** Testable against the fixture.
- **Evidence:** Actor, order owner, order ID, route, delegation record, HTTP result, and event time.
- **Benign explanation:** A support agent may be authorized by a contemporaneous support-case delegation. Verify the specific order and reason, not just the actor's role.
- **Model references:** threat-23-broken-object-authorization-could-expose-or-pay-another-customer-order at /threats/threats/22; scenario scenario-23-1-broken-object-authorization-could-expose-or-pay-another-customer-order at /threats/scenarios/26; merchant asset at /blueprints/0/assets/2.
- **ATT&CK:** Deferred. This is an application authorization pattern; the model's T1190 and T1213 tags are not supported merely by an object-ID mismatch.

## H04 — Fulfillment follows an unverified browser success claim

**Hypothesis:** If fulfillment is authorized from a browser-reported success state without applying the order's provider-state policy, a fulfillment event may be accepted while the authoritative provider state is failed, pending, or otherwise insufficient.

- **Lab testability:** Testable against the fixture.
- **Evidence:** Order ID, PaymentIntent ID, provider state at decision time, browser-reported state, server lookup or webhook source, fulfillment policy, and fulfillment decision.
- **Benign explanation:** A merchant may intentionally permit fulfillment on a provider authorization (requires_capture) or another documented state. Compare the decision with the order's recorded policy.
- **Model references:** threat-14-client-visible-payment-status-could-be-forged-or-stale at /threats/threats/13 and scenario-14-1-client-visible-payment-status-could-be-forged-or-stale at /threats/scenarios/17; threat-24-merchant-could-fulfill-based-on-untrusted-client-visible-status at /threats/threats/23 and scenario-24-1-merchant-could-fulfill-based-on-untrusted-client-visible-status at /threats/scenarios/27; relevant return flow at /blueprints/0/flows/7, merchant asset at /blueprints/0/assets/2.
- **Model gap:** The DFD does not show a server-side verification or webhook flow. That omission is a question to validate against a real deployment, not proof that verification is absent.
- **ATT&CK:** Deferred. The model's runtime-data-manipulation label would require evidence of adversarial status manipulation; a business-logic mismatch alone is insufficient.

## H05 — A client-secret fingerprint appears outside its intended session

**Hypothesis:** If a PaymentIntent client secret is exposed beyond its intended customer session, the same secret fingerprint will appear in a URL, referrer, analytics/log destination, or unrelated session.

- **Lab testability:** Testable against the synthetic fingerprint records only.
- **Evidence:** Fingerprint, intended recipient session, observed session, URL/referrer flags, destination, order/intent ID, and event time. No raw secret is present in the lab.
- **Benign explanation:** The customer receiving the secret for their own checkout is expected. Confirm that every additional occurrence is outside the intended session or recipient list.
- **Model references:** threat-7-paymentintent-or-client-secret-could-leak-through-the-browser at /threats/threats/6; scenario-7-1-paymentintent-or-client-secret-could-leak-through-the-browser at /threats/scenarios/7 and scenario-7-2-paymentintent-or-client-secret-could-leak-through-the-browser at /threats/scenarios/8; relevant return flow at /blueprints/0/flows/4.
- **ATT&CK:** Deferred. The synthetic fingerprint does not prove a real credential was exposed or used; the model's token/credential labels are not inherited as conclusions.

## ATT&CK and TIE handling

Behavior-based searches were run against the local Enterprise ATT&CK 19.2 corpus as a candidate check. The closest browser-related results included T1185 Browser Session Hijacking, T1539 Steal Web Session Cookie, and T1550.004 Web Session Cookie, but the fixture does not show session takeover or cookie theft: it contains only a synthetic client-secret fingerprint and destination flags. Other top-ranked results were unrelated host or cloud techniques. None is adopted as a mapping. No lab fixture represents an observed adversary technique, and the model's taxonomy labels are not treated as validated observations. TIE was not run because no ATT&CK seed was confirmed for these narrowly scoped behaviors. There are no real hunt results or compromise claims.

The exercises stop at human review: students formulate and assess hypotheses; an instructor checks the interpretation; a real hunt, if later authorized, requires validation against the deployed application's telemetry and business policies.
