# Payment Hunt Lab: Business and Lab Overview

## Why this document exists

Use this guide to orient students and facilitators before the exercise. It explains the fictional business scenario, what the lab represents, how students move from a threat model to a hunt, and what the storefront controls do. The README covers installation and commands; the hypothesis cards and worksheet support the investigation itself.

## Business use case

Northstar Market is a fictional online merchant selling a training course, a field guide, and a demo mug. A customer chooses an item and quantity, may enter a discount code, and submits an order. The merchant calculates the amount due and creates a payment intent with a payment provider. After payment, the merchant decides whether the order can be fulfilled.

The storefront provides five synthetic customer profiles: Alice, Bob, Charlie, Dean, and Elaina. Each profile has its own order list for practicing customer-scoped access.

The business problem for the exercise is straightforward: payment workflows cross trust boundaries. A browser is controlled by the customer; the merchant owns order pricing and authorization; the provider owns authoritative payment state. Discounts are normal business activity, while a changed amount, duplicate payment attempt, unauthorized order read, or fulfillment based only on a browser claim may signal a control gap.

The training use case is to help an application-security or threat-hunting team turn a payment threat model into practical investigation work. Students practice defining observable hypotheses, finding relevant records, joining evidence, checking legitimate explanations, and describing what the available evidence cannot establish. The seeded anomalies are intentionally synthetic examples, not claims about Northstar Market or any real merchant.

## How the lab works

The lab runs as one container with several logical roles:

```text
Customer browser → Storefront and merchant API → Local mock payment provider
                         │                               │
                         └────────── SQLite ledger ──────┘
                                      ↑
                              Analyst event explorer
```

- **Storefront:** lets students select a synthetic customer and product, enter a coupon, create an order, and inspect their orders.
- **Merchant API:** recalculates prices and discounts, creates orders, checks order ownership, asks the mock provider for payment state, and makes fulfillment decisions.
- **Local mock provider:** represents a provider boundary and PaymentIntent-style lifecycle. It never contacts a real payment provider.
- **SQLite event ledger:** stores deterministic seed records plus activity from the interactive storefront. Students can filter and export records in the analyst event explorer.
- **Analyst event explorer:** helps students search by event type, actor, and order ID, then correlate events by order, request, PaymentIntent, session, version, and time.

The initial dataset contains five hunt leads drawn from the supplied payment CycloneDX threat model. Interactive actions append new events; they do not alter the seeded case records. Reset training data restores the seed dataset and removes interactive activity.

## Student path

1. Read the assigned hypothesis card and rewrite its statement as a falsifiable question: what behavior should create which evidence, joined by which identifiers, in what time window?
2. Complete an ordinary checkout and trace its order snapshot, provider request, and provider state through the analyst explorer.
3. Exercise the discount flow, order retry, provider-state selector, and fulfillment action to learn what expected business activity looks like.
4. Investigate the five seeded leads: amount and discount integrity; repeated payment creation; object-level authorization; fulfillment based on payment state; and client-secret exposure.
5. Record evidence for and against the hypothesis, a benign explanation, missing telemetry, and an assessment of supported, refuted, or inconclusive **within this dataset**.
6. Discuss how the threat model or telemetry should change and what evidence would be required before making a real-world incident or ATT&CK claim.

This sequence separates the hands-on investigation from the group discussion. Facilitators can assign one hunt per team or have teams rotate through all five; suggested timing and expected findings are in [FACILITATOR.md](FACILITATOR.md).

## Discount-code exercise

The discount field makes normal price adjustment part of checkout, so students can compare a legitimate discount with an expired or ineligible code. Codes are checked and amounts are recalculated by the merchant API. The browser displays a quote but does not set the authoritative order total.

| Code | Expected behavior |
|---|---|
| `WELCOME10` | Valid: 10% off the subtotal. |
| `STUDENT5` | Valid: SGD 5.00 off when the subtotal is at least SGD 25.00. |
| `EXPIRED50` | Expired: no discount. |
| Any unknown code, such as `NOTREAL` | Invalid: no discount. |
| `STUDENT5` on the SGD 15.00 mug | Recognized but minimum not met: no discount. |

An expired, unknown, or ineligible code does not prevent a customer from placing an order at the regular price. If a code was supplied at checkout, the order records the merchant's validation result in a `discount.code_validation` event. Students can compare the accepted code, subtotal, discount, and total in the order snapshot and event details. A browser-submitted amount that differs from the merchant's calculation is rejected before a payment intent is created.

## What the controls under “My orders” do

Each order shows the order ID, current mock-provider state, total, owner, order version, and PaymentIntent ID. The buttons are deliberate training controls:

1. **Retry with same idempotency key** sends another create-payment request for that order. The merchant reuses the original idempotency key and should return the same PaymentIntent. Students can compare the retry event with the original request and distinguish a safe retry from duplicate creation.
2. **Provider-state dropdown** offers `succeeded`, `processing`, and `requires_payment_method`. **Set mock provider outcome** changes the local mock intent to the selected state. It simulates provider state for training; it does not charge a card or contact a provider.
3. **Submit browser “success” claim** asks the merchant to fulfill the order while sending a customer-reported `succeeded` state. The merchant should make its decision from the stored provider state and order policy, not trust the browser claim. Try it while the provider state is `processing` or `requires_payment_method`, then compare the fulfillment decision with the browser claim.

These controls let a class produce benign retry events and controlled payment-state transitions, then inspect how the server handles them.

## Scope and limits

All names, orders, payment intents, discount codes, secret fingerprints, and hunt signals are synthetic. No payment-card form is present. The lab does not need credentials, make external network calls, or prove that any production control is present or absent. The one-container application is representative enough to practice trust-boundary reasoning and event correlation; it is not a deployable payment implementation.

The seeded H04 amount helper compares synthetic order snapshots and provider requests. A mismatch or missing join is an investigation lead. Students should check order version, valid repricing, export coverage, and time alignment before reaching a conclusion. Refer to [HUNT_HYPOTHESES.md](HUNT_HYPOTHESES.md) for threat-model provenance and explicit scope limits.
