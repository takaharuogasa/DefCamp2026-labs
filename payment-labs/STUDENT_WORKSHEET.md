# Student Worksheet — Payment Threat Hunt

Team: ____________________    Date: ____________________    Hunt: ____________________

## Before searching

1. Which threat-model statement are you investigating?

   ______________________________________________________________________

2. Write a falsifiable hypothesis. State the behavior, evidence, data sources, join keys, and time window.

   If _________________________________________________________________,

   then I expect to find _______________________________________________

   in ______________________________ joined by ________________________

   during _____________________________________________________________.

3. What would weaken or refute the hypothesis?

   ______________________________________________________________________

## Evidence review

| Evidence ID or event | Supports or weakens? | Why? |
|---|---|---|
| | | |
| | | |
| | | |

What records or fields were missing, ambiguous, or outside the time window?

______________________________________________________________________

## Benign explanation

What ordinary activity could produce the same signal?

______________________________________________________________________

What additional record would help distinguish the benign explanation from misuse?

______________________________________________________________________

## Assessment

Choose one: **supported in the training dataset / refuted in the training dataset / inconclusive**.

Explain your choice without treating an anomaly as proof:

______________________________________________________________________

______________________________________________________________________

What is the next validation step if this were a real system?

______________________________________________________________________

## Hunt-specific prompts

### H01 — Amount and discount integrity

- Compare the latest authoritative order snapshot before the provider request.
- Check subtotal, accepted discount, total, currency, order version, request ID, and PaymentIntent ID.
- Try `WELCOME10`, `STUDENT5`, `EXPIRED50`, and an unknown code. Record which codes changed the server-calculated amount and which were ignored.
- Review any approved order adjustment before calling a difference suspicious. A difference is a lead, not proof of abuse.

### H02 — Repeated payment creation

- Group provider create requests by order ID and order version.
- Compare request count, idempotency key, and distinct PaymentIntent IDs.
- State whether the evidence shows duplicate attempts, duplicate settlements, or neither.

### H03 — Object-level authorization

- Compare the requesting actor with the order owner.
- Check the HTTP result and the specific delegation record for that order.
- Explain why a denied probe, a delegated support action, and an unauthorized successful read are different evidence.

### H04 — Fulfillment and payment state

- Join the fulfillment decision to provider state at decision time.
- Compare the browser-reported state, server lookup source, and fulfillment policy.
- Check whether a documented authorization or delayed-payment policy explains the state.

### H05 — Client-secret exposure

- Compare synthetic secret fingerprints across intended and observed sessions.
- Check URL/referrer indicators, destination, recipient, order ID, and time.
- Do not infer that a real credential exists or was used; only synthetic fingerprints are present.

## Discussion

1. Which evidence most changed your assessment?
2. Which benign explanation did you rule in or out, and how?
3. What telemetry or trust boundary should be added to the threat model?
4. What one detection or control would you recommend?
5. What additional evidence would you need before making an ATT&CK mapping?
