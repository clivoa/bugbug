---
name: business-logic
version: "1.0.0"
description: "Race conditions, parameter pollution, IDOR, privilege escalation, workflow abuse"
risk_level: "L0-L2"
approval: "L2 requires explicit approval"
program_types: [web2, api]
source: "reviewed from reference repositories, PortSwigger research, OWASP"
actions:
  - web.param-discover
  - net.http-post
  - net.http-put
  - net.http-delete
  - net.http-patch
---

# Business Logic Vulnerabilities

**status:** active
**risk:** L0 (analysis) – L2 (validation)
**approval:** L2 requires explicit approval
**program_types:** [web2, api]
**source:** reviewed from reference repositories, PortSwigger research, OWASP

## Approach

Business logic flaws are failures in the *intended* application flow — not coding errors. They require understanding the business domain, not just the technology.

1. **Map the business flow** — every step, every parameter, every state transition
2. **Identify assumptions** — what does the developer assume cannot happen?
3. **Break assumptions** — skip steps, reorder, repeat, race, overflow, go negative

## Race Conditions (TOCTOU)

### Detection
- Identify endpoints that check a condition THEN act:
  - Apply coupon → check balance → deduct
  - Redeem gift card → check validity → credit account
  - Withdraw → check balance → transfer
- Time gap between check and action is the window

### Validation (L2 — approval required)
- Send identical requests simultaneously (within same TCP window)
- Use single-packet attack (HTTP pipelining, last-byte sync)
- **Minimal value only:** apply coupon twice for $0.01, not $100
- STOP after proving the race exists

## Parameter Pollution & Manipulation

### Detection
- Duplicate parameters: `?price=100&price=1`
- Array injection: `?price[]=1` (PHP), `?price[0]=1`
- JSON pollution: `{"price": 100, "price": 1}`
- HPP + HPC (client-side): `?price=100%26price=1`
- Parameter in body + query string: which wins?

### Key Parameters to Test
- `price`, `amount`, `quantity`, `total`, `balance`
- `discount`, `coupon`, `promo`, `referral`
- `role`, `type`, `isAdmin`, `verified`, `approved`
- `returnUrl`, `redirectUrl`, `callbackUrl`
- `currency`, `locale`, `version`

## Workflow Bypass

### Detection
- Skip steps: go directly to step 3 from step 1
- Repeat steps: submit step 2 twice before step 3
- Reverse steps: go back to step 1 after completing step 3
- Negative amounts: quantity=-1, amount=-100
- Zero amounts: price=0, quantity=0
- Extreme values: quantity=999999999, price=0.00001
- Type confusion: string "0" vs int 0 vs null

### Common Flawed Workflows
- **Checkout:** modify price client-side, apply multiple coupons
- **Password reset:** skip email verification, guess token, reuse token
- **Account creation:** skip email verification, create premium account for free
- **Redemption:** redeem same code twice, guess sequential codes
- **Voting/rating:** vote multiple times, vote with negative values

## Integer Overflow & Boundary Issues

### Detection
- Negative values in quantity/amount fields
- MAX_INT + 1: `?quantity=2147483648` (32-bit signed)
- Wrap-around: very large number → negative
- Zero: `?amount=0` — free?
- Float vs integer: `?price=0.0000000001`
- NaN, Infinity: `?price=NaN`, `?price=Infinity`

## Inconsistent Validation

### Detection
- Same endpoint, different clients: web vs API vs mobile app
- Different versions: v1 vs v2 of the API
- Different methods: GET vs POST same endpoint
- Content-type confusion: JSON vs form-encoded vs XML
- Different user roles: user vs admin getting different validation rules

## Coupon / Discount Abuse

### Detection
- Apply coupon → remove item → coupon still applied?
- Apply coupon → change quantity → discount unchanged?
- Apply coupon → add more expensive item → no re-validation?
- Stack coupons: expected limit enforced client-side?
- Coupon for other user's tier: sequential/guessable codes?
- Negative value coupon: what if discount > order total?

## Negative Testing Patterns

```
quantity: -1 → refund?
amount: 0 → free?
price: 0.0001 → rounding?
quantity: 999999 → overflow?
role: admin → mass assignment?
verified: true → param pollution?
```

## Stop Conditions

- Race condition: prove with minimal-value duplicate transaction
- Workflow bypass: prove single step skip, document the flow
- Coupon abuse: prove with minimum-denomination coupon reuse
- **NEVER** extract real financial value
- **NEVER** exploit beyond minimal proof
