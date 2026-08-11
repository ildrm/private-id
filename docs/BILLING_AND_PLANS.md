# Plans and billing

All monetary amounts are stored as integer cents. Plans returned by `/billing/plans` never expose Stripe price identifiers.

| Plan | Monthly price | Included product scope |
| --- | ---: | --- |
| Free | $0 | Identity wallet, five connected apps, core safety controls, baseline proof allowance |
| Professional | $12 | Expanded credential/proof limits and priority support |
| Business | $49 | Issuer/verifier workspace, team roles, audit-oriented workflows |

Paid checkout requires `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PROFESSIONAL`, and `STRIPE_PRICE_BUSINESS`. Configure Stripe to send subscription lifecycle, `invoice.paid`, and `invoice.payment_failed` events to `POST /webhooks/stripe` on this server. Signatures are verified against the raw body; event IDs are claimed once to make retries idempotent.

Authenticated customers create Checkout Sessions at `POST /billing/checkout`, inspect their effective subscription at `GET /billing/subscription`, and create a Customer Portal session at `POST /billing/portal`. Stripe owns card collection and payment-method storage. The application stores only provider/customer references, subscription status, invoice/payment references, currency, and amount.

Each PrivateID deployment must use a distinct Stripe product/price set and webhook secret; do not reuse another project's billing database or webhook endpoint.
