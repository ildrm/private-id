# Billing and plans

`src/catalog.ts` is the sole catalog for API, UI, Stripe price checks and entitlements. Free: 20 monthly proofs, 5 active credentials, 5 connections. Professional: USD 12/month, 100 proofs, 50 credentials, 10 connections. Business: USD 49/month, 1,000 proofs, 500 credentials, 100 connections, one active organization with ten members including its owner. Unsupported priority-support/global-admin promises were removed.

Proof usage counts successful issuance in a UTC calendar month, not previews, denials, or failed transactions. Concurrent requests cannot overspend. Effective paid access requires a known plan, active/trialing provider status and a period end in the future. Inactive, past-due and expired subscriptions fall back to Free; history is separate. Existing over-limit data is retained; additional usage is blocked. Team membership is separate from staff roles.

## Provider setup

Enable billing only with `BILLING_ENABLED=true`, Stripe secret and webhook keys, and both monthly price IDs. Prices must be active, recurring monthly with quantity one, and match the published integer amount/currency. The adapter uses Stripe API **2026-07-29.dahlia** and reads subscription periods from subscription items. Configure the webhook endpoint to the same version and test/live mode; mismatches fail signature intake rather than guessing schema semantics.

Subscribe `/api/webhooks/stripe` to subscription created/updated/deleted; invoice paid/payment_failed/updated/voided/marked_uncollectible; refund created/updated/failed; charge.refunded; and charge.dispute created/updated/closed. The source-of-truth list is `handledEvents` in `src/stripe-gateway.ts`.

## Reliability

One durable checkout operation exists per account. Provider customer and checkout creation use stable idempotency keys. Before a new provider checkout, current active/nonterminal subscriptions are checked, preventing missed webhooks from creating another subscription. Customers with existing subscriptions use the billing portal. Checkout returns do not establish payment or entitlement.

Webhook intake verifies the raw body signature and commits a minimal receipt. A separate worker claims a lease, fetches the current provider object, then atomically updates projections/totals and marks completion. Failure leaves a retryable receipt. Unmapped early events remain pending. Retries use exponential backoff, with eight failed attempts before operator intervention. Expired processing leases are recovered. Pagination creates durable continuation jobs; billing reconciliation never assumes the first hundred historical records are complete.

Scheduled customer sweeps enqueue provider reconciliation at least once per completed hourly sweep; large account sets take proportionally longer. Reconciliation covers subscriptions, invoices and charge refunds. Disputes are maintained through the durable dispute event stream; reconcile missed historical disputes through provider event replay/operator review. Confirm reconciliation completion after incidents before relying on reporting.

## Money and deletion

Amounts are safe integers in each currency’s minor unit. Invoice upserts replace both amount and status. Successful refunds and disputed amounts are tracked separately from gross invoice payments. Currencies are never added together, and these totals are not recognized revenue, settlement cash, profit or financial statements. UI formatting uses the currency’s minor-unit exponent. Tax, exchange conversion, proration and settlement reporting belong to the provider/accounting process.

Deletion immediately revokes account access and queues provider cancellation. The worker expires open checkouts, cancels nonterminal subscriptions and clears provider contact fields before account erasure completes. Provider errors retain `DELETION_PENDING` for retry. Pseudonymous accounting references remain for the documented 730-day period. Actual provider transactions must be validated with a configured Stripe test account before production activation.
