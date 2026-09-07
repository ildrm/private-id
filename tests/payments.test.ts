import test from "node:test";
import assert from "node:assert/strict";
import Stripe from "stripe";
import { MemoryDatabase } from "../src/repository.js";
import { AccountService } from "../src/accounts.js";
import { testConfig } from "../src/config.js";
import { planCatalog } from "../src/catalog.js";
import { BillingService } from "../src/payments.js";
import {
  StripeGateway,
  type BillingGateway,
  type Projection,
  type Receipt,
} from "../src/stripe-gateway.js";
import { createUser } from "./helpers.js";

class Gateway implements BillingGateway {
  configured = true;
  customers = new Map<string, string>();
  checkouts = new Map<string, { id: string; url: string; expiresAt: string }>();
  latest: Projection = { customerId: "cus_test" };
  fail = false;
  afterFetch?: () => void;
  async assertCheckoutAllowed() {}
  async createCustomer(_accountId: string, _email: string, key: string) {
    if (!this.customers.has(key)) this.customers.set(key, "cus_test");
    return this.customers.get(key)!;
  }
  async createCheckout(
    _customer: string,
    _plan: unknown,
    _site: string,
    key: string,
    expiresAt: string,
  ) {
    if (!this.checkouts.has(key))
      this.checkouts.set(key, {
        id: key,
        url: `https://checkout.test/${key}`,
        expiresAt,
      });
    return this.checkouts.get(key)!;
  }
  async createPortal() {
    return { url: "https://portal.test" };
  }
  parseWebhook(raw: Buffer) {
    return JSON.parse(raw.toString()) as Receipt;
  }
  async projection() {
    if (this.fail) throw new Error("synthetic provider failure");
    this.afterFetch?.();
    return structuredClone(this.latest);
  }
  async reconcile() {
    return this.projection();
  }
  async cancel() {}
}
async function fixture() {
  let time = Date.parse("2026-09-07T12:00:00.000Z");
  const clock = () => time,
    db = new MemoryDatabase(),
    config = testConfig({
      enableBilling: true,
      stripePrices: { professional: "price_pro", business: "price_business" },
    }),
    plans = planCatalog(config),
    accounts = new AccountService(db, config, clock),
    user = await createUser(accounts, "billing@example.test"),
    gateway = new Gateway(),
    billing = new BillingService(db, plans, gateway, config, clock);
  const event = (
    id: string,
    type = "customer.subscription.updated",
    created = Math.floor(clock() / 1000),
  ): Receipt => ({
    id,
    type,
    created,
    objectId: "sub_test",
    customerId: "cus_test",
  });
  return {
    clock,
    advance: (ms: number) => {
      time += ms;
    },
    db,
    config,
    plans,
    accounts,
    user,
    gateway,
    billing,
    event,
  };
}
test("concurrent checkout uses one stable customer and checkout operation", async () => {
  const f = await fixture();
  const results = await Promise.all([
    f.billing.checkout(f.user.principal, "professional"),
    f.billing.checkout(f.user.principal, "professional"),
  ]);
  assert.ok(results.every((r) => r.status === "READY"));
  assert.equal(f.gateway.customers.size, 1);
  assert.equal(f.gateway.checkouts.size, 1);
  assert.equal(
    await f.db.transaction((tx) => tx.count("billing_customers")),
    1,
  );
  await assert.rejects(f.billing.checkout(f.user.principal, "free"));
  assert.equal(f.gateway.customers.size, 1);
});
test("a failed projection commit remains retryable and successful duplicate processing is harmless", async () => {
  const f = await fixture();
  await f.billing.checkout(f.user.principal, "professional");
  f.gateway.latest = {
    customerId: "cus_test",
    subscriptions: [
      {
        id: "sub_test",
        planId: "professional",
        status: "active",
        currentPeriodEnd: "2026-10-07T12:00:00.000Z",
        cancelAtPeriodEnd: false,
      },
    ],
  };
  await f.billing.receive(f.event("evt_failure"));
  f.gateway.afterFetch = () => {
    f.db.failNextCommit = true;
  };
  await f.billing.processEvent("evt_failure");
  assert.equal(
    (await f.db.transaction((tx) => tx.get("billing_events", "evt_failure")))!
      .status,
    "PENDING",
  );
  assert.equal(await f.db.transaction((tx) => tx.count("subscriptions")), 0);
  f.gateway.afterFetch = undefined;
  await f.billing.processEvent("evt_failure");
  assert.equal(
    (await f.billing.subscription(f.user.principal)).planId,
    "professional",
  );
  await f.billing.processEvent("evt_failure");
  assert.equal(await f.db.transaction((tx) => tx.count("subscriptions")), 1);
  assert.equal(
    (await f.billing.receive(f.event("evt_failure"))).status,
    "APPLIED",
  );
});
test("unmapped early events are retained and replay successfully after customer mapping", async () => {
  const f = await fixture();
  f.gateway.latest = {
    customerId: "cus_test",
    subscriptions: [
      {
        id: "sub_test",
        planId: "professional",
        status: "active",
        currentPeriodEnd: "2026-10-07T12:00:00.000Z",
        cancelAtPeriodEnd: false,
      },
    ],
  };
  await f.billing.receive(f.event("evt_early"));
  await f.billing.processEvent("evt_early");
  assert.equal(
    (await f.db.transaction((tx) => tx.get("billing_events", "evt_early")))!
      .error,
    "CUSTOMER_UNMAPPED",
  );
  await f.billing.checkout(f.user.principal, "professional");
  await f.billing.processEvent("evt_early");
  assert.equal(
    (await f.billing.subscription(f.user.principal)).planId,
    "professional",
  );
});
test("old subscription event cannot restore canceled effective access", async () => {
  const f = await fixture();
  await f.billing.checkout(f.user.principal, "professional");
  const subscription = {
    id: "sub_test",
    planId: "professional",
    status: "canceled",
    currentPeriodEnd: "2026-10-07T12:00:00.000Z",
    cancelAtPeriodEnd: false,
  };
  f.gateway.latest = { customerId: "cus_test", subscriptions: [subscription] };
  await f.billing.receive(f.event("evt_new"));
  await f.billing.processEvent("evt_new");
  f.gateway.latest.subscriptions![0].status = "active";
  await f.billing.receive(
    f.event(
      "evt_old",
      "customer.subscription.updated",
      Math.floor(f.clock() / 1000) - 100,
    ),
  );
  await f.billing.processEvent("evt_old");
  assert.equal((await f.billing.subscription(f.user.principal)).planId, "free");
});
test("failure to paid replaces the invoice amount; currencies and refunds remain separate", async () => {
  const f = await fixture();
  await f.billing.checkout(f.user.principal, "professional");
  f.gateway.latest = {
    customerId: "cus_test",
    invoices: [
      {
        id: "in_usd",
        amountPaid: 0,
        amountDue: 1200,
        currency: "USD",
        status: "open",
      },
    ],
  };
  await f.billing.receive(f.event("evt_failed", "invoice.payment_failed"));
  await f.billing.processEvent("evt_failed");
  f.gateway.latest.invoices![0].amountPaid = 1200;
  f.gateway.latest.invoices![0].status = "paid";
  await f.billing.receive(f.event("evt_paid", "invoice.paid"));
  await f.billing.processEvent("evt_paid");
  assert.equal(
    (await f.db.transaction((tx) => tx.get("invoices", "in_usd")))!.amountPaid,
    1200,
  );
  f.gateway.latest = {
    customerId: "cus_test",
    invoices: [
      {
        id: "in_eur",
        amountPaid: 1000,
        amountDue: 1000,
        currency: "EUR",
        status: "paid",
      },
    ],
    refunds: [
      {
        id: "re_usd",
        amount: 200,
        currency: "USD",
        status: "succeeded",
        chargeId: "ch_usd",
      },
    ],
  };
  await f.billing.receive(f.event("evt_extra", "invoice.paid"));
  await f.billing.processEvent("evt_extra");
  const summary = await f.db.transaction((tx) => f.billing.summary(tx));
  assert.deepEqual(summary.currencies, [
    { currency: "EUR", grossPaid: 1000, refunded: 0, disputed: 0 },
    { currency: "USD", grossPaid: 1200, refunded: 200, disputed: 0 },
  ]);
});
test("expired processing leases are recovered instead of permanently deduplicated", async () => {
  const f = await fixture();
  await f.billing.checkout(f.user.principal, "professional");
  await f.billing.receive(f.event("evt_crash"));
  await f.db.transaction(async (tx) => {
    const event = (await tx.get("billing_events", "evt_crash"))!;
    event.status = "PROCESSING";
    event.leaseToken = "dead-worker";
    event.leaseUntil = new Date(f.clock() - 1).toISOString();
    await tx.put("billing_events", event);
  });
  await f.billing.processEvent("evt_crash");
  assert.equal(
    (await f.db.transaction((tx) => tx.get("billing_events", "evt_crash")))!
      .status,
    "APPLIED",
  );
});
test("real Stripe raw-body signatures are verified and persisted receipts omit customer PII", () => {
  const config = testConfig({
      stripeKey: "sk_test_synthetic",
      stripeWebhookSecret: "whsec_synthetic",
    }),
    gateway = new StripeGateway(config, planCatalog(config)),
    stripe = new Stripe(config.stripeKey!);
  const payload = JSON.stringify({
    id: "evt_signed",
    type: "invoice.paid",
    api_version: config.stripeApiVersion,
    livemode: false,
    created: 1800000000,
    data: {
      object: {
        id: "in_signed",
        customer: "cus_test",
        customer_email: "private@example.test",
        customer_address: { country: "DE" },
      },
    },
  });
  const signature = stripe.webhooks.generateTestHeaderString({
    payload,
    secret: config.stripeWebhookSecret!,
  });
  assert.equal(
    gateway.parseWebhook(Buffer.from(payload), signature).objectId,
    "in_signed",
  );
  assert.equal(
    JSON.stringify(
      gateway.parseWebhook(Buffer.from(payload), signature),
    ).includes("private@example.test"),
    false,
  );
  assert.throws(() =>
    gateway.parseWebhook(Buffer.from(payload + " "), signature),
  );
});
