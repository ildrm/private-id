import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Database, Transaction, Query } from "./repository.js";
import type { Config } from "./config.js";
import { authorize, activeAccount, type Principal } from "./accounts.js";
import { effectivePlan, type Plan } from "./catalog.js";
import { audit } from "./audit.js";
import { AppError, requireThat } from "./errors.js";
import {
  receiptSchema,
  handledEvents,
  type Receipt,
  type BillingGateway,
  type Projection,
} from "./stripe-gateway.js";
const totalsSchema = z.object({
  currency: z.string(),
  grossPaid: z.number().int().safe(),
  refunded: z.number().int().safe(),
  disputed: z.number().int().safe(),
});
type Totals = z.infer<typeof totalsSchema>;
export class BillingService {
  constructor(
    public db: Database,
    public plans: Plan[],
    private gateway: BillingGateway,
    private config: Config,
    private clock = () => Date.now(),
  ) {}
  private now() {
    return new Date(this.clock()).toISOString();
  }
  listPlans() {
    return this.plans.map(({ stripePriceId, ...plan }) => ({
      ...plan,
      checkoutEnabled: this.gateway.configured && plan.priceMonthly > 0,
    }));
  }
  async subscription(principal: Principal) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock(), false);
      const result = await effectivePlan(
        tx,
        principal.accountId,
        this.plans,
        this.now(),
      );
      return {
        planId: result.plan.id,
        status: result.subscription?.status ?? "free",
        currentPeriodEnd: result.subscription?.currentPeriodEnd,
        cancelAtPeriodEnd: result.subscription?.cancelAtPeriodEnd ?? false,
        history: result.subscriptions,
      };
    });
  }
  async checkout(principal: Principal, planId: string) {
    requireThat(
      this.gateway.configured,
      "BILLING_DISABLED",
      "Billing is not configured for this deployment",
      503,
    );
    const plan = this.plans.find((p) => p.id === planId);
    requireThat(
      plan && plan.priceMonthly > 0 && plan.stripePriceId,
      "INVALID_PLAN",
      "Select a configured paid plan",
    );
    await this.db.transaction(async (tx) => {
      const user = await authorize(tx, principal, [], this.clock()),
        { subscription } = await effectivePlan(
          tx,
          user.id,
          this.plans,
          this.now(),
        );
      requireThat(
        !subscription,
        "USE_PORTAL",
        "Manage your existing subscription in the billing portal",
        409,
      );
      const old = await tx.get("checkouts", user.id);
      if (
        old &&
        ["PENDING", "READY"].includes(old.status) &&
        old.expiresAt > this.now()
      ) {
        requireThat(
          old.planId === planId,
          "CHECKOUT_PENDING",
          "Complete or wait for the existing checkout before choosing another plan",
          409,
        );
        return;
      }
      await tx.put("checkouts", {
        id: user.id,
        accountId: user.id,
        createdAt: this.now(),
        planId,
        status: "PENDING",
        expiresAt: new Date(this.clock() + 3600000).toISOString(),
        operationKey: randomUUID(),
      });
      await audit(tx, "billing.checkout_requested", user.id, user.id, {
        planId,
      });
    });
    await this.processCheckout(principal.accountId);
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock());
      const operation = (await tx.get("checkouts", principal.accountId))!;
      return operation.status === "READY"
        ? {
            status: "READY",
            url: operation.url,
            expiresAt: operation.expiresAt,
          }
        : {
            status: "PENDING",
            message: "Checkout is being prepared. Retry this request shortly.",
          };
    });
  }
  async processCheckout(accountId: string) {
    const data = await this.db.transaction(async (tx) => {
      const operation = await tx.get("checkouts", accountId);
      if (!operation || operation.status !== "PENDING") return;
      const account = await activeAccount(tx, accountId);
      if (operation.expiresAt <= this.now()) {
        operation.status = "EXPIRED";
        await tx.put("checkouts", operation);
        return;
      }
      return {
        operation,
        account,
        customer: await tx.get("billing_customers", accountId),
      };
    });
    if (!data) return;
    const customerId =
      data.customer?.stripeCustomerId ??
      (await this.gateway.createCustomer(
        accountId,
        data.account.email,
        `privateid-customer:${accountId}`,
      ));
    await this.db.transaction(async (tx) => {
      const existing = await tx.get("billing_customers", accountId);
      requireThat(
        !existing || existing.stripeCustomerId === customerId,
        "BILLING_CONFLICT",
        "Provider customer mapping changed",
        503,
      );
      if (!existing)
        await tx.insert("billing_customers", {
          id: accountId,
          accountId,
          createdAt: this.now(),
          stripeCustomerId: customerId,
        });
    });
    await this.gateway.assertCheckoutAllowed(customerId);
    const plan = this.plans.find((p) => p.id === data.operation.planId)!;
    const result = await this.gateway.createCheckout(
      customerId,
      plan,
      this.config.siteUrl,
      `privateid-checkout:${data.operation.operationKey}`,
      data.operation.expiresAt,
    );
    await this.db.transaction(async (tx) => {
      const operation = await tx.get("checkouts", accountId),
        account = await tx.get("accounts", accountId);
      requireThat(
        operation?.operationKey === data.operation.operationKey,
        "CHECKOUT_CHANGED",
        "Checkout operation changed",
        409,
      );
      if (account?.status !== "ACTIVE") return;
      operation.status = "READY";
      operation.url = result.url;
      operation.providerId = result.id;
      operation.expiresAt = result.expiresAt;
      await tx.put("checkouts", operation);
    });
  }
  async portal(principal: Principal) {
    const customer = await this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock(), false);
      return tx.get("billing_customers", principal.accountId);
    });
    requireThat(
      customer,
      "NOT_FOUND",
      "No billing customer exists for this account",
      404,
    );
    return this.gateway.createPortal(
      customer.stripeCustomerId,
      this.config.siteUrl,
    );
  }
  async handleWebhook(raw: Buffer, signature: string) {
    const receipt = this.gateway.parseWebhook(raw, signature);
    return this.receive(receipt);
  }
  async receive(receipt: Receipt) {
    const clean = receiptSchema.parse(receipt);
    return this.db.transaction(async (tx) => {
      const old = await tx.get("billing_events", clean.id);
      if (old) return { received: true, duplicate: true, status: old.status };
      const supported =
        handledEvents.has(clean.type) || clean.type === "privateid.reconcile";
      await tx.insert("billing_events", {
        id: clean.id,
        createdAt: this.now(),
        type: clean.type,
        payload: clean,
        status: supported ? "PENDING" : "IGNORED",
        attempts: 0,
        nextAttemptAt: this.now(),
      });
      return { received: true, status: supported ? "PENDING" : "IGNORED" };
    });
  }
  private async addTotals(
    tx: Transaction,
    currency: string,
    delta: Partial<Omit<Totals, "currency">>,
  ) {
    const id = `billing-totals:${currency}`,
      old = await tx.get("metadata", id),
      totals = old
        ? totalsSchema.parse(old.value)
        : { currency, grossPaid: 0, refunded: 0, disputed: 0 };
    for (const key of ["grossPaid", "refunded", "disputed"] as const)
      totals[key] += delta[key] ?? 0;
    totalsSchema.parse(totals);
    await tx.put("metadata", {
      id,
      createdAt: old?.createdAt ?? this.now(),
      value: { ...totals, kind: "BILLING_TOTALS" },
    });
  }
  private async apply(
    tx: Transaction,
    projection: Projection,
    version: number,
  ) {
    const customer = (
      await tx.list("billing_customers", {
        where: { stripeCustomerId: projection.customerId },
        limit: 1,
      })
    )[0];
    requireThat(
      customer,
      "CUSTOMER_UNMAPPED",
      "Provider customer has not been mapped yet",
      503,
    );
    const accountId = customer.accountId,
      now = this.now();
    for (const subscription of projection.subscriptions ?? []) {
      const old = await tx.get("subscriptions", subscription.id);
      requireThat(
        !old || old.accountId === accountId,
        "BILLING_CONFLICT",
        "Subscription owner changed",
        503,
      );
      if (old && old.providerUpdatedAt > version) continue;
      await tx.put("subscriptions", {
        ...subscription,
        accountId,
        createdAt: old?.createdAt ?? now,
        updatedAt: now,
        providerUpdatedAt: version,
      });
    }
    for (const invoice of projection.invoices ?? []) {
      const old = await tx.get("invoices", invoice.id);
      requireThat(
        !old || old.accountId === accountId,
        "BILLING_CONFLICT",
        "Invoice owner changed",
        503,
      );
      if (old && old.providerUpdatedAt > version) continue;
      if (old)
        await this.addTotals(tx, old.currency, { grossPaid: -old.amountPaid });
      await this.addTotals(tx, invoice.currency, {
        grossPaid: invoice.amountPaid,
      });
      await tx.put("invoices", {
        ...invoice,
        accountId,
        createdAt: old?.createdAt ?? now,
        updatedAt: now,
        providerUpdatedAt: version,
      });
    }
    for (const refund of projection.refunds ?? []) {
      const old = await tx.get("refunds", refund.id);
      requireThat(
        !old || old.accountId === accountId,
        "BILLING_CONFLICT",
        "Refund owner changed",
        503,
      );
      if (old?.status === "succeeded")
        await this.addTotals(tx, old.currency, { refunded: -old.amount });
      if (refund.status === "succeeded")
        await this.addTotals(tx, refund.currency, { refunded: refund.amount });
      await tx.put("refunds", {
        ...refund,
        accountId,
        createdAt: old?.createdAt ?? now,
      });
    }
    for (const dispute of projection.disputes ?? []) {
      const old = await tx.get("disputes", dispute.id),
        atRisk = (status: string) =>
          !["won", "prevented", "warning_closed"].includes(status);
      requireThat(
        !old || old.accountId === accountId,
        "BILLING_CONFLICT",
        "Dispute owner changed",
        503,
      );
      if (old && atRisk(old.status))
        await this.addTotals(tx, old.currency, { disputed: -old.amount });
      if (atRisk(dispute.status))
        await this.addTotals(tx, dispute.currency, {
          disputed: dispute.amount,
        });
      await tx.put("disputes", {
        ...dispute,
        accountId,
        createdAt: old?.createdAt ?? now,
      });
    }
    return accountId;
  }
  async processEvent(id: string) {
    const claimed = await this.db.transaction(async (tx) => {
      const event = await tx.get("billing_events", id);
      if (
        !event ||
        ["APPLIED", "IGNORED", "FAILED"].includes(event.status) ||
        (event.status === "PROCESSING" && (event.leaseUntil ?? "") > this.now())
      )
        return;
      const receipt = receiptSchema.parse(event.payload),
        lockId = `billing-sync:${receipt.customerId ?? receipt.objectId}`,
        lock = await tx.get("metadata", lockId);
      if (lock && String(lock.value.leaseUntil) > this.now()) return;
      const leaseToken = randomUUID(),
        leaseUntil = new Date(this.clock() + 180000).toISOString();
      event.status = "PROCESSING";
      event.attempts++;
      event.leaseToken = leaseToken;
      event.leaseUntil = leaseUntil;
      await tx.put("billing_events", event);
      await tx.put("metadata", {
        id: lockId,
        createdAt: this.now(),
        value: { leaseToken, leaseUntil },
      });
      return { event, receipt, lockId, leaseToken };
    });
    if (!claimed) return;
    try {
      const projection =
        claimed.receipt.type === "privateid.reconcile"
          ? await this.gateway.reconcile(
              claimed.receipt.objectId,
              claimed.receipt,
            )
          : await this.gateway.projection(claimed.receipt);
      if (!claimed.receipt.customerId) {
        // Resolve customer scope first, then refetch under its shared lease.
        // Refund/charge events for the same customer must not race projections.
        await this.db.transaction(async (tx) => {
          const current = await tx.get("billing_events", id),
            lock = await tx.get("metadata", claimed.lockId);
          requireThat(
            current?.leaseToken === claimed.leaseToken &&
              lock?.value.leaseToken === claimed.leaseToken,
            "STALE_WORKER",
            "Billing lease changed",
            503,
          );
          current.payload = {
            ...claimed.receipt,
            customerId: projection.customerId,
          };
          current.status = "PENDING";
          current.attempts--;
          current.nextAttemptAt = this.now();
          delete current.leaseToken;
          delete current.leaseUntil;
          await tx.put("billing_events", current);
          await tx.delete("metadata", claimed.lockId);
        });
        await this.processEvent(id);
        return;
      }
      requireThat(
        claimed.receipt.customerId === projection.customerId,
        "BILLING_CONFLICT",
        "Provider event customer changed",
        503,
      );
      await this.db.transaction(async (tx) => {
        const current = await tx.get("billing_events", id),
          lock = await tx.get("metadata", claimed.lockId);
        requireThat(
          current?.leaseToken === claimed.leaseToken &&
            lock?.value.leaseToken === claimed.leaseToken,
          "STALE_WORKER",
          "Billing worker lease changed",
          503,
        );
        const accountId = await this.apply(
          tx,
          projection,
          claimed.receipt.created,
        );
        for (const receipt of [
          ...(projection.followups ?? []),
          ...(projection.next
            ? [
                {
                  ...claimed.receipt,
                  ...projection.next,
                  cursor: projection.next.cursor,
                  id: `page:${claimed.receipt.created}:${claimed.receipt.objectId}:${projection.next.phase ?? claimed.receipt.type}:${projection.next.cursor ?? "first"}`,
                },
              ]
            : []),
        ]) {
          if (!(await tx.get("billing_events", receipt.id)))
            await tx.insert("billing_events", {
              id: receipt.id,
              createdAt: this.now(),
              type: receipt.type,
              payload: receipt,
              status: "PENDING",
              attempts: 0,
              nextAttemptAt: this.now(),
            });
        }
        current.status = "APPLIED";
        current.processedAt = this.now();
        delete current.error;
        delete current.leaseToken;
        delete current.leaseUntil;
        await tx.put("billing_events", current);
        await tx.delete("metadata", claimed.lockId);
        await audit(tx, "billing.event_applied", undefined, accountId, {
          eventId: id,
          type: current.type,
        });
      });
    } catch (error) {
      await this.db.transaction(async (tx) => {
        const current = await tx.get("billing_events", id);
        if (!current || current.leaseToken !== claimed.leaseToken) return;
        current.status = current.attempts >= 8 ? "FAILED" : "PENDING";
        current.error =
          error instanceof AppError
            ? error.code
            : "PROVIDER_OR_DATABASE_FAILURE";
        current.nextAttemptAt = new Date(
          this.clock() + Math.min(3600000, 5000 * 2 ** current.attempts),
        ).toISOString();
        delete current.leaseUntil;
        delete current.leaseToken;
        await tx.put("billing_events", current);
        const lock = await tx.get("metadata", claimed.lockId);
        if (lock?.value.leaseToken === claimed.leaseToken)
          await tx.delete("metadata", claimed.lockId);
      });
    }
  }
  async processDue() {
    const now = this.now(),
      ids = await this.db.transaction(async (tx) =>
        [
          ...(await tx.list("billing_events", {
            where: { status: "PENDING" },
            before: { field: "nextAttemptAt", value: now },
            limit: 20,
          })),
          ...(await tx.list("billing_events", {
            where: { status: "PROCESSING" },
            before: { field: "leaseUntil", value: now },
            limit: 20,
          })),
        ].map((e) => e.id),
      );
    for (const id of ids) await this.processEvent(id);
    const checkouts = await this.db.transaction((tx) =>
      tx.list("checkouts", { where: { status: "PENDING" }, limit: 20 }),
    );
    for (const checkout of checkouts) {
      if (checkout.nextAttemptAt && checkout.nextAttemptAt > now) continue;
      try {
        await this.processCheckout(checkout.accountId);
      } catch (error) {
        await this.db.transaction(async (tx) => {
          const current = await tx.get("checkouts", checkout.id);
          if (!current || current.operationKey !== checkout.operationKey)
            return;
          current.attempts = (current.attempts ?? 0) + 1;
          current.error =
            error instanceof AppError ? error.code : "PROVIDER_FAILURE";
          current.nextAttemptAt = new Date(
            this.clock() + Math.min(3600000, 5000 * 2 ** current.attempts),
          ).toISOString();
          if (
            current.expiresAt <= this.now() ||
            current.attempts >= 8 ||
            current.error === "USE_PORTAL"
          )
            current.status = "FAILED";
          await tx.put("checkouts", current);
        });
      }
    }
  }
  async reconcile(principal: Principal) {
    const customer = await this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock(), false);
      return tx.get("billing_customers", principal.accountId);
    });
    requireThat(customer, "NOT_FOUND", "No billing customer exists", 404);
    const receipt = {
      id: `reconcile:${customer.stripeCustomerId}:${this.now().slice(0, 16)}`,
      type: "privateid.reconcile",
      objectId: customer.stripeCustomerId,
      customerId: customer.stripeCustomerId,
      created: Math.floor(this.clock() / 1000),
    };
    await this.receive(receipt);
    await this.processEvent(receipt.id);
    const applied = await this.db.transaction((tx) =>
      tx.get("billing_events", receipt.id),
    );
    requireThat(
      applied?.status === "APPLIED",
      "RECONCILIATION_PENDING",
      "Provider synchronization is queued; retry shortly",
      503,
    );
    return this.subscription(principal);
  }
  async scheduleReconciliation() {
    if (!this.gateway.configured) return;
    await this.db.transaction(async (tx) => {
      const id = "billing-reconcile-cursor",
        state = await tx.get("metadata", id);
      if (state && String(state.value.nextAt) > this.now()) return;
      const customers = await tx.list("billing_customers", {
        limit: 10,
        cursor: state?.value.cursor as string | undefined,
      });
      for (const customer of customers) {
        const eventId = `scheduled:${customer.id}:${this.now().slice(0, 13)}`;
        if (!(await tx.get("billing_events", eventId))) {
          const receipt = {
            id: eventId,
            type: "privateid.reconcile",
            objectId: customer.stripeCustomerId,
            customerId: customer.stripeCustomerId,
            created: Math.floor(this.clock() / 1000),
          };
          await tx.insert("billing_events", {
            id: eventId,
            type: receipt.type,
            payload: receipt,
            createdAt: this.now(),
            status: "PENDING",
            attempts: 0,
            nextAttemptAt: this.now(),
          });
        }
      }
      await tx.put("metadata", {
        id,
        createdAt: this.now(),
        value: {
          cursor: customers.length === 10 ? customers.at(-1)!.id : undefined,
          nextAt: new Date(
            this.clock() + (customers.length === 10 ? 1000 : 3600000),
          ).toISOString(),
        },
      });
    });
  }
  async invoices(principal: Principal, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, [], this.clock(), false);
      return tx.list("invoices", {
        ...query,
        where: { accountId: principal.accountId },
      });
    });
  }
  async events(principal: Principal, query: Query = {}) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, ["SECURITY_ADMIN"], this.clock());
      return (await tx.list("billing_events", query)).map(
        ({ payload, leaseToken, ...event }) => event,
      );
    });
  }
  async retry(principal: Principal, id: string) {
    return this.db.transaction(async (tx) => {
      await authorize(tx, principal, ["SECURITY_ADMIN"], this.clock());
      const event = await tx.get("billing_events", id);
      requireThat(
        event && ["FAILED", "PENDING"].includes(event.status),
        "INVALID_EVENT",
        "Only pending or failed events can be retried",
      );
      event.status = "PENDING";
      event.attempts = 0;
      event.nextAttemptAt = this.now();
      delete event.error;
      await tx.put("billing_events", event);
      await audit(tx, "billing.event_retried", principal.accountId, id);
      return { queued: true };
    });
  }
  async summary(tx: Transaction) {
    const currencies: Totals[] = [];
    for (const value of await tx.list("metadata", {
      where: { "value.kind": "BILLING_TOTALS" },
      limit: 1000,
    }))
      if (value.id.startsWith("billing-totals:"))
        currencies.push(totalsSchema.parse(value.value));
    return {
      customers: await tx.count("billing_customers"),
      subscriptions: await tx.count("subscriptions"),
      invoices: await tx.count("invoices"),
      pendingEvents: await tx.count("billing_events", { status: "PENDING" }),
      failedEvents: await tx.count("billing_events", { status: "FAILED" }),
      currencies,
      definition:
        "Gross invoice payments, successful refunds, and disputed amounts are separate totals in integer currency minor units. These are not recognized revenue.",
    };
  }
  async cancelForDeletion(accountId: string) {
    await this.db.transaction(async (tx) => {
      const operation = await tx.get("checkouts", accountId);
      if (operation) {
        operation.status = "EXPIRED";
        delete operation.url;
        await tx.put("checkouts", operation);
      }
    });
    const customer = await this.db.transaction((tx) =>
      tx.get("billing_customers", accountId),
    );
    if (customer) await this.gateway.cancel(customer.stripeCustomerId);
  }
}
