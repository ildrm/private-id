import Stripe from "stripe";
import { z } from "zod";
import type { Config } from "./config.js";
import type { Plan } from "./catalog.js";
import { AppError, requireThat, unavailable } from "./errors.js";
export const receiptSchema = z
  .object({
    id: z.string(),
    type: z.string(),
    created: z.number().int(),
    objectId: z.string(),
    customerId: z.string().optional(),
    phase: z.enum(["subscriptions", "invoices", "charges"]).optional(),
    cursor: z.string().optional(),
  })
  .strict();
export type Receipt = z.infer<typeof receiptSchema>;
export type Projection = {
  next?: { phase?: Receipt["phase"]; cursor?: string };
  followups?: Receipt[];
  customerId: string;
  subscriptions?: {
    id: string;
    planId: string;
    status: string;
    currentPeriodEnd?: string;
    cancelAtPeriodEnd: boolean;
  }[];
  invoices?: {
    id: string;
    amountPaid: number;
    amountDue: number;
    currency: string;
    status: string;
  }[];
  refunds?: {
    id: string;
    amount: number;
    currency: string;
    status: string;
    chargeId: string;
  }[];
  disputes?: {
    id: string;
    amount: number;
    currency: string;
    status: string;
    chargeId: string;
  }[];
};
export interface BillingGateway {
  readonly configured: boolean;
  createCustomer(
    accountId: string,
    email: string,
    operationKey: string,
  ): Promise<string>;
  createCheckout(
    customerId: string,
    plan: Plan,
    siteUrl: string,
    operationKey: string,
    expiresAt: string,
  ): Promise<{ id: string; url: string; expiresAt: string }>;
  createPortal(customerId: string, siteUrl: string): Promise<{ url: string }>;
  parseWebhook(raw: Buffer, signature: string): Receipt;
  projection(receipt: Receipt): Promise<Projection>;
  reconcile(customerId: string, receipt?: Receipt): Promise<Projection>;
  assertCheckoutAllowed(customerId: string): Promise<void>;
  cancel(customerId: string): Promise<void>;
}
export const handledEvents = new Set([
  "customer.subscription.created",
  "customer.subscription.updated",
  "customer.subscription.deleted",
  "invoice.paid",
  "invoice.payment_failed",
  "invoice.updated",
  "invoice.voided",
  "invoice.marked_uncollectible",
  "refund.created",
  "refund.updated",
  "refund.failed",
  "charge.refunded",
  "charge.dispute.created",
  "charge.dispute.updated",
  "charge.dispute.closed",
]);
function reference(value: string | { id: string } | null | undefined) {
  requireThat(
    value,
    "BILLING_REFERENCE",
    "Provider customer or payment reference is missing",
    503,
  );
  return typeof value === "string" ? value : value.id;
}
export class StripeGateway implements BillingGateway {
  readonly configured = true;
  private stripe: Stripe;
  constructor(
    private config: Config,
    private plans: Plan[],
  ) {
    requireThat(
      config.stripeKey && config.stripeWebhookSecret,
      "BILLING_CONFIGURATION",
      "Stripe configuration is incomplete",
      503,
    );
    this.stripe = new Stripe(config.stripeKey, {
      apiVersion: "2026-07-29.dahlia",
      timeout: 20000,
      maxNetworkRetries: 2,
    });
  }
  async createCustomer(accountId: string, email: string, operationKey: string) {
    return (
      await this.stripe.customers.create(
        { email, metadata: { privateidAccountId: accountId } },
        { idempotencyKey: operationKey },
      )
    ).id;
  }
  async createCheckout(
    customerId: string,
    plan: Plan,
    siteUrl: string,
    operationKey: string,
    expiresAt: string,
  ) {
    requireThat(
      plan.stripePriceId && plan.priceMonthly > 0,
      "BILLING_CONFIGURATION",
      "Paid plan is not configured for checkout",
      503,
    );
    const price = await this.stripe.prices.retrieve(plan.stripePriceId);
    requireThat(
      price.active &&
        price.type === "recurring" &&
        price.recurring?.interval === "month" &&
        price.recurring.interval_count === 1 &&
        price.unit_amount === plan.priceMonthly &&
        price.currency.toUpperCase() === plan.currency,
      "PRICE_MISMATCH",
      "Provider price does not match the published plan",
      503,
    );
    const session = await this.stripe.checkout.sessions.create(
      {
        mode: "subscription",
        customer: customerId,
        line_items: [{ price: plan.stripePriceId, quantity: 1 }],
        success_url: `${siteUrl}/site/?checkout=success`,
        cancel_url: `${siteUrl}/site/?checkout=cancelled`,
        expires_at: Math.floor(Date.parse(expiresAt) / 1000),
        client_reference_id: operationKey,
      },
      { idempotencyKey: operationKey },
    );
    requireThat(
      session.url,
      "BILLING_PROVIDER",
      "Checkout URL is unavailable",
      503,
    );
    return {
      id: session.id,
      url: session.url,
      expiresAt: new Date(session.expires_at * 1000).toISOString(),
    };
  }
  async createPortal(customerId: string, siteUrl: string) {
    const result = await this.stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${siteUrl}/site/`,
    });
    return { url: result.url };
  }
  parseWebhook(raw: Buffer, signature: string): Receipt {
    let event: Stripe.Event;
    try {
      event = this.stripe.webhooks.constructEvent(
        raw,
        signature,
        this.config.stripeWebhookSecret!,
      );
    } catch {
      throw new AppError(
        "INVALID_WEBHOOK_SIGNATURE",
        "Webhook signature is invalid",
        400,
      );
    }
    requireThat(
      event.api_version === this.config.stripeApiVersion &&
        event.livemode === !!this.config.stripeKey?.startsWith("sk_live_"),
      "WEBHOOK_ENVIRONMENT",
      "Webhook API version or live/test mode does not match configuration",
      400,
    );
    if (!handledEvents.has(event.type))
      return {
        id: event.id,
        type: event.type,
        created: event.created,
        objectId: event.id,
      };
    const object = z
      .object({
        id: z.string(),
        customer: z.union([z.string(), z.object({ id: z.string() })]).nullish(),
      })
      .parse(event.data.object);
    return {
      id: event.id,
      type: event.type,
      created: event.created,
      objectId: object.id,
      ...(object.customer ? { customerId: reference(object.customer) } : {}),
    };
  }
  private subscription(s: Stripe.Subscription) {
    requireThat(
      s.items.data.length === 1 &&
        !s.items.has_more &&
        s.items.data[0].quantity === 1,
      "UNSUPPORTED_SUBSCRIPTION",
      "Subscription must contain exactly one owned plan item",
      503,
    );
    const item = s.items.data[0],
      plan = this.plans.find((p) => p.stripePriceId === item.price.id);
    requireThat(
      plan,
      "UNKNOWN_PROVIDER_PRICE",
      "Subscription price is not in this deployment’s plan catalog",
      503,
    );
    return {
      id: s.id,
      planId: plan.id,
      status: s.status,
      currentPeriodEnd: new Date(item.current_period_end * 1000).toISOString(),
      cancelAtPeriodEnd: s.cancel_at_period_end,
    };
  }
  private invoice(i: Stripe.Invoice) {
    return {
      id: i.id,
      amountPaid: i.amount_paid,
      amountDue: i.amount_due,
      currency: i.currency.toUpperCase(),
      status: i.status ?? "unknown",
    };
  }
  private refund(r: Stripe.Refund) {
    return {
      id: r.id,
      amount: r.amount,
      currency: r.currency.toUpperCase(),
      status: r.status ?? "unknown",
      chargeId: reference(r.charge),
    };
  }
  async projection(receipt: Receipt): Promise<Projection> {
    if (receipt.type.startsWith("customer.subscription.")) {
      const subscription = await this.stripe.subscriptions.retrieve(
        receipt.objectId,
      );
      return {
        customerId: reference(subscription.customer),
        subscriptions: [this.subscription(subscription)],
      };
    }
    if (receipt.type.startsWith("invoice.")) {
      const invoice = await this.stripe.invoices.retrieve(receipt.objectId);
      return {
        customerId: reference(invoice.customer),
        invoices: [this.invoice(invoice)],
      };
    }
    if (receipt.type.startsWith("refund.")) {
      const refund = await this.stripe.refunds.retrieve(receipt.objectId);
      const charge = await this.stripe.charges.retrieve(
        reference(refund.charge),
      );
      return {
        customerId: reference(charge.customer),
        refunds: [this.refund(refund)],
      };
    }
    if (receipt.type === "charge.refunded") {
      const charge = await this.stripe.charges.retrieve(receipt.objectId),
        refunds = await this.stripe.refunds.list({
          charge: charge.id,
          limit: 100,
          starting_after: receipt.cursor,
        });
      return {
        customerId: reference(charge.customer),
        refunds: refunds.data.map((r) => this.refund(r)),
        ...(refunds.has_more
          ? { next: { cursor: refunds.data.at(-1)!.id } }
          : {}),
      };
    }
    if (receipt.type.startsWith("charge.dispute.")) {
      const dispute = await this.stripe.disputes.retrieve(receipt.objectId),
        charge = await this.stripe.charges.retrieve(reference(dispute.charge));
      return {
        customerId: reference(charge.customer),
        disputes: [
          {
            id: dispute.id,
            amount: dispute.amount,
            currency: dispute.currency.toUpperCase(),
            status: dispute.status,
            chargeId: charge.id,
          },
        ],
      };
    }
    throw new AppError("UNSUPPORTED_EVENT", "Unsupported event type");
  }
  async reconcile(customerId: string, receipt?: Receipt): Promise<Projection> {
    const phase = receipt?.phase ?? "subscriptions",
      starting_after = receipt?.cursor;
    if (phase === "subscriptions") {
      const page = await this.stripe.subscriptions.list({
        customer: customerId,
        status: "all",
        limit: 100,
        starting_after,
      });
      return {
        customerId,
        subscriptions: page.data.map((s) => this.subscription(s)),
        next: page.has_more
          ? { phase, cursor: page.data.at(-1)!.id }
          : { phase: "invoices" },
      };
    }
    if (phase === "invoices") {
      const page = await this.stripe.invoices.list({
        customer: customerId,
        limit: 100,
        starting_after,
      });
      return {
        customerId,
        invoices: page.data.map((i) => this.invoice(i)),
        next: page.has_more
          ? { phase, cursor: page.data.at(-1)!.id }
          : { phase: "charges" },
      };
    }
    const page = await this.stripe.charges.list({
      customer: customerId,
      limit: 100,
      starting_after,
    });
    return {
      customerId,
      followups: page.data
        .filter((c) => c.refunded || c.amount_refunded > 0)
        .map((c) => ({
          id: `${receipt!.id}:refund:${c.id}`,
          type: "charge.refunded",
          objectId: c.id,
          customerId,
          created: receipt!.created,
        })),
      ...(page.has_more
        ? { next: { phase, cursor: page.data.at(-1)!.id } }
        : {}),
    };
  }
  async assertCheckoutAllowed(customerId: string) {
    for (const status of [
      "active",
      "trialing",
      "incomplete",
      "past_due",
      "unpaid",
      "paused",
    ] as const) {
      const page = await this.stripe.subscriptions.list({
        customer: customerId,
        status,
        limit: 1,
      });
      requireThat(
        !page.data.length,
        "USE_PORTAL",
        "Manage your existing subscription in the billing portal",
        409,
      );
    }
  }
  async cancel(customerId: string) {
    // Each pass is bounded. The deletion worker repeats until no open sessions remain.
    const sessions = await this.stripe.checkout.sessions.list({
      customer: customerId,
      status: "open",
      limit: 20,
    });
    for (const session of sessions.data)
      await this.stripe.checkout.sessions.expire(
        session.id,
        {},
        { idempotencyKey: `privateid-expire:${session.id}` },
      );
    if (sessions.has_more)
      throw unavailable(
        "Checkout cancellation will continue in the next batch",
      );
    for (const status of [
      "active",
      "trialing",
      "incomplete",
      "past_due",
      "unpaid",
      "paused",
    ] as const) {
      const page = await this.stripe.subscriptions.list({
        customer: customerId,
        status,
        limit: 20,
      });
      for (const subscription of page.data)
        await this.stripe.subscriptions.cancel(
          subscription.id,
          {},
          { idempotencyKey: `privateid-delete:${subscription.id}` },
        );
      if (page.has_more)
        throw unavailable(
          "Subscription cancellation will continue in the next batch",
        );
    }
    await this.stripe.customers.update(
      customerId,
      {
        email: "",
        name: "",
        phone: "",
        address: "",
        metadata: { privateidAccountId: "" },
      },
      { idempotencyKey: `privateid-erase:${customerId}` },
    );
  }
}
export class UnavailableBillingGateway implements BillingGateway {
  readonly configured = false;
  async createCustomer(): Promise<string> {
    throw unavailable("Billing is not configured");
  }
  async createCheckout(): Promise<{
    id: string;
    url: string;
    expiresAt: string;
  }> {
    throw unavailable("Billing is not configured");
  }
  async createPortal(): Promise<{ url: string }> {
    throw unavailable("Billing is not configured");
  }
  parseWebhook(): Receipt {
    throw unavailable("Billing is not configured");
  }
  async projection(): Promise<Projection> {
    throw unavailable("Billing is not configured");
  }
  async reconcile(): Promise<Projection> {
    throw unavailable("Billing is not configured");
  }
  async assertCheckoutAllowed(): Promise<void> {
    throw unavailable("Billing is not configured");
  }
  async cancel(): Promise<void> {
    throw unavailable("Billing is not configured");
  }
}
