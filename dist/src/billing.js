import Stripe from 'stripe';
export class MemoryBillingStore {
    customers = new Map();
    subscriptions = new Map();
    payments = new Map();
    events = new Set();
    async getCustomer(id) { return this.customers.get(id); }
    async findCustomer(id) { return [...this.customers.values()].find(x => x.stripeCustomerId === id); }
    async saveCustomer(x) { this.customers.set(x.accountId, x); }
    async getSubscription(id) { return [...this.subscriptions.values()].find(x => x.accountId === id); }
    async saveSubscription(x) { this.subscriptions.set(x.id, x); }
    async savePayment(x) { this.payments.set(x.id, x); }
    async claimEvent(id) { if (this.events.has(id))
        return false; this.events.add(id); return true; }
    async summary() { const p = [...this.payments.values()]; return { customers: this.customers.size, activeSubscriptions: [...this.subscriptions.values()].filter(x => ['active', 'trialing'].includes(x.status)).length, revenue: p.filter(x => x.status === 'paid').reduce((n, x) => n + x.amount, 0), payments: p.length }; }
}
export class PostgresBillingStore {
    pool;
    constructor(pool) {
        this.pool = pool;
    }
    async getCustomer(id) { const r = await this.pool.query('SELECT account_id AS "accountId",stripe_customer_id AS "stripeCustomerId",email FROM billing_customers WHERE account_id=$1', [id]); return r.rows[0]; }
    async findCustomer(id) { const r = await this.pool.query('SELECT account_id AS "accountId",stripe_customer_id AS "stripeCustomerId",email FROM billing_customers WHERE stripe_customer_id=$1', [id]); return r.rows[0]; }
    async saveCustomer(x) { await this.pool.query('INSERT INTO billing_customers(account_id,stripe_customer_id,email)VALUES($1,$2,$3) ON CONFLICT(account_id)DO UPDATE SET stripe_customer_id=EXCLUDED.stripe_customer_id,email=EXCLUDED.email', [x.accountId, x.stripeCustomerId, x.email]); }
    async getSubscription(id) { const r = await this.pool.query('SELECT id,account_id AS "accountId",plan_id AS "planId",status,current_period_end AS "currentPeriodEnd",cancel_at_period_end AS "cancelAtPeriodEnd" FROM subscriptions WHERE account_id=$1 ORDER BY updated_at DESC LIMIT 1', [id]); return r.rows[0]; }
    async saveSubscription(x) { await this.pool.query('INSERT INTO subscriptions(id,account_id,plan_id,status,current_period_end,cancel_at_period_end)VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id)DO UPDATE SET plan_id=EXCLUDED.plan_id,status=EXCLUDED.status,current_period_end=EXCLUDED.current_period_end,cancel_at_period_end=EXCLUDED.cancel_at_period_end,updated_at=now()', [x.id, x.accountId, x.planId, x.status, x.currentPeriodEnd, x.cancelAtPeriodEnd]); }
    async savePayment(x) { await this.pool.query('INSERT INTO payments(id,account_id,amount,currency,status,invoice_id)VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id)DO UPDATE SET status=EXCLUDED.status', [x.id, x.accountId, x.amount, x.currency, x.status, x.invoiceId]); }
    async claimEvent(id, type) { const r = await this.pool.query('INSERT INTO stripe_events(id,type)VALUES($1,$2) ON CONFLICT DO NOTHING', [id, type]); return r.rowCount === 1; }
    async summary() { const r = await this.pool.query("SELECT (SELECT count(*)::int FROM billing_customers) customers,(SELECT count(*)::int FROM subscriptions WHERE status IN ('active','trialing')) active,(SELECT COALESCE(sum(amount),0)::bigint FROM payments WHERE status='paid') revenue,(SELECT count(*)::int FROM payments) payments"); return { customers: r.rows[0].customers, activeSubscriptions: r.rows[0].active, revenue: Number(r.rows[0].revenue), payments: r.rows[0].payments }; }
}
export class UnavailableBillingGateway {
    fail() { throw new Error('billing provider is not configured'); }
    async createCustomer() { return this.fail(); }
    async createCheckout() { return this.fail(); }
    async createPortal() { return this.fail(); }
    parseWebhook() { return this.fail(); }
}
export class StripeGateway {
    webhookSecret;
    stripe;
    constructor(key, webhookSecret) {
        this.webhookSecret = webhookSecret;
        if (!key)
            throw new Error('STRIPE_SECRET_KEY is required');
        this.stripe = new Stripe(key, { apiVersion: '2026-02-25.clover' });
    }
    async createCustomer(accountId, email) { return (await this.stripe.customers.create({ email, metadata: { accountId } })).id; }
    async createCheckout(customerId, plan, successUrl, cancelUrl) { if (!plan.stripePriceId)
        throw new Error('plan is not configured for checkout'); const s = await this.stripe.checkout.sessions.create({ mode: 'subscription', customer: customerId, line_items: [{ price: plan.stripePriceId, quantity: 1 }], success_url: successUrl, cancel_url: cancelUrl, allow_promotion_codes: true, subscription_data: { metadata: { planId: plan.id } } }); if (!s.url)
        throw new Error('checkout URL unavailable'); return { id: s.id, url: s.url }; }
    async createPortal(customerId, returnUrl) { const s = await this.stripe.billingPortal.sessions.create({ customer: customerId, return_url: returnUrl }); return { url: s.url }; }
    parseWebhook(raw, signature) { return this.stripe.webhooks.constructEvent(raw, signature, this.webhookSecret); }
}
export class BillingService {
    plans;
    store;
    gateway;
    siteUrl;
    constructor(plans, store, gateway, siteUrl) {
        this.plans = plans;
        this.store = store;
        this.gateway = gateway;
        this.siteUrl = siteUrl;
    }
    listPlans() { return this.plans.map(({ stripePriceId, ...safe }) => safe); }
    async checkout(accountId, email, planId) { const plan = this.plans.find(x => x.id === planId); if (!plan)
        throw new Error('plan not found'); let customer = await this.store.getCustomer(accountId); if (!customer) {
        customer = { accountId, email, stripeCustomerId: await this.gateway.createCustomer(accountId, email) };
        await this.store.saveCustomer(customer);
    } return this.gateway.createCheckout(customer.stripeCustomerId, plan, `${this.siteUrl}/site/?checkout=success`, `${this.siteUrl}/site/?checkout=cancelled`); }
    async portal(accountId) { const c = await this.store.getCustomer(accountId); if (!c)
        throw new Error('billing customer not found'); return this.gateway.createPortal(c.stripeCustomerId, `${this.siteUrl}/site/`); }
    async subscription(accountId) { return (await this.store.getSubscription(accountId)) ?? { status: 'free', planId: 'free' }; }
    async handleWebhook(raw, signature) { const event = this.gateway.parseWebhook(raw, signature); if (!await this.store.claimEvent(event.id, event.type))
        return { duplicate: true }; const object = event.data.object; if (event.type.startsWith('customer.subscription.')) {
        const customer = await this.store.findCustomer(String(object.customer));
        if (customer)
            await this.store.saveSubscription({ id: object.id, accountId: customer.accountId, planId: object.metadata?.planId ?? 'unknown', status: object.status, currentPeriodEnd: object.current_period_end ? new Date(object.current_period_end * 1000).toISOString() : undefined, cancelAtPeriodEnd: !!object.cancel_at_period_end });
    } if (event.type === 'invoice.paid' || event.type === 'invoice.payment_failed') {
        const customer = await this.store.findCustomer(String(object.customer));
        if (customer)
            await this.store.savePayment({ id: String(object.payment_intent ?? object.id), accountId: customer.accountId, amount: Number(object.amount_paid ?? object.amount_due ?? 0), currency: String(object.currency ?? 'usd').toUpperCase(), status: event.type === 'invoice.paid' ? 'paid' : 'failed', invoiceId: object.id });
    } return { processed: true }; }
    adminSummary() { return this.store.summary(); }
}
