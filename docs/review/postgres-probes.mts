/** Run only against the disposable review cluster on 127.0.0.1:55439.
 * This script creates project tables and synthetic data in that cluster.
 * Run: node --import tsx docs/review/postgres-probes.mts
 */
import assert from 'node:assert/strict';
import Stripe from 'stripe';
import { createPool, migrate } from '../../src/database.ts';
import { PostgresStateStore } from '../../src/state-store.ts';
import { PrivateIdService } from '../../src/domain.ts';
import { BillingService, PostgresBillingStore, StripeGateway } from '../../src/billing.ts';
import { buildApp } from '../../src/app.ts';

const pool = createPool('postgres://privateid_review@127.0.0.1:55439/postgres');
const results: Record<string, unknown> = {};
try {
  await migrate(pool); await migrate(pool);
  results.migrations = { applied: (await pool.query('SELECT count(*)::int AS n FROM schema_migrations')).rows[0].n, secondRunSucceeded: true };
  const store = new PostgresStateStore<any>(pool), s = new PrivateIdService(undefined, store);
  const user = await s.register({ email: 'postgres@review.test', password: 'synthetic postgres review password' });
  const login = await s.login(user.email, 'synthetic postgres review password');
  const r = s.createProofRequest(user, 'relationship-network', ['account_valid']); const proof = s.decide(user, r.id, true).proof!; await s.flush();
  const hydrated = new PrivateIdService(undefined, store); await hydrated.hydrate(); assert.equal(hydrated.authenticate(login.accessToken).id, user.id);
  results.hydration = { authenticatedAfterHydration: true };
  results.storageSplit = { normalizedUsers: (await pool.query('SELECT count(*)::int AS n FROM users')).rows[0].n, runtimeUsers: (await store.load()).users.length };
  assert.equal((results.storageSplit as any).normalizedUsers, 0);
  s.verifyProof(proof, 'relationship-network'); await s.flush(); hydrated.verifyProof(proof, 'relationship-network'); await hydrated.flush();
  results.twoInstances = { sameProofAcceptedTwice: true, deploymentDocsProhibitMultipleReplicas: true };
  const billingStore = new PostgresBillingStore(pool);
  await billingStore.saveCustomer({ accountId: user.id, stripeCustomerId: 'cus_review_pg' });
  const payment = { id: 'in_review', accountId: user.id, amount: 0, currency: 'USD', status: 'failed', invoiceId: 'in_review' };
  await billingStore.savePayment(payment); await billingStore.savePayment({ ...payment, amount: 1200, status: 'paid' });
  const stored = (await pool.query('SELECT amount,status FROM payments WHERE id=$1', [payment.id])).rows[0]; assert.equal(Number(stored.amount), 0); assert.equal(stored.status, 'paid'); results.paymentUpsert = stored;
  const key = 'sk_test_review_synthetic', secret = 'whsec_review_synthetic';
  const gateway = new StripeGateway(key, secret), billing = new BillingService([], billingStore, gateway, 'https://review.test');
  const stripe = new Stripe(key);
  const payload = JSON.stringify({ id: 'evt_pg_failure', object: 'event', type: 'customer.subscription.updated', data: { object: { id: 'sub_pg', customer: 'cus_review_pg', status: 'active', metadata: { planId: 'professional' } } } });
  const signature = stripe.webhooks.generateTestHeaderString({ payload, secret });
  const app = await buildApp(s, billing);
  try {
    const invalid = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: { 'content-type': 'application/json', 'stripe-signature': 'invalid' }, payload });
    assert.equal(invalid.statusCode, 400); results.invalidRealSignatureRejected = true;
    await pool.query('ALTER TABLE subscriptions ADD CONSTRAINT review_failure CHECK(false)');
    const failed = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: { 'content-type': 'application/json', 'stripe-signature': signature }, payload });
    await pool.query('ALTER TABLE subscriptions DROP CONSTRAINT review_failure');
    const retried = await app.inject({ method: 'POST', url: '/webhooks/stripe', headers: { 'content-type': 'application/json', 'stripe-signature': signature }, payload });
    assert.equal(failed.statusCode, 400); assert.deepEqual(retried.json(), { duplicate: true });
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM subscriptions')).rows[0].n, 0);
    results.webhookFailure = { initialDatabaseFailureStatus: failed.statusCode, retryResponse: retried.json(), subscriptionsPersisted: 0, actualStripeSignatureAndRawBodyVerified: true };
  } finally { await app.close(); }
  const other = new PrivateIdService(undefined, store); await other.hydrate();
  await s.register({ email: 'writer-a@review.test', password: 'synthetic writer a password' }); await s.flush();
  await other.register({ email: 'writer-b@review.test', password: 'synthetic writer b password' }); await other.flush();
  const final = new PrivateIdService(undefined, store); await final.hydrate();
  assert.equal([...final.users.values()].some(u => u.email === 'writer-a@review.test'), false);
  results.twoWriters = { earlierCommittedAccountLost: true, deploymentDocsProhibitMultipleReplicas: true };
  console.log(JSON.stringify(results, null, 2));
} finally { await pool.end(); }
