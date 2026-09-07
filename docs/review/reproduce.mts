/** Baseline review probes. These assert observed defects, not desired behavior.
 * Run: node --import tsx docs/review/reproduce.mts
 * Uses synthetic accounts and in-memory stores only. No external requests.
 */
import assert from 'node:assert/strict';
import { buildApp } from '../../src/app.ts';
import { PrivateIdService, SignedCredentialProofProvider } from '../../src/domain.ts';
import { BillingService, MemoryBillingStore, type BillingGateway, type Plan } from '../../src/billing.ts';

const observations: { probe: string; result: string; detail: unknown }[] = [];
async function probe(name: string, run: () => Promise<unknown>) {
  try { observations.push({ probe: name, result: 'CONFIRMED', detail: await run() }); }
  catch (error) { observations.push({ probe: name, result: 'NOT_REPRODUCED', detail: String(error) }); }
}
const password = 'synthetic review password';
async function account(s: PrivateIdService, extra: Record<string, unknown> = {}) {
  return s.register({ email: `${s.users.size}@review.test`, password, ...extra });
}
function approved(s: PrivateIdService, u: Awaited<ReturnType<typeof account>>, claim = 'account_valid', client = 'relationship-network') {
  return s.decide(u, s.createProofRequest(u, client, [claim]).id, true).proof!;
}

await probe('S01 bootstrap grants administrator roles without email ownership', async () => {
  const previous = process.env.PRIVATEID_BOOTSTRAP_ADMIN_EMAILS;
  process.env.PRIVATEID_BOOTSTRAP_ADMIN_EMAILS = 'bootstrap@review.test';
  const app = await buildApp();
  try {
    const r = await app.inject({ method: 'POST', url: '/accounts', payload: { email: 'bootstrap@review.test', password } });
    const u = app.privateId.users.get(r.json().id)!;
    assert.equal(r.statusCode, 200); assert.ok(u.roles.includes('SECURITY_ADMIN')); assert.equal(u.emailVerified, true);
    return { roles: u.roles, emailVerifiedWithoutChallenge: u.emailVerified };
  } finally { await app.close(); if (previous === undefined) delete process.env.PRIVATEID_BOOTSTRAP_ADMIN_EMAILS; else process.env.PRIVATEID_BOOTSTRAP_ADMIN_EMAILS = previous; }
});
await probe('S02 suspension leaves an existing bearer session authorized', async () => {
  const app = await buildApp();
  try {
    const admin = await account(app.privateId, { roles: ['IDENTITY_ADMIN'] });
    const u = await account(app.privateId);
    const a = await app.privateId.login(admin.email, password), b = await app.privateId.login(u.email, password);
    const suspension = await app.inject({ method: 'PUT', url: `/admin/customers/${u.id}/assurance`, headers: { authorization: `Bearer ${a.accessToken}` }, payload: { identityVerified: false, uniquePerson: false, kycValid: false, investorEligible: false, accountValid: false } });
    const after = await app.inject({ method: 'GET', url: '/customers/me', headers: { authorization: `Bearer ${b.accessToken}` } });
    assert.equal(suspension.statusCode, 200); assert.equal(after.statusCode, 200);
    return { accountValid: u.accountValid, authenticatedStatus: after.statusCode };
  } finally { await app.close(); }
});
for (const action of ['access', 'delete', 'credential'] as const) await probe(`S03 approved proof survives ${action} revocation`, async () => {
  const s = new PrivateIdService(), u = await account(s), issuer = await account(s, { roles: ['ISSUER_ADMIN'] });
  const credential = s.issueCredential(issuer, u.id, { type: 'Adult', claims: { adult_verified: true } });
  const token = approved(s, u, 'adult_verified');
  if (action === 'access') s.revokeApplicationAccess(u, 'relationship-network');
  if (action === 'delete') s.deleteAccount(u);
  if (action === 'credential') s.revokeCredential(issuer, credential.id);
  const claims = s.verifyProof(token, 'relationship-network'); assert.equal(claims.adult_verified, true);
  return { verificationAfterRevocation: true };
});
await probe('S04 session listing discloses other usable bearer tokens', async () => {
  const app = await buildApp();
  try {
    const u = await account(app.privateId), a = await app.privateId.login(u.email, password), b = await app.privateId.login(u.email, password);
    const rows = (await app.inject({ method: 'GET', url: '/sessions', headers: { authorization: `Bearer ${a.accessToken}` } })).json();
    assert.ok(rows.some((r: { id: string }) => r.id === b.accessToken));
    return { listsSecondSessionBearer: true };
  } finally { await app.close(); }
});
await probe('D01 concurrent registrations bypass email uniqueness', async () => {
  const s = new PrivateIdService();
  const users = await Promise.all([s.register({ email: 'duplicate@review.test', password }), s.register({ email: 'duplicate@review.test', password })]);
  assert.equal(s.users.size, 2); assert.equal(users[0].email, users[1].email);
  return { accountsForSameEmail: s.users.size };
});
await probe('D02 a failed state save permanently poisons the save queue', async () => {
  let attempts = 0;
  const s = new PrivateIdService(undefined, { async load() { return undefined; }, async save() { attempts++; if (attempts === 1) throw new Error('synthetic write failure'); } });
  await account(s); await assert.rejects(s.flush(), /synthetic write failure/);
  await account(s); await assert.rejects(s.flush(), /synthetic write failure/);
  assert.equal(attempts, 1); assert.equal(s.users.size, 2);
  return { saveAttemptsDespiteTwoMutations: attempts, uncommittedUsersStillInMemory: s.users.size };
});
await probe('D03 mutable snapshot includes changes made after snapshot creation', async () => {
  let release!: () => void, captured: unknown;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const s = new PrivateIdService(undefined, { async load() { return undefined; }, async save(value: unknown) { await gate; captured = structuredClone(value); } });
  const u = await account(s); u.roles = ['SECURITY_ADMIN']; release(); await s.flush();
  assert.deepEqual((captured as any).users[0][1].roles, ['SECURITY_ADMIN']);
  return { unscheduledRoleMutationPersisted: true };
});
await probe('I01 claims can overwrite the signed proof expiration', async () => {
  const s = new PrivateIdService(), u = await account(s), admin = await account(s, { roles: ['IDENTITY_ADMIN'] });
  await s.registerApplication(admin, { name: 'Reserved claim test', clientId: 'reserved-test', redirectUris: ['https://review.test/callback'], allowedClaims: ['exp'], environment: 'PRODUCTION' });
  s.issueCredential(admin, u.id, { type: 'Collision', claims: { exp: 4102444800 } });
  const claims = s.verifyProof(approved(s, u, 'exp', 'reserved-test'), 'reserved-test');
  assert.equal(claims.exp, 4102444800);
  return { issuedExpiration: '2100-01-01', requiresPrivilegedIssuerAndVerifierConfiguration: true };
});
await probe('I02 earliest credential wins over a newer conflicting credential', async () => {
  const s = new PrivateIdService(), u = await account(s), admin = await account(s, { roles: ['ISSUER_ADMIN'] });
  s.issueCredential(admin, u.id, { type: 'Old', claims: { adult_verified: true }, assuranceLevel: 'low' });
  s.issueCredential(admin, u.id, { type: 'New', claims: { adult_verified: false }, assuranceLevel: 'high' });
  assert.equal(s.verifyProof(approved(s, u, 'adult_verified'), 'relationship-network').adult_verified, true);
  return { earlierLowAssuranceValueSelected: true };
});
await probe('I03 credential revocation falls back to an unexpired account boolean', async () => {
  const s = new PrivateIdService(), u = await account(s, { kycValid: true }), admin = await account(s, { roles: ['ISSUER_ADMIN'] });
  const c = s.issueCredential(admin, u.id, { type: 'KYC', claims: { kyc_valid: true } }); s.revokeCredential(admin, c.id);
  assert.equal(s.verifyProof(approved(s, u, 'kyc_valid', 'assettoken'), 'assettoken').kyc_valid, true);
  return { kycTrueAfterSourceRevocation: true };
});
await probe('I04 configured proof-provider issuer is not used when signing', async () => {
  const previous = process.env.PRIVATEID_ISSUER; delete process.env.PRIVATEID_ISSUER;
  try {
    const s = new PrivateIdService(new SignedCredentialProofProvider('synthetic-secret-with-at-least-32-characters', 'https://configured.review.test'));
    const u = await account(s); assert.throws(() => s.verifyProof(approved(s, u), 'relationship-network'), /invalid issuer/);
    return { ownProofRejectedByConfiguredProvider: true };
  } finally { if (previous !== undefined) process.env.PRIVATEID_ISSUER = previous; }
});
await probe('I05 request can still be approved after verifier suspension', async () => {
  const s = new PrivateIdService(), u = await account(s), admin = await account(s, { roles: ['VERIFIER_ADMIN'] });
  await s.registerApplication(admin, { name: 'Suspend test', clientId: 'suspend-test', redirectUris: ['https://review.test/callback'], allowedClaims: ['account_valid'], environment: 'SANDBOX' });
  const r = s.createProofRequest(u, 'suspend-test', ['account_valid']); s.applications.get('suspend-test')!.status = 'SUSPENDED';
  const token = s.decide(u, r.id, true).proof!; assert.equal(s.verifyProof(token, 'suspend-test').account_valid, true);
  return { proofIssuedAndVerifiedAfterSuspension: true, suspensionViaDomainState: true };
});
await probe('P01 free-plan proof allowance is not enforced', async () => {
  const s = new PrivateIdService(), u = await account(s);
  for (let i = 0; i < 21; i++) approved(s, u);
  assert.equal(s.requests.size, 21); return { approvedProofs: 21, documentedFreeAllowance: 20 };
});
await probe('A01 rate-limit exception is rewritten from 429 to 400', async () => {
  const app = await buildApp();
  try {
    let r; for (let i = 0; i < 101; i++) r = await app.inject({ method: 'GET', url: '/health' });
    assert.equal(r!.statusCode, 400); assert.match(r!.body, /rate limit/i);
    return { statusAtLimit: r!.statusCode };
  } finally { await app.close(); }
});
await probe('A02 missing federation body exposes a TypeError message', async () => {
  const app = await buildApp();
  try {
    const u = await account(app.privateId), login = await app.privateId.login(u.email, password);
    const r = await app.inject({ method: 'POST', url: '/federation/proof', headers: { authorization: `Bearer ${login.accessToken}` } });
    assert.equal(r.statusCode, 400); assert.match(r.json().error, /undefined/);
    return { status: r.statusCode, error: r.json().error };
  } finally { await app.close(); }
});

class Gateway implements BillingGateway {
  customers = 0;
  async createCustomer() { return `cus_review_${++this.customers}`; }
  async createCheckout() { return { id: 'cs_review', url: 'https://checkout.review.test' }; }
  async createPortal() { return { url: 'https://portal.review.test' }; }
  parseWebhook(raw: Buffer) { return JSON.parse(raw.toString()); }
}
const plan: Plan = { id: 'professional', name: 'Professional', priceMonthly: 1200, currency: 'USD', stripePriceId: 'price_review', features: [], roleLimits: { proofs: 100 } };
const evt = (id: string, status: string, extra = {}) => Buffer.from(JSON.stringify({ id, type: 'customer.subscription.updated', data: { object: { id: 'sub_review', customer: 'cus_review_1', status, metadata: { planId: 'professional' }, ...extra } } }));
await probe('B01 failed webhook is permanently acknowledged as duplicate on retry', async () => {
  class FailStore extends MemoryBillingStore { fail = true; override async saveSubscription(s: any) { if (this.fail) { this.fail = false; throw new Error('synthetic DB failure'); } await super.saveSubscription(s); } }
  const store = new FailStore(), b = new BillingService([plan], store, new Gateway(), 'https://review.test');
  await b.checkout('account', undefined, plan.id); const event = evt('evt_failure', 'active');
  await assert.rejects(b.handleWebhook(event, ''), /synthetic DB failure/);
  const retry = await b.handleWebhook(event, ''); assert.deepEqual(retry, { duplicate: true }); assert.equal(store.subscriptions.size, 0);
  return { retry, subscriptionsPersisted: 0 };
});
await probe('B02 event received before customer mapping is silently lost', async () => {
  const store = new MemoryBillingStore(), b = new BillingService([plan], store, new Gateway(), 'https://review.test'), event = evt('evt_early', 'active');
  assert.deepEqual(await b.handleWebhook(event, ''), { processed: true }); await b.checkout('account', undefined, plan.id);
  assert.deepEqual(await b.handleWebhook(event, ''), { duplicate: true }); assert.equal(store.subscriptions.size, 0);
  return { laterRetryIgnored: true };
});
await probe('B03 older subscription event overwrites a newer cancellation', async () => {
  const store = new MemoryBillingStore(), b = new BillingService([plan], store, new Gateway(), 'https://review.test');
  await b.checkout('account', undefined, plan.id); await b.handleWebhook(evt('evt_new', 'canceled'), ''); await b.handleWebhook(evt('evt_old', 'active'), '');
  assert.equal((await b.subscription('account')).status, 'active'); return { finalStatus: 'active' };
});
await probe('B04 concurrent checkouts create duplicate Stripe customers', async () => {
  const store = new MemoryBillingStore(), gateway = new Gateway(), b = new BillingService([plan], store, gateway, 'https://review.test');
  await Promise.all([b.checkout('account', undefined, plan.id), b.checkout('account', undefined, plan.id)]);
  assert.equal(gateway.customers, 2); return { providerCustomersCreated: gateway.customers, storedMappings: store.customers.size };
});
await probe('B05 current subscription-item period is silently dropped', async () => {
  const store = new MemoryBillingStore(), b = new BillingService([plan], store, new Gateway(), 'https://review.test');
  await b.checkout('account', undefined, plan.id); await b.handleWebhook(evt('evt_period', 'active', { items: { data: [{ current_period_end: 1900000000 }] } }), '');
  assert.equal((await b.subscription('account') as any).currentPeriodEnd, undefined); return { itemPeriodIgnored: true };
});
await probe('B06 subscription plan stays paid when status is canceled', async () => {
  const store = new MemoryBillingStore(), b = new BillingService([plan], store, new Gateway(), 'https://review.test');
  await b.checkout('account', undefined, plan.id); await b.handleWebhook(evt('evt_cancel', 'canceled'), '');
  const sub = await b.subscription('account'); assert.equal(sub.planId, 'professional'); assert.equal(sub.status, 'canceled');
  return { planId: sub.planId, status: sub.status, effectiveEntitlementNotCalculated: true };
});
await probe('B07 currency totals are added without currency separation', async () => {
  const store = new MemoryBillingStore(); await store.savePayment({ id: 'usd', accountId: 'a', amount: 100, currency: 'USD', status: 'paid' }); await store.savePayment({ id: 'eur', accountId: 'a', amount: 100, currency: 'EUR', status: 'paid' });
  assert.equal((await store.summary()).revenue, 200); return { mixedCurrencyRevenue: 200 };
});

console.log(JSON.stringify({ generatedAt: new Date().toISOString(), probes: observations.length, confirmed: observations.filter(x => x.result === 'CONFIRMED').length, observations }, null, 2));
if (observations.some(x => x.result !== 'CONFIRMED')) process.exitCode = 1;
