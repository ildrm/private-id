import { z } from "zod";

export const roles = [
  "USER",
  "ISSUER_ADMIN",
  "VERIFIER_ADMIN",
  "IDENTITY_ADMIN",
  "SECURITY_ADMIN",
] as const;
export type Role = (typeof roles)[number];
export const claimNames = [
  "adult_verified",
  "unique_person",
  "account_valid",
  "identity_verified",
  "kyc_valid",
  "jurisdiction",
  "investor_eligible",
  "authorized_company_signatory",
  "asset_owner_verified",
  "employment_verified",
  "degree_verified",
] as const;
export type ClaimName = (typeof claimNames)[number];
export const claimSchema = z.enum(claimNames);
export const assuranceSchema = z.enum(["LOW", "SUBSTANTIAL", "HIGH"]);
export const claimsSchema = z.partialRecord(
  claimSchema,
  z.union([z.boolean(), z.string().max(128)]),
);
export type Claims = Partial<Record<ClaimName, boolean | string>>;
const id = z.string().min(1).max(255);
const date = z.iso.datetime();
const base = { id, createdAt: date };
export const accountSchema = z
  .object({
    ...base,
    email: z.string().max(254),
    passwordHash: z.string(),
    emailVerified: z.boolean(),
    status: z.enum(["ACTIVE", "SUSPENDED", "DELETION_PENDING", "DELETED"]),
    roles: z.array(z.enum(roles)),
    authVersion: z.number().int().nonnegative(),
    mfaSecret: z.string().optional(),
    mfaPending: z.string().optional(),
    mfaPendingExpiresAt: date.optional(),
    mfaLastStep: z.number().int().optional(),
    recoveryHashes: z.array(z.string()),
    deletedAt: date.optional(),
  })
  .strict();
export type Account = z.infer<typeof accountSchema>;
export const sessionSchema = z
  .object({
    ...base,
    userId: id,
    tokenHash: z.string(),
    csrfHash: z.string(),
    expiresAt: date,
    authVersion: z.number().int(),
    lastSeenAt: date,
    device: z.string().max(160),
    mfaVerified: z.boolean(),
  })
  .strict();
export type Session = z.infer<typeof sessionSchema>;
export const challengeSchema = z
  .object({
    ...base,
    userId: id,
    kind: z.enum(["EMAIL", "PASSWORD"]),
    tokenHash: z.string(),
    expiresAt: date,
  })
  .strict();
export const mailSchema = z
  .object({
    ...base,
    userId: id,
    content: z.string(),
    attempts: z.number().int(),
    nextAttemptAt: date,
    status: z.enum(["PENDING", "SENT", "FAILED"]),
  })
  .strict();
export const organizationSchema = z
  .object({
    ...base,
    name: z.string().min(2).max(120),
    ownerId: id,
    status: z.enum(["ACTIVE", "SUSPENDED"]),
  })
  .strict();
export const membershipSchema = z
  .object({
    ...base,
    organizationId: id,
    userId: id,
    role: z.enum(["OWNER", "ISSUER", "VERIFIER", "MEMBER"]),
  })
  .strict();
export const issuerSchema = z
  .object({
    ...base,
    ownerId: id,
    organizationId: id.optional(),
    issuerName: z.string().min(2).max(120),
    jurisdiction: z.string().regex(/^[A-Z]{2}$/),
    supportedClaims: z.array(claimSchema).min(1).max(20),
    assuranceLevel: assuranceSchema,
    status: z.enum(["PENDING", "TRUSTED", "SUSPENDED", "REVOKED"]),
    policy: z.string().min(10).max(2000),
    version: z.number().int(),
    reviewedBy: id.optional(),
    reviewedAt: date.optional(),
    reason: z.string().max(1000).optional(),
  })
  .strict();
export type Issuer = z.infer<typeof issuerSchema>;
export const credentialSchema = z
  .object({
    ...base,
    userId: id,
    issuerId: id,
    organizationId: id.optional(),
    type: z.string().min(1).max(100),
    claims: z.record(z.string(), z.union([z.string(), z.boolean()])),
    assuranceLevel: assuranceSchema,
    evidenceReference: z.string(),
    evidencePolicy: z.string().min(1),
    issuedBy: id,
    expiresAt: date,
    status: z.enum(["ACTIVE", "REVOKED", "EXPIRED", "REDACTED"]),
    revokedAt: date.optional(),
    revocationReason: z.string().max(1000).optional(),
    redactedAt: date.optional(),
  })
  .strict();
export type Credential = z.infer<typeof credentialSchema>;
export const verifierSchema = z
  .object({
    ...base,
    ownerId: id.optional(),
    organizationId: id.optional(),
    name: z.string().min(2).max(120),
    redirectUris: z.array(z.url()).min(1).max(10),
    allowedClaims: z.array(claimSchema).min(1).max(20),
    secretHash: z.string().optional(),
    environment: z.enum(["SANDBOX", "PRODUCTION"]),
    status: z.enum(["PENDING", "ACTIVE", "SUSPENDED", "REVOKED"]),
    version: z.number().int(),
    reviewedBy: id.optional(),
    purpose: z.string().min(10).max(2000),
  })
  .strict();
export type Verifier = z.infer<typeof verifierSchema>;
export const proofRequestSchema = z
  .object({
    ...base,
    userId: id,
    clientId: id,
    clientName: z.string(),
    requestedClaims: z.array(claimSchema).min(1),
    purpose: z.string(),
    policyVersion: z.literal("1"),
    status: z.enum([
      "PENDING",
      "DENIED",
      "EXPIRED",
      "ISSUED",
      "REDEEMED",
      "REVOKED",
    ]),
    expiresAt: date,
    decidedAt: date.optional(),
    redeemedAt: date.optional(),
    clientVersion: z.number().int(),
    accountVersion: z.number().int(),
    accessVersion: z.number().int(),
    sources: z.array(
      z.object({
        credentialId: id,
        issuerId: id,
        issuerVersion: z.number().int(),
      }),
    ),
    codeHash: z.string().optional(),
    proofHash: z.string().optional(),
    jti: id.optional(),
    redirectUri: z.url().optional(),
    state: z.string().max(512).optional(),
    nonce: z.string().max(256).optional(),
    codeChallenge: z.string().optional(),
    disclosures: z
      .record(z.string(), z.union([z.string(), z.boolean()]))
      .optional(),
  })
  .strict();
export type ProofRequest = z.infer<typeof proofRequestSchema>;
export const accessSchema = z
  .object({
    ...base,
    userId: id,
    clientId: id,
    status: z.enum(["ACTIVE", "REVOKED"]),
    version: z.number().int(),
    revokedAt: date.optional(),
    lastProofAt: date,
    shared: z.array(claimSchema),
  })
  .strict();
export const auditSchema = z
  .object({
    ...base,
    event: z.string(),
    actorId: id.optional(),
    targetId: id.optional(),
    organizationId: id.optional(),
    outcome: z.enum(["SUCCESS", "FAILURE"]),
    metadata: z.record(
      z.string(),
      z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]),
    ),
  })
  .strict();
export type Audit = z.infer<typeof auditSchema>;
export const usageSchema = z
  .object({
    ...base,
    accountId: id,
    period: z.string(),
    proofs: z.number().int().nonnegative(),
  })
  .strict();
export const billingCustomerSchema = z
  .object({ ...base, accountId: id, stripeCustomerId: id })
  .strict();
export const subscriptionSchema = z
  .object({
    ...base,
    accountId: id,
    planId: z.string(),
    status: z.string(),
    currentPeriodEnd: date.optional(),
    cancelAtPeriodEnd: z.boolean(),
    providerUpdatedAt: z.number(),
    updatedAt: date,
  })
  .strict();
export type Subscription = z.infer<typeof subscriptionSchema>;
export const invoiceSchema = z
  .object({
    ...base,
    accountId: id,
    amountPaid: z.number().int().nonnegative().safe(),
    amountDue: z.number().int().nonnegative().safe(),
    currency: z.string().regex(/^[A-Z]{3}$/),
    status: z.string(),
    updatedAt: date,
    providerUpdatedAt: z.number(),
  })
  .strict();
export const refundSchema = z
  .object({
    ...base,
    accountId: id,
    amount: z.number().int().nonnegative().safe(),
    currency: z.string().regex(/^[A-Z]{3}$/),
    status: z.string(),
    chargeId: id,
  })
  .strict();
export const disputeSchema = z
  .object({
    ...base,
    accountId: id,
    amount: z.number().int().nonnegative().safe(),
    currency: z.string().regex(/^[A-Z]{3}$/),
    status: z.string(),
    chargeId: id,
  })
  .strict();
export const checkoutSchema = z
  .object({
    ...base,
    accountId: id,
    planId: z.string(),
    status: z.enum(["PENDING", "READY", "EXPIRED", "FAILED"]),
    expiresAt: date,
    url: z.url().optional(),
    providerId: id.optional(),
    operationKey: id,
    attempts: z.number().int().optional(),
    error: z.string().max(200).optional(),
    nextAttemptAt: date.optional(),
  })
  .strict();
export const eventSchema = z
  .object({
    ...base,
    type: z.string(),
    payload: z.unknown(),
    status: z.enum(["PENDING", "PROCESSING", "APPLIED", "IGNORED", "FAILED"]),
    attempts: z.number().int(),
    nextAttemptAt: date,
    leaseUntil: date.optional(),
    leaseToken: z.string().optional(),
    error: z.string().max(200).optional(),
    processedAt: date.optional(),
  })
  .strict();
export type BillingEvent = z.infer<typeof eventSchema>;
export const metadataSchema = z
  .object({ ...base, value: z.record(z.string(), z.unknown()) })
  .strict();
export const recordSchemas = {
  accounts: accountSchema,
  sessions: sessionSchema,
  challenges: challengeSchema,
  mail: mailSchema,
  organizations: organizationSchema,
  memberships: membershipSchema,
  issuers: issuerSchema,
  credentials: credentialSchema,
  verifiers: verifierSchema,
  requests: proofRequestSchema,
  access: accessSchema,
  audit: auditSchema,
  usage: usageSchema,
  billing_customers: billingCustomerSchema,
  subscriptions: subscriptionSchema,
  invoices: invoiceSchema,
  refunds: refundSchema,
  disputes: disputeSchema,
  checkouts: checkoutSchema,
  billing_events: eventSchema,
  metadata: metadataSchema,
};
export type Table = keyof typeof recordSchemas;
export type Records = { [K in Table]: z.infer<(typeof recordSchemas)[K]> };
export type PublicAccount = Pick<
  Account,
  "id" | "email" | "emailVerified" | "roles" | "status" | "createdAt"
> & { mfaEnabled: boolean };
export function publicAccount(a: Account): PublicAccount {
  return {
    id: a.id,
    email: a.email,
    emailVerified: a.emailVerified,
    roles: a.roles,
    status: a.status,
    createdAt: a.createdAt,
    mfaEnabled: !!a.mfaSecret,
  };
}
export type Page<T> = { items: T[]; nextCursor?: string };
