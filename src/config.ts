import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { AppError } from "./errors.js";

export type Config = {
  mode: "development" | "test" | "production";
  host: string;
  port: number;
  siteUrl: string;
  issuer: string;
  allowedOrigins: string[];
  encryptionKey: string;
  subjectSecret: string;
  signingSecret: string;
  signingPrivateKey?: string;
  signingPublicKeys: Record<string, string>;
  signingKeyId: string;
  databaseUrl?: string;
  databaseSsl: boolean;
  poolSize: number;
  trustProxy: string[];
  logLevel: string;
  smtpUrl?: string;
  mailFrom: string;
  mailDirectory: string;
  stripeKey?: string;
  stripeWebhookSecret?: string;
  stripePrices: { professional?: string; business?: string };
  stripeApiVersion: string;
  sessionHours: number;
  proofSeconds: number;
  retentionDays: number;
  auditRetentionDays: number;
  enableBilling: boolean;
};
const devKey = Buffer.alloc(32, 17).toString("base64");
export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    mode: "test",
    host: "127.0.0.1",
    port: 3001,
    siteUrl: "http://localhost:3001",
    issuer: "https://privateid.test",
    allowedOrigins: [
      "http://localhost:3001",
      "http://localhost:3101",
      "http://127.0.0.1:3101",
    ],
    encryptionKey: devKey,
    subjectSecret: "test-subject-secret-32-characters-minimum",
    signingSecret: "test-signing-secret-32-characters-minimum",
    signingPublicKeys: {},
    signingKeyId: "test-v1",
    databaseSsl: false,
    poolSize: 10,
    trustProxy: [],
    logLevel: "silent",
    mailFrom: "PrivateID <noreply@privateid.test>",
    mailDirectory: "/tmp/privateid-mail-test",
    stripePrices: {},
    stripeApiVersion: "2026-07-29.dahlia",
    sessionHours: 1,
    proofSeconds: 300,
    retentionDays: 730,
    auditRetentionDays: 365,
    enableBilling: false,
    ...overrides,
  };
}
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const mode = z
      .enum(["development", "test", "production"])
      .parse(env.NODE_ENV ?? "development"),
    production = mode === "production";
  const integer = (value: string | undefined, fallback: number, max: number) =>
    z.coerce
      .number()
      .int()
      .min(1)
      .max(max)
      .parse(value ?? fallback);
  const url = (value: string, https = production) => {
    const u = new URL(value);
    if (
      u.username ||
      u.password ||
      (https && u.protocol !== "https:") ||
      !["http:", "https:"].includes(u.protocol)
    )
      throw new AppError("CONFIGURATION", "Expected a valid HTTPS URL");
    return u.origin;
  };
  const siteUrl = url(env.SITE_URL ?? "http://localhost:3001");
  const signingPrivateKey = env.PRIVATEID_SIGNING_KEY_FILE
    ? readFileSync(env.PRIVATEID_SIGNING_KEY_FILE, "utf8")
    : undefined;
  const publicKeys = env.PRIVATEID_PUBLIC_KEYS_FILE
    ? z
        .record(z.string(), z.string())
        .parse(JSON.parse(readFileSync(env.PRIVATEID_PUBLIC_KEYS_FILE, "utf8")))
    : {};
  const config: Config = {
    ...testConfig(),
    mode,
    host: env.HOST ?? "127.0.0.1",
    port: integer(env.PORT, 3001, 65535),
    siteUrl,
    issuer: url(env.PRIVATEID_ISSUER ?? siteUrl),
    allowedOrigins: [
      ...new Set([
        siteUrl,
        ...(
          env.ALLOWED_ORIGINS ??
          (production ? "" : "http://localhost:3101,http://127.0.0.1:3101")
        )
          .split(",")
          .filter(Boolean)
          .map((x) => url(x.trim())),
      ]),
    ],
    encryptionKey: env.DATA_ENCRYPTION_KEY ?? devKey,
    subjectSecret:
      env.PRIVATEID_SUBJECT_SECRET ??
      "development-subject-secret-change-me-0001",
    signingSecret:
      env.PRIVATEID_PROOF_SECRET ?? randomBytes(32).toString("hex"),
    signingPrivateKey,
    signingPublicKeys: publicKeys,
    signingKeyId: env.PRIVATEID_SIGNING_KEY_ID ?? "local-v1",
    databaseUrl: env.DATABASE_URL,
    databaseSsl: env.DATABASE_SSL === "true",
    poolSize: integer(env.DATABASE_POOL_SIZE, 10, 100),
    trustProxy: (env.TRUSTED_PROXIES ?? "").split(",").filter(Boolean),
    logLevel: env.LOG_LEVEL ?? "info",
    smtpUrl: env.SMTP_URL,
    mailFrom: env.MAIL_FROM ?? "PrivateID <noreply@localhost>",
    mailDirectory: env.MAIL_DIRECTORY ?? ".data/mail",
    stripeKey: env.STRIPE_SECRET_KEY,
    stripeWebhookSecret: env.STRIPE_WEBHOOK_SECRET,
    stripePrices: {
      professional: env.STRIPE_PRICE_PROFESSIONAL,
      business: env.STRIPE_PRICE_BUSINESS,
    },
    enableBilling: env.BILLING_ENABLED === "true",
    stripeApiVersion: "2026-07-29.dahlia",
    sessionHours: integer(env.SESSION_HOURS, 1, 24),
    proofSeconds: integer(env.PROOF_SECONDS, 300, 300),
    retentionDays: integer(env.CONSENT_RETENTION_DAYS, 730, 3650),
    auditRetentionDays: integer(env.AUDIT_RETENTION_DAYS, 365, 3650),
  };
  if (
    Buffer.from(config.encryptionKey, "base64").length !== 32 ||
    config.subjectSecret.length < 32
  )
    throw new AppError(
      "CONFIGURATION",
      "DATA_ENCRYPTION_KEY must encode 32 bytes and PRIVATEID_SUBJECT_SECRET must have at least 32 characters",
    );
  if (env.PRIVATEID_BOOTSTRAP_ADMIN_EMAILS)
    throw new AppError(
      "CONFIGURATION",
      "Email-based administrator bootstrap was removed. Use the admin enrollment CLI.",
    );
  if (
    production &&
    (!config.databaseUrl ||
      !config.databaseSsl ||
      !config.smtpUrl ||
      !signingPrivateKey ||
      !env.PRIVATEID_SIGNING_KEY_ID ||
      !env.PRIVATEID_SUBJECT_SECRET ||
      /^(development|local-|test-)/.test(config.subjectSecret) ||
      config.encryptionKey === devKey ||
      !env.MAIL_FROM)
  )
    throw new AppError(
      "CONFIGURATION",
      "Production requires PostgreSQL TLS, SMTP, a mounted Ed25519 signing key, a key ID, and dedicated encryption/subject secrets.",
    );
  if (
    config.enableBilling &&
    (!config.stripeKey ||
      !config.stripeWebhookSecret ||
      !config.stripePrices.professional ||
      !config.stripePrices.business)
  )
    throw new AppError(
      "CONFIGURATION",
      "Enabled billing requires the Stripe key, webhook secret, and both plan prices.",
    );
  if (config.smtpUrl) {
    const smtp = new URL(config.smtpUrl);
    if (
      !["smtp:", "smtps:"].includes(smtp.protocol) ||
      (production &&
        smtp.protocol !== "smtps:" &&
        smtp.searchParams.get("requireTLS") !== "true")
    )
      throw new AppError(
        "CONFIGURATION",
        "SMTP requires smtps:// or smtp:// with ?requireTLS=true in production",
      );
  }
  return config;
}
