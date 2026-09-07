import Fastify, {
  type FastifyRequest,
  type FastifyReply,
  type HTTPMethods,
} from "fastify";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import rateLimit from "@fastify/rate-limit";
import rawBody from "fastify-raw-body";
import { z } from "zod";
import { Metrics } from "./metrics.js";
import type { Services } from "./services.js";
import {
  authorize,
  registrationSchema,
  passwordSchema,
  type Principal,
} from "./accounts.js";
import { issuerInput, credentialInput } from "./credentials.js";
import { verifierInput } from "./verifiers.js";
import { requestInput } from "./proofs.js";
import { AppError, requireThat } from "./errors.js";
import { digest, equal, canonicalEmail } from "./security.js";
import { audit } from "./audit.js";
import {
  accountSchema,
  publicAccount,
  roles,
  claimNames,
  credentialSchema,
  issuerSchema,
  verifierSchema,
  proofRequestSchema,
  accessSchema,
  auditSchema,
  subscriptionSchema,
  invoiceSchema,
  eventSchema,
  organizationSchema,
} from "./models.js";

declare module "fastify" {
  interface FastifyRequest {
    principal?: Principal;
    signedInUser?: ReturnType<typeof publicAccount>;
  }
}
const empty = z.object({}).strict(),
  reason = z.string().min(10).max(1000),
  code = z.string().min(6).max(100).optional();
const pagination = z
  .object({
    organizationId: z.string().max(255).optional(),
    cursor: z.string().max(255).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
  })
  .strict();
const userSchema = accountSchema
  .pick({
    id: true,
    email: true,
    emailVerified: true,
    roles: true,
    status: true,
    createdAt: true,
  })
  .extend({ mfaEnabled: z.boolean() });
const credentialDto = credentialSchema
  .omit({ evidenceReference: true })
  .extend({ evidenceRecorded: z.boolean() });
const verifierDto = verifierSchema
  .omit({ secretHash: true })
  .extend({ confidential: z.boolean() });
const requestDto = proofRequestSchema.omit({
  codeHash: true,
  proofHash: true,
  disclosures: true,
  sources: true,
});
const planDto = z.object({
  id: z.enum(["free", "professional", "business"]),
  name: z.string(),
  priceMonthly: z.number().int(),
  currency: z.string(),
  features: z.array(z.string()),
  limits: z.object({
    proofs: z.number(),
    credentials: z.number(),
    connections: z.number(),
    teamMembers: z.number(),
  }),
  checkoutEnabled: z.boolean().optional(),
});
const subscriptionDto = z.object({
  planId: z.string(),
  status: z.string(),
  currentPeriodEnd: z.string().optional(),
  cancelAtPeriodEnd: z.boolean(),
  history: z.array(subscriptionSchema),
});
const pageOf = <T extends z.ZodType>(item: T) =>
  z.object({ items: z.array(item), nextCursor: z.string().optional() });
const page = <T extends { id: string }>(items: T[], limit: number) => ({
  items,
  ...(items.length === limit ? { nextCursor: items.at(-1)!.id } : {}),
});
const id = (req: FastifyRequest, name = "id") =>
  z
    .string()
    .min(1)
    .max(255)
    .parse((req.params as Record<string, string>)[name]);
const principal = (req: FastifyRequest) => {
  requireThat(req.principal, "UNAUTHORIZED", "Sign in to continue", 401);
  return req.principal;
};
const errorDto = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    requestId: z.string(),
    fields: z.array(z.string()).optional(),
  }),
});

export async function buildApp(s: Services) {
  const { config } = s,
    metrics = new Metrics();
  const app = Fastify({
    logger:
      config.logLevel === "silent"
        ? false
        : {
            level: config.logLevel,
            redact: [
              "req.headers.authorization",
              "req.headers.cookie",
              'res.headers["set-cookie"]',
            ],
            serializers: {
              req: (req) => ({
                method: req.method,
                url: String(req.url).split("?")[0],
              }),
              err: (err) => ({
                type: err.name,
                message: "Request failed",
                stack: "",
                code: err.code,
              }),
            },
          },
    requestIdHeader: false,
    trustProxy: config.trustProxy.length ? config.trustProxy : false,
    bodyLimit: 65536,
    requestTimeout: 30000,
    connectionTimeout: 10000,
  });
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: config.mode === "production" ? [] : null,
      },
    },
    referrerPolicy: { policy: "no-referrer" },
  });
  await app.register(cors, {
    origin: config.allowedOrigins,
    credentials: true,
    allowedHeaders: ["content-type", "authorization", "x-csrf-token"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  });
  await app.register(cookie);
  await app.register(rateLimit, {
    max: 120,
    timeWindow: "1 minute",
    allowList: (req) => ["/health", "/ready"].includes(req.url),
    errorResponseBuilder: (req) => ({
      error: {
        code: "RATE_LIMITED",
        message: "Too many requests. Try again shortly.",
        requestId: req.id,
      },
    }),
  });
  await app.register(rawBody, {
    global: false,
    encoding: false,
    runFirst: true,
  });
  app.addHook("onSend", async (req, reply) => {
    if (!req.url.startsWith("/site/assets/"))
      reply.header("Cache-Control", "no-store");
    reply.header("X-Request-Id", req.id);
  });
  app.setErrorHandler(async (error, req, reply) => {
    const httpError = error as { validation?: unknown; statusCode?: number };
    const known = error instanceof AppError,
      validation = error instanceof z.ZodError || !!httpError.validation;
    const status = known
      ? error.status
      : validation
        ? 400
        : httpError.statusCode &&
            httpError.statusCode >= 400 &&
            httpError.statusCode < 500
          ? httpError.statusCode
          : 500;
    const errorCode = known
      ? error.code
      : validation
        ? "INVALID_INPUT"
        : status === 429
          ? "RATE_LIMITED"
          : status === 413
            ? "PAYLOAD_TOO_LARGE"
            : status >= 500
              ? "INTERNAL_ERROR"
              : "BAD_REQUEST";
    if (status >= 500)
      req.log.error({
        event: "request.failed",
        code: errorCode,
        requestId: req.id,
        route: req.routeOptions.url,
      });
    if (
      [401, 403, 409, 422].includes(status) &&
      req.routeOptions.url &&
      req.routeOptions.url !== "/api/auth/me"
    )
      await s.db
        .transaction((tx) =>
          audit(
            tx,
            "request.rejected",
            req.principal?.accountId,
            undefined,
            {
              route: req.routeOptions.url!,
              code: errorCode,
              requestId: req.id,
            },
            undefined,
            "FAILURE",
          ),
        )
        .catch(() => req.log.error({ event: "audit.rejection_failed" }));
    if (status === 429) reply.header("Retry-After", "60");
    return reply.code(status).send({
      error: {
        code: errorCode,
        message: known
          ? error.message
          : validation
            ? "Check the submitted fields"
            : status >= 500
              ? "The request could not be completed. Retry or contact the operator with the request ID."
              : "Request rejected",
        requestId: req.id,
        ...(error instanceof z.ZodError
          ? { fields: error.issues.map((issue) => issue.path.join(".")) }
          : {}),
      },
    });
  });
  const authenticate = async (req: FastifyRequest) => {
    const bearer = req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.slice(7)
      : undefined;
    const session = await s.accounts.authenticate(
      bearer ?? req.cookies.pid_session ?? "",
    );
    req.principal = session.principal;
    req.signedInUser = session.account;
    if (!bearer && !["GET", "HEAD", "OPTIONS"].includes(req.method))
      requireThat(
        typeof req.headers["x-csrf-token"] === "string" &&
          equal(digest(req.headers["x-csrf-token"]), session.session.csrfHash),
        "CSRF_REJECTED",
        "Refresh the page and submit the form again",
        403,
      );
  };
  app.addHook("onRequest", async (req) => {
    if (
      req.url.startsWith("/api/") &&
      !["GET", "HEAD", "OPTIONS"].includes(req.method) &&
      !req.url.startsWith("/api/webhooks/stripe")
    ) {
      requireThat(
        !req.headers.origin ||
          config.allowedOrigins.includes(req.headers.origin),
        "ORIGIN_REJECTED",
        "Request origin is not allowed",
        403,
      );
      requireThat(
        req.headers["sec-fetch-site"] !== "cross-site",
        "ORIGIN_REJECTED",
        "Cross-site requests are not allowed",
        403,
      );
    }
  });
  app.addHook("onResponse", async (req, reply) =>
    metrics.observe(
      req.routeOptions.url ?? "not-found",
      reply.statusCode,
      reply.elapsedTime,
    ),
  );
  const paths: Record<string, Record<string, unknown>> = {};
  const json = (schema: z.ZodType, io: "input" | "output" = "output") => {
    const { $schema, ...value } = z.toJSONSchema(schema, {
      target: "draft-7",
      io,
      unrepresentable: "any",
    });
    return value;
  };
  function route<B extends z.ZodType, R extends z.ZodType>(
    method: HTTPMethods,
    path: string,
    summary: string,
    body: B,
    response: R,
    handler: (
      req: FastifyRequest,
      body: z.output<B>,
      reply: FastifyReply,
    ) => Promise<unknown> | unknown,
    auth = true,
    paginated = false,
  ) {
    const parameters: unknown[] = [...path.matchAll(/:([A-Za-z]+)/g)].map(
      (m) => ({
        name: m[1],
        in: "path",
        required: true,
        schema: { type: "string", maxLength: 255 },
      }),
    );
    if (paginated)
      parameters.push(
        {
          name: "organizationId",
          in: "query",
          schema: { type: "string", maxLength: 255 },
          description:
            "Issuer/verifier workspace lists only; requires membership.",
        },
        {
          name: "cursor",
          in: "query",
          schema: { type: "string", maxLength: 255 },
        },
        {
          name: "limit",
          in: "query",
          schema: { type: "integer", minimum: 1, maximum: 100, default: 50 },
        },
      );
    const publicPath = `/api${path}`,
      specPath = publicPath.replace(/:([A-Za-z]+)/g, "{$1}");
    paths[specPath] ??= {};
    paths[specPath][method.toLowerCase()] = {
      operationId: `${method.toLowerCase()}${path.replace(/[^A-Za-z0-9]/g, "_")}`,
      summary,
      security: auth
        ? [
            {
              sessionCookie: [],
              ...(!["GET", "HEAD"].includes(method) ? { csrfHeader: [] } : {}),
            },
            { bearerAuth: [] },
          ]
        : [],
      parameters,
      ...(!["GET", "DELETE"].includes(method) || (body as z.ZodType) !== empty
        ? {
            requestBody: {
              required: true,
              content: { "application/json": { schema: json(body, "input") } },
            },
          }
        : {}),
      responses: {
        200: {
          description: "Successful response",
          content: { "application/json": { schema: json(response) } },
        },
        ...Object.fromEntries(
          [400, 401, 403, 404, 409, 422, 429, 500, 503].map((status) => [
            status,
            {
              description: "Structured error; inspect error.code",
              content: { "application/json": { schema: json(errorDto) } },
            },
          ]),
        ),
      },
    };
    app.route({
      method,
      url: publicPath,
      ...(auth ? { preHandler: authenticate } : {}),
      handler: async (req, reply) => {
        const input = body.parse(req.body ?? {});
        if (paginated) pagination.parse(req.query);
        const result = await handler(req, input, reply),
          validated = response.safeParse(result);
        if (!validated.success) {
          req.log.error({
            event: "response.contract_failed",
            route: publicPath,
            fields: validated.error.issues.map((i) => i.path.join(".")),
          });
          throw new AppError(
            "INTERNAL_ERROR",
            "The response could not be validated",
            500,
          );
        }
        return validated.data;
      },
    });
  }
  const list = <T extends z.ZodType>(
    path: string,
    summary: string,
    schema: T,
    load: (
      req: FastifyRequest,
      query: z.output<typeof pagination>,
    ) => Promise<{ id: string }[]>,
    auth = true,
  ) =>
    route(
      "GET",
      path,
      summary,
      empty,
      pageOf(schema),
      async (req) => {
        const query = pagination.parse(req.query);
        return page(await load(req, query), query.limit);
      },
      auth,
      true,
    );
  const flag = (name: string) => z.object({ [name]: z.boolean() });
  const sensitiveLimit = async (req: FastifyRequest, email?: string) => {
    await s.limiter.take(`source:${req.ip}`, 30, 600000);
    if (email)
      await s.limiter.take(`account:${canonicalEmail(email)}`, 12, 600000);
    else if (req.principal)
      await s.limiter.take(`sensitive:${req.principal.accountId}`, 12, 600000);
  };
  const clearCookies = (reply: FastifyReply) => {
    reply.clearCookie("pid_session", { path: "/" });
    reply.clearCookie("pid_csrf", { path: "/" });
  };
  app.get("/", async (_req, reply) => reply.redirect("/site/"));
  app.get("/health", async () => ({ status: "ok" }));
  app.get("/ready", async (_req, reply) => {
    const healthy = await s.db.health();
    return reply
      .code(healthy ? 200 : 503)
      .send({ status: healthy ? "ready" : "unavailable" });
  });
  app.get("/.well-known/jwks.json", async () => s.provider.jwks());
  app.get("/openapi.json", async () => ({
    openapi: "3.1.0",
    info: {
      title: "PrivateID API",
      version: "2.0.0",
      description:
        "Minimal-disclosure, online-revocable proofs. This custom protocol is not OAuth/OIDC or zero-knowledge cryptography.",
    },
    servers: [{ url: config.siteUrl }],
    paths,
    components: {
      securitySchemes: {
        sessionCookie: { type: "apiKey", in: "cookie", name: "pid_session" },
        csrfHeader: { type: "apiKey", in: "header", name: "X-CSRF-Token" },
        bearerAuth: { type: "http", scheme: "bearer" },
      },
    },
  }));
  route(
    "GET",
    "/configuration",
    "Public product configuration",
    empty,
    z.object({
      mode: z.string(),
      claims: z.array(z.string()),
      proofSeconds: z.number(),
      consentRetentionDays: z.number(),
      auditRetentionDays: z.number(),
    }),
    () => ({
      mode: config.mode,
      claims: claimNames,
      proofSeconds: config.proofSeconds,
      consentRetentionDays: config.retentionDays,
      auditRetentionDays: config.auditRetentionDays,
    }),
    false,
  );
  route(
    "POST",
    "/accounts",
    "Create an unverified user account",
    registrationSchema,
    userSchema,
    async (req, body) => {
      await sensitiveLimit(req, body.email);
      return s.accounts.register(body);
    },
    false,
  );
  route(
    "POST",
    "/auth/login",
    "Sign in with a cookie session or explicit machine bearer",
    z
      .object({
        email: z.email(),
        password: z.string().min(1).max(128),
        code,
        device: z.string().max(160).optional(),
        bearer: z.boolean().default(false),
      })
      .strict(),
    z.object({
      user: userSchema,
      csrfToken: z.string(),
      expiresAt: z.string(),
      accessToken: z.string().optional(),
    }),
    async (req, body, reply) => {
      await sensitiveLimit(req, body.email);
      const result = await s.accounts.login(body);
      if (body.bearer) return result;
      const options = {
        path: "/",
        secure: config.mode === "production",
        sameSite: "strict" as const,
        expires: new Date(result.expiresAt),
      };
      reply.setCookie("pid_session", result.accessToken, {
        ...options,
        httpOnly: true,
      });
      reply.setCookie("pid_csrf", result.csrfToken, options);
      const { accessToken, ...safe } = result;
      return safe;
    },
    false,
  );
  route(
    "GET",
    "/auth/me",
    "Get the signed-in account",
    empty,
    userSchema,
    (req) => req.signedInUser,
  );
  route(
    "POST",
    "/auth/logout",
    "Revoke the current session",
    empty,
    flag("revoked"),
    async (req, _body, reply) => {
      const p = principal(req),
        result = await s.accounts.revokeSession(p, p.sessionId);
      clearCookies(reply);
      return result;
    },
  );
  route(
    "POST",
    "/auth/verify-email",
    "Consume an email verification challenge",
    z.object({ token: z.string().min(20).max(200) }).strict(),
    flag("verified"),
    async (req, body) => {
      await sensitiveLimit(req);
      return s.accounts.verifyEmail(body.token);
    },
    false,
  );
  for (const [path, kind] of [
    ["resend-verification", "EMAIL"],
    ["forgot-password", "PASSWORD"],
  ] as const)
    route(
      "POST",
      `/auth/${path}`,
      "Send a one-time account challenge if eligible",
      z.object({ email: z.email() }).strict(),
      z.object({ message: z.string() }),
      async (req, body) => {
        await sensitiveLimit(req, body.email);
        return s.accounts.requestChallenge(body.email, kind);
      },
      false,
    );
  route(
    "POST",
    "/auth/reset-password",
    "Reset password and revoke all sessions",
    z
      .object({
        token: z.string().min(20).max(200),
        password: passwordSchema,
        code,
      })
      .strict(),
    flag("reset"),
    async (req, body) => {
      await sensitiveLimit(req);
      return s.accounts.resetPassword(body.token, body.password, body.code);
    },
    false,
  );
  route(
    "POST",
    "/auth/password",
    "Change password and revoke all sessions",
    z
      .object({
        currentPassword: z.string().max(128),
        password: passwordSchema,
        code,
      })
      .strict(),
    z.object({ changed: z.boolean(), signInAgain: z.boolean() }),
    async (req, body, reply) => {
      await sensitiveLimit(req);
      const result = await s.accounts.changePassword(
        principal(req),
        body.currentPassword,
        body.password,
        body.code,
      );
      clearCookies(reply);
      return result;
    },
  );
  route(
    "POST",
    "/auth/mfa/setup",
    "Begin ten-minute authenticator enrollment",
    z.object({ password: z.string().max(128) }).strict(),
    z.object({ secret: z.string(), uri: z.string() }),
    async (req, body) => {
      await sensitiveLimit(req);
      return s.accounts.startMfa(principal(req), body.password);
    },
  );
  route(
    "POST",
    "/auth/mfa/confirm",
    "Confirm authenticator and return recovery codes once",
    z.object({ code: z.string().regex(/^\d{6}$/) }).strict(),
    z.object({ recoveryCodes: z.array(z.string()) }),
    async (req, body) => {
      await sensitiveLimit(req);
      return s.accounts.confirmMfa(principal(req), body.code);
    },
  );
  route(
    "DELETE",
    "/accounts/me",
    "Queue billing cancellation and erasure; revoke access now",
    z.object({ password: z.string().max(128), code }).strict(),
    z.object({ status: z.string(), message: z.string() }),
    async (req, body, reply) => {
      await sensitiveLimit(req);
      const result = await s.accounts.requestDeletion(
        principal(req),
        body.password,
        body.code,
      );
      clearCookies(reply);
      return result;
    },
  );
  route(
    "GET",
    "/sessions",
    "List public session identifiers",
    empty,
    z.array(
      z.object({
        id: z.string(),
        createdAt: z.string(),
        expiresAt: z.string(),
        lastSeenAt: z.string(),
        device: z.string(),
        current: z.boolean(),
      }),
    ),
    (req) => s.accounts.sessions(principal(req)),
  );
  route(
    "DELETE",
    "/sessions/:id",
    "Revoke an owned session",
    empty,
    flag("revoked"),
    (req, _body, reply) => {
      if (id(req) === principal(req).sessionId) clearCookies(reply);
      return s.accounts.revokeSession(principal(req), id(req));
    },
  );
  list("/credentials", "List your credentials", credentialDto, (req, query) =>
    s.credentials.list(principal(req), query),
  );
  route(
    "POST",
    "/credentials",
    "Issue evidence-backed claims within reviewed authority",
    credentialInput,
    credentialDto,
    (req, body) => s.credentials.issue(principal(req), body),
  );
  route(
    "POST",
    "/credentials/:id/revoke",
    "Revoke an issued credential with a reason",
    z.object({ reason }).strict(),
    credentialDto,
    (req, body) => s.credentials.revoke(principal(req), id(req), body.reason),
  );
  list(
    "/issuers",
    "List owned issuers or staff review queue",
    issuerSchema,
    (req, query) => s.credentials.issuers(principal(req), query),
  );
  list(
    "/trust-registry",
    "List reviewed public issuer policies",
    issuerSchema.pick({
      id: true,
      issuerName: true,
      jurisdiction: true,
      assuranceLevel: true,
      supportedClaims: true,
      policy: true,
    }),
    (_req, query) => s.credentials.issuers(undefined, query),
    false,
  );
  route(
    "POST",
    "/issuers",
    "Submit an issuer for independent review",
    issuerInput,
    issuerSchema,
    (req, body) => s.credentials.registerIssuer(principal(req), body),
  );
  route(
    "PUT",
    "/issuers/:id/review",
    "Approve, suspend, or revoke an issuer",
    z
      .object({ status: z.enum(["TRUSTED", "SUSPENDED", "REVOKED"]), reason })
      .strict(),
    issuerSchema,
    (req, body) =>
      s.credentials.reviewIssuer(
        principal(req),
        id(req),
        body.status,
        body.reason,
      ),
  );
  list(
    "/issuers/:id/credentials",
    "List credentials within an owned issuer workspace",
    credentialDto,
    (req, query) => s.credentials.issued(principal(req), id(req), query),
  );
  list(
    "/verifiers",
    "List owned applications or identity review queue",
    verifierDto,
    (req, query) => s.verifiers.list(principal(req), query),
  );
  route(
    "GET",
    "/verifiers/:id/public",
    "Get a reviewed verifier consent policy",
    empty,
    verifierSchema.pick({
      id: true,
      name: true,
      purpose: true,
      allowedClaims: true,
      redirectUris: true,
    }),
    (req) => s.verifiers.publicInfo(id(req)),
    false,
  );
  route(
    "POST",
    "/verifiers",
    "Submit a verifier and return its secret once",
    verifierInput,
    z.object({ application: verifierDto, clientSecret: z.string() }),
    (req, body) => s.verifiers.register(principal(req), body),
  );
  route(
    "PUT",
    "/verifiers/:id",
    "Change a verifier and require renewed review",
    verifierInput.omit({ clientId: true, organizationId: true }),
    verifierDto,
    (req, body) => s.verifiers.update(principal(req), id(req), body),
  );
  route(
    "PUT",
    "/verifiers/:id/review",
    "Independently review a verifier",
    z
      .object({ status: z.enum(["ACTIVE", "SUSPENDED", "REVOKED"]), reason })
      .strict(),
    verifierDto,
    (req, body) =>
      s.verifiers.review(principal(req), id(req), body.status, body.reason),
  );
  route(
    "POST",
    "/verifiers/:id/rotate-secret",
    "Rotate a verifier secret and invalidate proofs",
    empty,
    z.object({ clientSecret: z.string() }),
    (req) => s.verifiers.rotateSecret(principal(req), id(req)),
  );
  list(
    "/proof-requests",
    "List your consent history",
    requestDto,
    (req, query) => s.proofs.list(principal(req), query),
  );
  route(
    "POST",
    "/proof-requests",
    "Create a pending explicit-consent request",
    requestInput,
    requestDto,
    (req, body) => s.proofs.create(principal(req), body),
  );
  route(
    "GET",
    "/proof-requests/:id",
    "Get an owned consent request",
    empty,
    requestDto,
    (req) => s.proofs.get(principal(req), id(req)),
  );
  const decisionDto = z.object({
    request: requestDto,
    proof: z.string().optional(),
    redirectUrl: z.string().optional(),
  });
  route(
    "GET",
    "/proof-requests/:id/preview",
    "Preview exact disclosures before consent",
    empty,
    z.object({
      claims: z.record(z.string(), z.union([z.boolean(), z.string()])),
      previewHash: z.string(),
      expiresAt: z.string(),
    }),
    (req) => s.proofs.preview(principal(req), id(req)),
  );
  route(
    "POST",
    "/proof-requests/:id/approve",
    "Approve the previewed disclosures",
    z.object({ previewHash: z.string().regex(/^[a-f0-9]{64}$/) }).strict(),
    decisionDto,
    (req, body) =>
      s.proofs.decide(principal(req), id(req), true, body.previewHash),
  );
  route(
    "POST",
    "/proof-requests/:id/deny",
    "Deny a pending request",
    empty,
    decisionDto,
    (req) => s.proofs.decide(principal(req), id(req), false),
  );
  const verificationInput = z
    .object({
      proof: z.string().max(16384),
      clientId: z.string().max(60),
      clientSecret: z.string().max(200),
    })
    .strict();
  const verificationDto = z.object({
    valid: z.boolean(),
    claims: z.record(z.string(), z.union([z.string(), z.boolean()])),
    subject: z.string(),
    expiresAt: z.string(),
    nonce: z.string().optional(),
  });
  for (const action of ["verify", "introspect"] as const)
    route(
      "POST",
      `/proofs/${action}`,
      action === "verify"
        ? "Authenticate verifier and consume proof once"
        : "Check current proof authority without consuming",
      verificationInput,
      verificationDto,
      (_req, body) =>
        s.proofs.verify(
          body.proof,
          body.clientId,
          body.clientSecret,
          action === "verify",
        ),
      false,
    );
  route(
    "POST",
    "/federation/token",
    "Redeem an authorization code with S256 PKCE",
    z
      .object({
        clientId: z.string().max(60),
        clientSecret: z.string().max(200).optional(),
        code: z.string().max(200),
        codeVerifier: z.string().min(43).max(128),
        redirectUri: z.url(),
      })
      .strict(),
    z.object({
      token_type: z.literal("privateid-proof"),
      proof: z.string(),
      claims: z.record(z.string(), z.union([z.string(), z.boolean()])),
      subject: z.string(),
      nonce: z.string().optional(),
      expiresAt: z.string(),
    }),
    (_req, body) => s.proofs.redeemCode(body),
    false,
  );
  route(
    "GET",
    "/privacy-dashboard",
    "Get effective quotas and disclosure counts",
    empty,
    z.object({
      plan: planDto,
      subscriptionStatus: z.string(),
      usage: z.object({
        proofs: z.number(),
        period: z.string(),
        credentials: z.number(),
        connections: z.number(),
      }),
      counts: z.object({
        pendingRequests: z.number(),
        approvedRequests: z.number(),
        disclosures: z.number(),
      }),
    }),
    (req) => s.proofs.dashboard(principal(req)),
  );
  list(
    "/connections",
    "List application access and shared claim names",
    accessSchema,
    (req, query) => s.proofs.connections(principal(req), query),
  );
  route(
    "DELETE",
    "/connections/:id",
    "Revoke application access and outstanding proofs",
    empty,
    flag("revoked"),
    (req) => s.proofs.revokeAccess(principal(req), id(req)),
  );
  route(
    "POST",
    "/connections/:id/restore",
    "Allow new consent without reviving old proofs",
    empty,
    z.object({ restored: z.boolean(), requiresNewConsent: z.boolean() }),
    (req) => s.proofs.restoreAccess(principal(req), id(req)),
  );
  route(
    "GET",
    "/billing/plans",
    "Get the authoritative price and entitlement catalog",
    empty,
    z.array(planDto),
    () => s.billing.listPlans(),
    false,
  );
  route(
    "GET",
    "/billing/subscription",
    "Get effective access separately from billing history",
    empty,
    subscriptionDto,
    (req) => s.billing.subscription(principal(req)),
  );
  route(
    "POST",
    "/billing/checkout",
    "Create or reuse one checkout operation",
    z.object({ planId: z.enum(["professional", "business"]) }).strict(),
    z.object({
      status: z.string(),
      url: z.string().optional(),
      expiresAt: z.string().optional(),
      message: z.string().optional(),
    }),
    (req, body) => s.billing.checkout(principal(req), body.planId),
  );
  route(
    "POST",
    "/billing/portal",
    "Open your billing portal",
    empty,
    z.object({ url: z.string() }),
    (req) => s.billing.portal(principal(req)),
  );
  route(
    "POST",
    "/billing/reconcile",
    "Refresh subscriptions and queue history reconciliation",
    empty,
    subscriptionDto,
    (req) => s.billing.reconcile(principal(req)),
  );
  list(
    "/billing/invoices",
    "List invoice history in currency minor units",
    invoiceSchema,
    (req, query) => s.billing.invoices(principal(req), query),
  );
  app.post(
    "/api/webhooks/stripe",
    {
      bodyLimit: 1048576,
      config: {
        rawBody: true,
        rateLimit: { max: 600, timeWindow: "1 minute" },
      },
    },
    async (req) => {
      requireThat(
        Buffer.isBuffer(req.rawBody),
        "INVALID_WEBHOOK",
        "Raw webhook body is required",
      );
      return s.billing.handleWebhook(
        req.rawBody,
        String(req.headers["stripe-signature"] ?? ""),
      );
    },
  );
  paths["/api/webhooks/stripe"] = {
    post: {
      summary:
        "Verify raw Stripe signature and durably enqueue a minimal receipt",
      security: [],
      parameters: [
        {
          name: "Stripe-Signature",
          in: "header",
          required: true,
          schema: { type: "string" },
        },
      ],
      requestBody: {
        required: true,
        content: { "application/json": { schema: { type: "object" } } },
      },
      responses: {
        200: {
          description:
            "Durably accepted or already received; processing continues asynchronously",
        },
        400: { description: "Invalid signature, environment, or API version" },
        503: { description: "Not durably accepted; provider must retry" },
      },
    },
  };
  route(
    "GET",
    "/organizations",
    "List organization memberships",
    empty,
    z.array(organizationSchema.extend({ role: z.string() })),
    (req) => s.organizations.list(principal(req)),
  );
  route(
    "POST",
    "/organizations",
    "Create a Business workspace",
    z.object({ name: z.string().min(2).max(120) }).strict(),
    organizationSchema,
    (req, body) => s.organizations.create(principal(req), body.name),
  );
  route(
    "GET",
    "/organizations/:id/members",
    "List workspace members as owner",
    empty,
    z.array(
      z.object({
        id: z.string(),
        userId: z.string(),
        organizationId: z.string(),
        createdAt: z.string(),
        role: z.string(),
        email: z.string().optional(),
      }),
    ),
    (req) => s.organizations.members(principal(req), id(req)),
  );
  route(
    "POST",
    "/organizations/:id/members",
    "Add a verified member within the plan limit",
    z
      .object({
        email: z.email(),
        role: z.enum(["ISSUER", "VERIFIER", "MEMBER"]),
      })
      .strict(),
    z.object({
      id: z.string(),
      createdAt: z.string(),
      organizationId: z.string(),
      userId: z.string(),
      role: z.string(),
    }),
    (req, body) => s.organizations.addMember(principal(req), id(req), body),
  );
  route(
    "DELETE",
    "/organizations/:id/members/:userId",
    "Remove a workspace member",
    empty,
    flag("removed"),
    (req) =>
      s.organizations.removeMember(principal(req), id(req), id(req, "userId")),
  );
  route(
    "POST",
    "/organizations/:id/transfer",
    "Transfer ownership to a Business owner with MFA",
    z.object({ userId: z.string() }).strict(),
    organizationSchema,
    (req, body) =>
      s.organizations.transfer(principal(req), id(req), body.userId),
  );
  route(
    "POST",
    "/organizations/:id/leave",
    "Leave a workspace as a non-owner",
    empty,
    flag("left"),
    (req) => s.organizations.leave(principal(req), id(req)),
  );
  route(
    "POST",
    "/organizations/:id/close",
    "Close a workspace and revoke its authority",
    empty,
    flag("closed"),
    (req) => s.organizations.close(principal(req), id(req)),
  );
  list(
    "/organizations/:id/audit",
    "Read scoped workspace audit",
    auditSchema,
    (req, query) =>
      s.organizations.audit(principal(req), id(req), query.cursor, query.limit),
  );
  list(
    "/admin/customers",
    "List safe account metadata for identity/security staff",
    userSchema,
    (req, query) => s.accounts.customers(principal(req), query),
  );
  route(
    "PUT",
    "/admin/customers/:id/roles",
    "Assign staff roles to a verified MFA-enabled account",
    z.object({ roles: z.array(z.enum(roles)).min(1).max(5), reason }).strict(),
    userSchema,
    (req, body) =>
      s.accounts.grantRoles(principal(req), id(req), body.roles, body.reason),
  );
  route(
    "PUT",
    "/admin/customers/:id/status",
    "Change account status and invalidate sessions",
    z.object({ status: z.enum(["ACTIVE", "SUSPENDED"]), reason }).strict(),
    userSchema,
    (req, body) =>
      s.accounts.setStatus(principal(req), id(req), body.status, body.reason),
  );
  list("/audit", "Read append-only security audit", auditSchema, (req, query) =>
    s.db.transaction(async (tx) => {
      await authorize(tx, principal(req), ["SECURITY_ADMIN"], s.clock());
      return tx.list("audit", query);
    }),
  );
  list(
    "/admin/billing/events",
    "Inspect webhook retries without raw payloads",
    eventSchema.omit({ payload: true, leaseToken: true }),
    (req, query) => s.billing.events(principal(req), query),
  );
  route(
    "POST",
    "/admin/billing/events/:id/retry",
    "Retry a failed billing receipt",
    empty,
    flag("queued"),
    (req) => s.billing.retry(principal(req), id(req)),
  );
  route(
    "GET",
    "/admin/overview",
    "Read operational counts and separate currency totals",
    empty,
    z.object({
      accounts: z.number(),
      credentials: z.number(),
      pendingIssuers: z.number(),
      pendingVerifiers: z.number(),
      failedMail: z.number(),
      workerUpdatedAt: z.string().optional(),
      billing: z.object({
        customers: z.number(),
        subscriptions: z.number(),
        invoices: z.number(),
        pendingEvents: z.number(),
        failedEvents: z.number(),
        currencies: z.array(
          z.object({
            currency: z.string(),
            grossPaid: z.number(),
            refunded: z.number(),
            disputed: z.number(),
          }),
        ),
        definition: z.string(),
      }),
    }),
    (req) =>
      s.db.transaction(async (tx) => {
        await authorize(
          tx,
          principal(req),
          ["IDENTITY_ADMIN", "SECURITY_ADMIN"],
          s.clock(),
        );
        return {
          accounts: await tx.count("accounts"),
          credentials: await tx.count("credentials"),
          pendingIssuers: await tx.count("issuers", { status: "PENDING" }),
          pendingVerifiers: await tx.count("verifiers", { status: "PENDING" }),
          failedMail: await tx.count("mail", { status: "FAILED" }),
          workerUpdatedAt: (await tx.get("metadata", "worker-heartbeat"))?.value
            .updatedAt,
          billing: await s.billing.summary(tx),
        };
      }),
  );
  route(
    "GET",
    "/admin/metrics",
    "Read bounded per-route operational counters for this process",
    empty,
    z.object({
      scope: z.string(),
      routes: z.array(
        z.object({
          route: z.string(),
          requests: z.number(),
          errors: z.number(),
          meanMilliseconds: z.number(),
          maximumMilliseconds: z.number(),
        }),
      ),
    }),
    async (req) => {
      await s.db.transaction((tx) =>
        authorize(tx, principal(req), ["SECURITY_ADMIN"], s.clock()),
      );
      return metrics.snapshot();
    },
  );
  return app;
}
