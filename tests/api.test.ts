import { test } from "node:test";
import assert from "node:assert/strict";
import { buildApp } from "../src/app.js";
import { createServices } from "../src/services.js";
import { MemoryDatabase } from "../src/repository.js";
import { testConfig } from "../src/config.js";
import { createUser, testPassword } from "./helpers.js";
async function setup() {
  const db = new MemoryDatabase(),
    services = await createServices(db, testConfig()),
    app = await buildApp(services);
  return { services, app, db };
}
test("HTTP cookie login, CSRF, origin rejection, safe responses and logout", async (t) => {
  const { services, app } = await setup();
  t.after(() => app.close());
  const { user } = await createUser(
    services.accounts,
    "browser@synthetic.test",
  );
  const login = await app.inject({
    method: "POST",
    url: "/api/auth/login",
    payload: { email: user.email, password: testPassword },
  });
  assert.equal(login.statusCode, 200, login.body);
  assert.equal(login.json().accessToken, undefined);
  const cookies = login.cookies.map((c) => `${c.name}=${c.value}`).join("; "),
    sessionCookie = login.cookies.find((c) => c.name === "pid_session")!;
  assert.equal(sessionCookie.httpOnly, true);
  assert.equal(sessionCookie.sameSite, "Strict");
  const me = await app.inject({
    url: "/api/auth/me",
    headers: { cookie: cookies },
  });
  assert.equal(me.statusCode, 200);
  assert.equal(me.json().passwordHash, undefined);
  assert.equal(me.headers["cache-control"], "no-store");
  const denied = await app.inject({
    method: "POST",
    url: "/api/auth/logout",
    headers: { cookie: cookies },
    payload: {},
  });
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.json().error.code, "CSRF_REJECTED");
  assert.equal(
    (
      await app.inject({
        method: "POST",
        url: "/api/auth/logout",
        headers: {
          cookie: cookies,
          origin: "https://evil.invalid",
          "x-csrf-token": login.json().csrfToken,
        },
        payload: {},
      })
    ).statusCode,
    403,
  );
  assert.equal(
    (
      await app.inject({
        method: "POST",
        url: "/api/auth/logout",
        headers: { cookie: cookies, "x-csrf-token": login.json().csrfToken },
        payload: {},
      })
    ).statusCode,
    200,
  );
  assert.equal(
    (await app.inject({ url: "/api/auth/me", headers: { cookie: cookies } }))
      .statusCode,
    401,
  );
});
test("registration rejects privileged fields, errors are structured, and unverified accounts cannot issue proofs", async (t) => {
  const { app } = await setup();
  t.after(() => app.close());
  const bad = await app.inject({
    method: "POST",
    url: "/api/accounts",
    payload: {
      email: "test@synthetic.test",
      password: testPassword,
      roles: ["SECURITY_ADMIN"],
    },
  });
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.json().error.code, "INVALID_INPUT");
  const created = await app.inject({
    method: "POST",
    url: "/api/accounts",
    payload: { email: "test@synthetic.test", password: testPassword },
  });
  assert.equal(created.statusCode, 200);
  assert.equal(created.json().emailVerified, false);
  const login = await app.inject({
    method: "POST",
    url: "/api/auth/login",
    payload: {
      email: "test@synthetic.test",
      password: testPassword,
      bearer: true,
    },
  });
  const protectedRoute = await app.inject({
    url: "/api/privacy-dashboard",
    headers: { authorization: `Bearer ${login.json().accessToken}` },
  });
  assert.equal(protectedRoute.statusCode, 403);
});
test("every documented API operation has a response schema and authentication policy", async (t) => {
  const { app } = await setup();
  t.after(() => app.close());
  const spec = (await app.inject("/openapi.json")).json();
  assert.equal(spec.openapi, "3.1.0");
  assert.ok(Object.keys(spec.paths).length >= 45);
  for (const [path, methods] of Object.entries(spec.paths))
    for (const operation of Object.values(
      methods as Record<
        string,
        { responses: Record<string, unknown>; security: unknown }
      >,
    )) {
      assert.ok(operation.responses["200"], path);
      assert.ok(operation.security, path);
    }
  assert.equal(
    (await app.inject("/api/billing/plans")).json()[0].limits.credentials,
    5,
  );
  assert.equal(
    (await app.inject("/api/billing/plans")).json()[1].checkoutEnabled,
    false,
  );
});
test("staff endpoints fail closed for ordinary customers and session listings do not leak tokens", async (t) => {
  const { app, services } = await setup();
  t.after(() => app.close());
  const customer = await createUser(
    services.accounts,
    "ordinary@synthetic.test",
  );
  const headers = { authorization: `Bearer ${customer.login.accessToken}` };
  for (const url of [
    "/api/admin/customers",
    "/api/admin/overview",
    "/api/audit",
    "/api/admin/billing/events",
  ])
    assert.equal((await app.inject({ url, headers })).statusCode, 403, url);
  const sessions = await app.inject({ url: "/api/sessions", headers });
  assert.equal(sessions.statusCode, 200);
  assert.ok(!sessions.body.includes(customer.login.accessToken));
  assert.ok(!sessions.body.includes("tokenHash"));
});
test("readiness reflects database failure and 500 responses never reveal exception details", async (t) => {
  const { app, db } = await setup();
  t.after(() => app.close());
  db.health = async () => false;
  assert.equal((await app.inject("/health")).statusCode, 200);
  assert.equal((await app.inject("/ready")).statusCode, 503);
  db.transaction = async () => {
    throw new Error("secret database host and password");
  };
  const response = await app.inject({
    method: "POST",
    url: "/api/accounts",
    payload: { email: "oops@synthetic.test", password: testPassword },
  });
  assert.equal(response.statusCode, 500);
  assert.ok(!response.body.includes("secret database"));
  assert.ok(response.json().error.requestId);
});
