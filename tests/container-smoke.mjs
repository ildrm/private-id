import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { totp } from "./dist/src/security.js";
const base = "http://127.0.0.1:3001";
const fixture = JSON.parse(
  await readFile("/app/.data/synthetic-accounts.json", "utf8"),
);
async function call(path, body, token) {
  const response = await fetch(base + path, {
    method: body ? "POST" : "GET",
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  assert.equal(response.status, 200, `${path} failed with ${response.status}`);
  return response.json();
}
assert.equal((await call("/ready")).status, "ready");
assert.match(await (await fetch(base + "/site/")).text(), /PrivateID/);
const spec = await call("/openapi.json");
assert.ok(Object.keys(spec.paths).length > 45);
const customer = fixture.customer;
const login = await call("/api/auth/login", {
  email: customer.email,
  password: customer.password,
  code: totp(customer.authenticatorKey, Math.floor(Date.now() / 30000)),
  bearer: true,
});
const request = await call(
  "/api/proof-requests",
  { clientId: fixture.verifier.clientId, requestedClaims: ["account_valid"] },
  login.accessToken,
);
const preview = await call(
  `/api/proof-requests/${request.id}/preview`,
  undefined,
  login.accessToken,
);
const issued = await call(
  `/api/proof-requests/${request.id}/approve`,
  { previewHash: preview.previewHash },
  login.accessToken,
);
const verified = await call("/api/proofs/verify", {
  proof: issued.proof,
  clientId: fixture.verifier.clientId,
  clientSecret: fixture.verifier.clientSecret,
});
assert.deepEqual(verified.claims, { account_valid: true });
assert.equal(process.getuid(), 1000);
console.log(
  JSON.stringify({
    node: process.version,
    uid: process.getuid(),
    readiness: true,
    staticSite: true,
    openapiPaths: Object.keys(spec.paths).length,
    persistedSeedLogin: true,
    consentAndRedemption: true,
  }),
);
