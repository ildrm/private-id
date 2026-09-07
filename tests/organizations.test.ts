import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryDatabase } from "../src/repository.js";
import { createServices } from "../src/services.js";
import { testConfig } from "../src/config.js";
import { createUser } from "./helpers.js";
test("Business workspaces enforce membership, ownership transfer, independent review, and scope", async () => {
  const db = new MemoryDatabase(),
    s = await createServices(db, testConfig()),
    now = new Date().toISOString();
  const owner = await createUser(s.accounts, "owner@synthetic.test", {
      mfa: true,
    }),
    member = await createUser(s.accounts, "member@synthetic.test", {
      mfa: true,
    }),
    outsider = await createUser(s.accounts, "outsider@synthetic.test", {
      mfa: true,
    });
  await assert.rejects(
    s.organizations.create(owner.principal, "Example organization"),
  );
  for (const user of [owner, member])
    await db.transaction((tx) =>
      tx.insert("subscriptions", {
        id: `sub-${user.user.id}`,
        createdAt: now,
        accountId: user.user.id,
        planId: "business",
        status: "active",
        currentPeriodEnd: new Date(Date.now() + 86400000).toISOString(),
        cancelAtPeriodEnd: false,
        providerUpdatedAt: 0,
        updatedAt: now,
      }),
    );
  const org = await s.organizations.create(
    owner.principal,
    "Example organization",
  );
  await s.organizations.addMember(owner.principal, org.id, {
    email: member.user.email,
    role: "ISSUER",
  });
  await assert.rejects(s.organizations.members(outsider.principal, org.id));
  await assert.rejects(
    s.organizations.addMember(member.principal, org.id, {
      email: outsider.user.email,
      role: "MEMBER",
    }),
  );
  const issuer = await s.credentials.registerIssuer(member.principal, {
    issuerName: "Organization issuer",
    organizationId: org.id,
    jurisdiction: "DE",
    supportedClaims: ["identity_verified"],
    assuranceLevel: "LOW",
    policy: "Synthetic evidence review policy",
  });
  assert.equal(issuer.ownerId, owner.user.id);
  assert.equal(
    (await s.credentials.issuers(member.principal, { organizationId: org.id }))
      .length,
    1,
  );
  await assert.rejects(
    s.credentials.issuers(outsider.principal, { organizationId: org.id }),
  );
  await s.organizations.transfer(owner.principal, org.id, member.user.id);
  assert.equal(
    (await db.transaction((tx) => tx.get("issuers", issuer.id)))?.ownerId,
    member.user.id,
  );
  await s.organizations.leave(owner.principal, org.id);
  await assert.rejects(
    s.credentials.issuers(owner.principal, { organizationId: org.id }),
  );
  assert.equal(
    (
      await s.accounts.authenticate(member.login.accessToken)
    ).account.roles.join(","),
    "USER",
  );
  await s.organizations.close(member.principal, org.id);
  await assert.rejects(
    s.credentials.issuers(member.principal, { organizationId: org.id }),
  );
});
