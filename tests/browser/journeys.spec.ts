import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
async function fixture() {
  return JSON.parse(await readFile(".data/browser-fixture.json", "utf8")) as {
    email: string;
    password: string;
    clientId: string;
    clientSecret: string;
  };
}
test("customer signs in, reviews exact claims, approves, revokes, and navigates without stale data", async ({
  page,
}) => {
  const f = await fixture(),
    errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/site/");
  await page.getByLabel("Email address").fill(f.email);
  await page.getByLabel("Password", { exact: true }).fill(f.password);
  await page
    .getByRole("button", { name: "Sign in", exact: true })
    .first()
    .click();
  await expect(
    page.getByRole("heading", { name: "Your identity wallet" }),
  ).toBeVisible();
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);
  await page.getByRole("button", { name: "Security", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Sessions", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Billing", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Billing and plans" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Free", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Credentials", exact: true }).click();
  await expect(
    page.getByText("No credentials yet.", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Proofs & consent" }).click();
  await page.getByLabel("Reviewed verifier client ID").fill(f.clientId);
  await page.getByRole("button", { name: "Review disclosure" }).click();
  await expect(
    page.getByRole("heading", { name: "Exactly what will be shared" }),
  ).toBeVisible();
  await expect(page.getByText("Yes", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Approve these values" }).click();
  await expect(
    page.getByRole("heading", { name: "One-time proof for your verifier" }),
  ).toBeVisible();
  const proof = await page.locator(".secret pre").innerText();
  const response = await page.request.post("/api/proofs/verify", {
    data: { proof, clientId: f.clientId, clientSecret: f.clientSecret },
  });
  expect(response.ok()).toBeTruthy();
  expect((await response.json()).claims).toEqual({ account_valid: true });
  await page.getByRole("button", { name: "Done", exact: true }).click();
  await page
    .getByRole("button", { name: "Connected apps", exact: true })
    .click();
  await page.getByRole("button", { name: "Revoke application access" }).click();
  await expect(page.getByText("REVOKED", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Welcome to PrivateID" }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});
test("registration, email verification, password recovery, and authenticator setup work through the UI", async ({
  page,
  request,
}) => {
  const email = `registration-${Date.now()}@synthetic.test`,
    password = "a browser-only strong passphrase";
  await page.goto("/site/");
  await page
    .getByRole("button", { name: "Create account", exact: true })
    .click();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page
    .getByRole("button", { name: "Create account", exact: true })
    .first()
    .click();
  await expect(
    page.getByText("Account created.", { exact: false }),
  ).toBeVisible();
  const messages = await (
    await request.get(`/__test__/challenge/${email}`)
  ).json();
  const token = messages[0].text.match(/verify=([A-Za-z0-9_-]+)/)[1];
  await page.goto(`/site/#verify=${token}`);
  await page.getByRole("button", { name: "Verify email address" }).click();
  await expect(
    page.getByText("Email verified.", { exact: false }),
  ).toBeVisible();
  expect(page.url()).not.toContain(token);
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page
    .getByRole("button", { name: "Sign in", exact: true })
    .first()
    .click();
  await expect(
    page.getByRole("heading", { name: "Your identity wallet" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Security", exact: true }).click();
  await page
    .getByLabel("Current password", { exact: true })
    .first()
    .fill(password);
  await page.getByRole("button", { name: "Set up authenticator" }).click();
  const mfaSecret = await page.locator(".secret pre").innerText();
  const { totp } = await import("../../src/security.js");
  await page
    .getByLabel("Six-digit authenticator code")
    .fill(totp(mfaSecret, Math.floor(Date.now() / 30000)));
  await page.getByRole("button", { name: "Confirm authenticator" }).click();
  await expect(
    page.getByRole("heading", { name: "Single-use recovery codes" }),
  ).toBeVisible();
  const recovery = (await page.locator(".secret pre").innerText()).split(
    "\n",
  )[0];
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByRole("button", { name: "Forgot password" }).click();
  await page.getByLabel("Email address").fill(email);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(
    page.getByText("If the account is eligible", { exact: false }),
  ).toBeVisible();
  const resetMail = await (
    await request.get(`/__test__/challenge/${email}`)
  ).json();
  const reset = resetMail
    .find((m: { subject: string }) => m.subject.includes("Reset"))
    .text.match(/reset=([A-Za-z0-9_-]+)/)[1];
  await page.goto(`/site/#reset=${reset}`);
  await page
    .getByLabel("Password", { exact: true })
    .fill(password + " changed");
  await page
    .getByLabel("Authenticator or recovery code (if enabled)")
    .fill(recovery);
  await page
    .getByRole("button", { name: "Reset password", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Welcome to PrivateID" }),
  ).toBeVisible();
});
test("small viewport remains usable and forms expose accessible labels and focus", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/site/");
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to content" }),
  ).toBeFocused();
  await expect(page.getByLabel("Email address")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
});
