import { AccountService } from "../src/accounts.js";
import { unseal, totp } from "../src/security.js";
import type { Role } from "../src/models.js";
export const testPassword = "a unique fixture password";
export async function createUser(
  accounts: AccountService,
  email: string,
  options: { roles?: Role[]; mfa?: boolean } = {},
) {
  const user = await accounts.register({ email, password: testPassword });
  const mail = await accounts.db.transaction((tx) =>
    tx.list("mail", { where: { userId: user.id } }),
  );
  const text = JSON.parse(
    unseal(mail[0].content, accounts.config.encryptionKey),
  ).text as string;
  await accounts.verifyEmail(text.match(/verify=([A-Za-z0-9_-]+)/)![1]);
  let login = await accounts.login({ email, password: testPassword });
  let principal = (await accounts.authenticate(login.accessToken)).principal;
  let recoveryCodes: string[] = [],
    mfaSecret: string | undefined;
  if (options.mfa || options.roles?.some((r) => r !== "USER")) {
    mfaSecret = (await accounts.startMfa(principal, testPassword)).secret;
    recoveryCodes = (
      await accounts.confirmMfa(
        principal,
        totp(mfaSecret, Math.floor(accounts.clock() / 30000)),
      )
    ).recoveryCodes;
    if (options.roles) {
      await accounts.enrollAdministrator(
        user.id,
        options.roles,
        "Synthetic test enrollment",
      );
      login = await accounts.login({
        email,
        password: testPassword,
        code: recoveryCodes.shift(),
      });
      principal = (await accounts.authenticate(login.accessToken)).principal;
    }
  }
  return { user, principal, login, recoveryCodes, mfaSecret };
}
