import { useState } from "react";
import { api, useResource, text, optional, date, type User } from "./api";
import { Action, Field, Form, Secret, Status, Badge } from "./components";
export function Authentication({
  onLogin,
  resetToken,
  verifiedMessage,
}: {
  onLogin: (user: User) => void;
  resetToken?: string;
  verifiedMessage?: string;
}) {
  const [mode, setMode] = useState<"login" | "register" | "forgot" | "reset">(
      resetToken ? "reset" : "login",
    ),
    [registered, setRegistered] = useState(false);
  return (
    <section className="auth-card">
      <p className="eyebrow">Your identity. Your decision.</p>
      <h1>
        {mode === "login"
          ? "Welcome to PrivateID"
          : mode === "register"
            ? "Create your account"
            : mode === "reset"
              ? "Choose a new password"
              : "Recover your account"}
      </h1>
      <p>
        Keep credentials in one place and choose exactly which claims you share
        with reviewed applications.
      </p>
      {verifiedMessage && (
        <p className="notice" role="status">
          {verifiedMessage}
        </p>
      )}
      {registered && (
        <p className="notice" role="status">
          Account created. Check your email for the verification link, then sign
          in.
        </p>
      )}
      <Form
        key={mode}
        submit={
          mode === "login"
            ? "Sign in"
            : mode === "register"
              ? "Create account"
              : mode === "reset"
                ? "Reset password"
                : "Send reset link"
        }
        onSubmit={async (form) => {
          if (mode === "register") {
            await api("/accounts", "POST", {
              email: text(form, "email"),
              password: String(form.get("password")),
            });
            setRegistered(true);
            setMode("login");
          }
          if (mode === "login") {
            const result = await api<{ user: User }>("/auth/login", "POST", {
              email: text(form, "email"),
              password: String(form.get("password")),
              code: optional(form, "code"),
              device: navigator.userAgent.slice(0, 160),
            });
            onLogin(result.user);
          }
          if (mode === "forgot")
            return (
              await api<{ message: string }>("/auth/forgot-password", "POST", {
                email: text(form, "email"),
              })
            ).message;
          if (mode === "reset") {
            await api("/auth/reset-password", "POST", {
              token: resetToken,
              password: String(form.get("password")),
              code: optional(form, "code"),
            });
            setMode("login");
            return "Password reset. Sign in with the new password.";
          }
        }}
      >
        {mode !== "reset" && (
          <Field
            label="Email address"
            name="email"
            type="email"
            autoComplete="email"
            required
            maxLength={254}
          />
        )}
        {mode !== "forgot" && (
          <Field
            label="Password"
            name="password"
            type="password"
            autoComplete={
              mode === "login" ? "current-password" : "new-password"
            }
            minLength={mode === "login" ? 1 : 12}
            maxLength={128}
            required
            hint={
              mode === "login"
                ? undefined
                : "Use a unique passphrase of 12–128 characters."
            }
          />
        )}
        {(mode === "login" || mode === "reset") && (
          <Field
            label="Authenticator or recovery code (if enabled)"
            name="code"
            autoComplete="one-time-code"
            maxLength={100}
          />
        )}
        {mode === "register" && (
          <p className="muted">
            Email verification confirms mailbox ownership. Identity and
            eligibility claims require separate evidence from a reviewed issuer.
          </p>
        )}
      </Form>
      <nav aria-label="Account entry">
        <button onClick={() => setMode("login")}>Sign in</button>
        <button onClick={() => setMode("register")}>Create account</button>
        <button onClick={() => setMode("forgot")}>Forgot password</button>
      </nav>
    </section>
  );
}
export function EmailVerification({
  user,
  reload,
}: {
  user: User;
  reload: () => void;
}) {
  return (
    <section className="panel">
      <h1>Verify your email</h1>
      <p>
        Open the link sent to {user.email} to activate your wallet. Verification
        links expire after 30 minutes.
      </p>
      <Action
        label="Send a new verification link"
        path="/auth/resend-verification"
        body={{ email: user.email }}
      />
      <button onClick={reload}>I’ve verified my email</button>
    </section>
  );
}
export function Security({
  user,
  reloadUser,
  signedOut,
}: {
  user: User;
  reloadUser: () => void;
  signedOut: () => void;
}) {
  const sessions = useResource<
      {
        id: string;
        device: string;
        createdAt: string;
        expiresAt: string;
        lastSeenAt: string;
        current: boolean;
      }[]
    >("/sessions"),
    [enrollment, setEnrollment] = useState<{ secret: string; uri: string }>(),
    [recovery, setRecovery] = useState<string[]>(),
    [deleting, setDeleting] = useState(false);
  return (
    <>
      <h1>Account security</h1>
      <section className="panel">
        <h2>
          Authenticator protection{" "}
          <Badge>{user.mfaEnabled ? "Enabled" : "Not enabled"}</Badge>
        </h2>
        <p>
          Required for staff and issuer or verifier management. Recovery codes
          work once; keep them somewhere you can access if you lose your
          authenticator.
        </p>
        {!user.mfaEnabled && !enrollment && (
          <Form
            submit="Set up authenticator"
            onSubmit={async (form) => {
              setEnrollment(
                await api("/auth/mfa/setup", "POST", {
                  password: String(form.get("password")),
                }),
              );
            }}
          >
            <Field
              label="Current password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              maxLength={128}
            />
          </Form>
        )}
        {enrollment && (
          <>
            <Secret title="Authenticator setup key" value={enrollment.secret} />
            <p>
              In your authenticator, add this key as a time-based account named
              PrivateID. Setup expires after ten minutes.
            </p>
            <Form
              submit="Confirm authenticator"
              onSubmit={async (form) => {
                const result = await api<{ recoveryCodes: string[] }>(
                  "/auth/mfa/confirm",
                  "POST",
                  { code: text(form, "code") },
                );
                setRecovery(result.recoveryCodes);
                setEnrollment(undefined);
                reloadUser();
              }}
            >
              <Field
                label="Six-digit authenticator code"
                name="code"
                inputMode="numeric"
                pattern="[0-9]{6}"
                autoComplete="one-time-code"
                required
              />
            </Form>
          </>
        )}
        {recovery && (
          <Secret
            title="Single-use recovery codes"
            value={recovery.join("\n")}
          />
        )}
      </section>
      <section className="panel">
        <h2>Sessions</h2>
        <Status {...sessions} />
        {sessions.data?.map((session) => (
          <article className="record" key={session.id}>
            <h3>{session.current ? "This session" : "Other session"}</h3>
            <p className="break">{session.device}</p>
            <p>
              Last active {date(session.lastSeenAt)} · expires{" "}
              {date(session.expiresAt)}
            </p>
            <Action
              label={
                session.current ? "Sign out this session" : "Revoke session"
              }
              path={`/sessions/${session.id}`}
              method="DELETE"
              done={session.current ? signedOut : sessions.reload}
            />
          </article>
        ))}
      </section>
      <section className="panel">
        <h2>Change password</h2>
        <p>
          Changing your password signs out every session. Use a fresh
          authenticator code if you just signed in.
        </p>
        <Form
          submit="Change password and sign out"
          onSubmit={async (form) => {
            await api("/auth/password", "POST", {
              currentPassword: String(form.get("currentPassword")),
              password: String(form.get("password")),
              code: optional(form, "code"),
            });
            signedOut();
          }}
        >
          <Field
            label="Current password"
            name="currentPassword"
            type="password"
            autoComplete="current-password"
            required
            maxLength={128}
          />
          <Field
            label="New password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            minLength={12}
            maxLength={128}
          />
          {user.mfaEnabled && (
            <Field
              label="Fresh authenticator or recovery code"
              name="code"
              autoComplete="one-time-code"
              required
            />
          )}
        </Form>
      </section>
      <section className="panel danger-zone">
        <h2>Delete account</h2>
        <p>
          Access and outstanding proofs are revoked immediately. After a
          five-minute safety delay, background jobs cancel open checkout
          sessions and subscriptions, erase your account details, and retry
          failed cancellations. Pseudonymous accounting references remain for
          730 days; security audits follow the deployment’s retention policy.
          Claims already shared with another application cannot be recalled.
        </p>
        <p>
          Transfer or close owned workspaces first. Security administrators must
          transfer responsibility and remove their staff role before deletion.
        </p>
        {!deleting ? (
          <button className="danger" onClick={() => setDeleting(true)}>
            Start account deletion
          </button>
        ) : (
          <Form
            submit="Permanently request deletion"
            danger
            onSubmit={async (form) => {
              if (text(form, "confirm") !== "DELETE")
                throw new Error("Type DELETE to confirm.");
              await api("/accounts/me", "DELETE", {
                password: String(form.get("password")),
                code: optional(form, "code"),
              });
              signedOut();
            }}
          >
            <Field label="Type DELETE to confirm" name="confirm" required />
            <Field
              label="Current password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
            {user.mfaEnabled && (
              <Field
                label="Fresh authenticator or recovery code"
                name="code"
                required
                autoComplete="one-time-code"
              />
            )}
          </Form>
        )}
      </section>
    </>
  );
}
