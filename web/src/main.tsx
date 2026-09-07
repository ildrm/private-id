import { StrictMode, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, type User } from "./api";
import { Authentication, EmailVerification, Security } from "./account";
import { Overview, Credentials, Connections, Proofs, Billing } from "./wallet";
import { Issuers, Verifiers, Organizations } from "./workspaces";
import { Customers, AuditLog, BillingOperations, Operations } from "./admin";
import "./styles.css";
const initialFragment = new URLSearchParams(window.location.hash.slice(1));
const initialChallenge = {
  resetToken: initialFragment.get("reset") ?? undefined,
  verifyToken: initialFragment.get("verify") ?? undefined,
};
if (initialFragment.has("verify") || initialFragment.has("reset"))
  history.replaceState(
    null,
    "",
    window.location.pathname + window.location.search,
  );
const authorization = new URLSearchParams(window.location.search);
function App() {
  const [challenge, setChallenge] = useState(initialChallenge),
    { resetToken, verifyToken } = challenge;
  const [user, setUser] = useState<User>(),
    [loading, setLoading] = useState(true),
    [message, setMessage] = useState(""),
    [error, setError] = useState(""),
    [tab, setTab] = useState(
      authorization.has("client_id") ? "proofs" : "overview",
    ),
    [mode, setMode] = useState(""),
    main = useRef<HTMLElement>(null);
  const previousTab = useRef(tab);
  const signedOut = () => {
    setUser(undefined);
    setTab("overview");
  };
  const reloadUser = () => {
    api<User>("/auth/me")
      .then(setUser)
      .catch(() => signedOut());
  };
  useEffect(() => {
    let mounted = true;
    api<{ mode: string }>("/configuration")
      .then((x) => {
        if (mounted) setMode(x.mode);
      })
      .catch(() => {});
    api<User>("/auth/me")
      .then((value) => {
        if (mounted && !resetToken) setUser(value);
      })
      .catch(() => {})
      .finally(() => {
        if (mounted) setLoading(false);
      });
    const readChallenge = () => {
      const fragment = new URLSearchParams(location.hash.slice(1));
      if (!fragment.has("verify") && !fragment.has("reset")) return;
      const next = {
        resetToken: fragment.get("reset") ?? undefined,
        verifyToken: fragment.get("verify") ?? undefined,
      };
      history.replaceState(null, "", location.pathname + location.search);
      setChallenge(next);
      setMessage("");
      setError("");
      if (next.resetToken) setUser(undefined);
    };
    window.addEventListener("hashchange", readChallenge);
    window.addEventListener("privateid:expired", signedOut);
    return () => {
      mounted = false;
      window.removeEventListener("privateid:expired", signedOut);
      window.removeEventListener("hashchange", readChallenge);
    };
  }, []);
  useEffect(() => {
    if (previousTab.current !== tab) main.current?.focus();
    previousTab.current = tab;
    document.title = `${tab === "overview" ? "Wallet" : tab.charAt(0).toUpperCase() + tab.slice(1)} · PrivateID`;
  }, [tab]);
  const tabs = [
    ["overview", "Overview"],
    ["credentials", "Credentials"],
    ["proofs", "Proofs & consent"],
    ["connections", "Connected apps"],
    ["security", "Security"],
    ["billing", "Billing"],
    ["issuers", "Issuer workspace"],
    ["verifiers", "Verifier workspace"],
    ["organizations", "Organization"],
  ];
  if (user?.roles.some((r) => ["IDENTITY_ADMIN", "SECURITY_ADMIN"].includes(r)))
    tabs.push(["operations", "Operations"], ["customers", "Accounts"]);
  if (user?.roles.includes("SECURITY_ADMIN"))
    tabs.push(["audit", "Audit"], ["events", "Billing events"]);
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header>
        <a href="/site/" className="brand">
          <span aria-hidden="true">◈</span> PrivateID
        </a>
        <span className="brand-note">Identity with consent</span>
        {user && (
          <div className="account-menu">
            <span>{user.email}</span>
            <button
              onClick={async () => {
                try {
                  await api("/auth/logout", "POST", {});
                  signedOut();
                } catch (error) {
                  setError(
                    error instanceof Error ? error.message : "Sign out failed",
                  );
                }
              }}
            >
              Sign out
            </button>
          </div>
        )}
      </header>
      {mode && mode !== "production" && (
        <div className="environment">
          Development environment · synthetic credentials have no real-world
          assurance.
        </div>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className={user && user.emailVerified ? "layout" : "entry-layout"}>
        {user?.emailVerified && (
          <aside>
            <nav aria-label="Workspace">
              {tabs.map(([id, title]) => (
                <button
                  key={id}
                  aria-current={tab === id ? "page" : undefined}
                  onClick={() => setTab(id)}
                >
                  {title}
                </button>
              ))}
            </nav>
            <div className="account-id">
              <small>Your account ID</small>
              <p>{user.id}</p>
            </div>
          </aside>
        )}
        <main id="main" ref={main} tabIndex={-1}>
          {verifyToken && !message && (
            <section className="panel">
              <h1>Confirm email ownership</h1>
              <p>
                Complete verification for the account that requested this link.
              </p>
              <button
                onClick={async () => {
                  try {
                    await api("/auth/verify-email", "POST", {
                      token: verifyToken,
                    });
                    setMessage("Email verified. You can sign in now.");
                    reloadUser();
                  } catch (error) {
                    setError(
                      error instanceof Error
                        ? error.message
                        : "Verification failed",
                    );
                  }
                }}
              >
                Verify email address
              </button>
            </section>
          )}
          {loading ? (
            <p role="status">Loading your account…</p>
          ) : !user ? (
            <Authentication
              key={resetToken ?? "login"}
              onLogin={setUser}
              resetToken={resetToken}
              verifiedMessage={message}
            />
          ) : !user.emailVerified ? (
            <EmailVerification user={user} reload={reloadUser} />
          ) : (
            <div key={tab}>
              {tab === "overview" && <Overview />}
              {tab === "credentials" && <Credentials />}
              {tab === "proofs" && (
                <Proofs
                  authorization={
                    authorization.has("client_id") ? authorization : undefined
                  }
                />
              )}
              {tab === "connections" && <Connections />}
              {tab === "security" && (
                <Security
                  user={user}
                  reloadUser={reloadUser}
                  signedOut={signedOut}
                />
              )}
              {tab === "billing" && <Billing />}
              {tab === "issuers" && <Issuers user={user} />}
              {tab === "verifiers" && <Verifiers user={user} />}
              {tab === "organizations" && <Organizations />}
              {tab === "operations" && <Operations />}
              {tab === "customers" && <Customers user={user} />}
              {tab === "audit" && <AuditLog />}
              {tab === "events" && <BillingOperations />}
            </div>
          )}
        </main>
      </div>
      <footer>
        <span>PrivateID · Share only what is needed.</span>
        <a href="/openapi.json">API reference</a>
      </footer>
    </>
  );
}
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
