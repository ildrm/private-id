import { useState } from "react";
import {
  api,
  useResource,
  text,
  date,
  money,
  claimLabels,
  type Credential,
  type Request,
  type Preview,
  type Dashboard,
  type Connection,
  type Plan,
  type Subscription,
} from "./api";
import {
  Action,
  Badge,
  Claims,
  ClaimSelection,
  Collection,
  Field,
  Form,
  Secret,
  Status,
} from "./components";
export function Overview() {
  const resource = useResource<Dashboard>("/privacy-dashboard");
  return (
    <>
      <h1>Your identity wallet</h1>
      <p>
        Review credentials, choose what to disclose, and control connected
        access.
      </p>
      <Status {...resource} />
      {resource.data && (
        <>
          <div className="stats">
            <article>
              <span>Plan</span>
              <strong>{resource.data.plan.name}</strong>
            </article>
            <article>
              <span>Monthly proofs</span>
              <strong>
                {resource.data.usage.proofs} /{" "}
                {resource.data.plan.limits.proofs}
              </strong>
            </article>
            <article>
              <span>Active credentials</span>
              <strong>
                {resource.data.usage.credentials} /{" "}
                {resource.data.plan.limits.credentials}
              </strong>
            </article>
            <article>
              <span>Connected applications</span>
              <strong>
                {resource.data.usage.connections} /{" "}
                {resource.data.plan.limits.connections}
              </strong>
            </article>
          </div>
          <section className="panel">
            <h2>Consent activity</h2>
            <p>
              {resource.data.counts.pendingRequests} pending ·{" "}
              {resource.data.counts.approvedRequests} issued ·{" "}
              {resource.data.counts.disclosures} redeemed
            </p>
            <p className="muted">
              Proof allowance resets each UTC calendar month. A claim can be Yes
              or No; an unavailable or conflicting claim prevents issuance.
            </p>
          </section>
        </>
      )}
    </>
  );
}
export function Credentials() {
  return (
    <>
      <h1>Credentials</h1>
      <p>
        Only current evidence from a reviewed issuer can support a proof. Raw
        evidence is kept outside this wallet; the platform stores an encrypted
        reference.
      </p>
      <Collection<Credential>
        path="/credentials"
        empty="No credentials yet. A reviewed issuer can issue one to your account ID."
      >
        {(credential) => (
          <>
            <h2>
              {credential.type} <Badge>{credential.status}</Badge>
            </h2>
            <Claims values={credential.claims} />
            <p>
              Assurance: {credential.assuranceLevel} · expires{" "}
              {date(credential.expiresAt)}
            </p>
            <p className="muted break">
              Issuer: {credential.issuerId} · credential: {credential.id}
            </p>
            {credential.revocationReason && (
              <p>Reason: {credential.revocationReason}</p>
            )}
          </>
        )}
      </Collection>
    </>
  );
}
export function Connections() {
  return (
    <>
      <h1>Connected applications</h1>
      <p>
        Revoking access invalidates outstanding proofs and prevents new
        requests. Restoring access requires new consent and never revives an old
        proof.
      </p>
      <Collection<Connection>
        path="/connections"
        empty="You have not approved a connection yet."
      >
        {(connection, reload) => (
          <>
            <h2>
              {connection.clientId} <Badge>{connection.status}</Badge>
            </h2>
            <p>
              Shared claim names:{" "}
              {connection.shared.map((c) => claimLabels[c]).join(", ")}
            </p>
            <p>Last approved {date(connection.lastProofAt)}</p>
            <Action
              label={
                connection.status === "ACTIVE"
                  ? "Revoke application access"
                  : "Restore for new requests"
              }
              path={`/connections/${encodeURIComponent(connection.clientId)}${connection.status === "ACTIVE" ? "" : "/restore"}`}
              method={connection.status === "ACTIVE" ? "DELETE" : "POST"}
              done={reload}
            />
          </>
        )}
      </Collection>
    </>
  );
}
function Consent({ request, done }: { request: Request; done: () => void }) {
  const resource = useResource<Preview>(
      `/proof-requests/${request.id}/preview`,
    ),
    [proof, setProof] = useState<string>();
  return (
    <section className="consent" aria-label="Review requested disclosure">
      <h2>{request.clientName} requests your consent</h2>
      <p>{request.purpose}</p>
      <p>
        Requested:{" "}
        {request.requestedClaims.map((c) => claimLabels[c]).join(", ")}
      </p>
      <Status {...resource} />
      {resource.data && (
        <>
          <h3>Exactly what will be shared</h3>
          <Claims values={resource.data.claims} />
          <p>
            A pairwise subject identifies you only to this application. The
            proof expires by {date(resource.data.expiresAt)}. Revocation
            prevents future use; it cannot erase claims already received by the
            application.
          </p>
          <Form
            submit="Approve these values"
            onSubmit={async () => {
              const result = await api<{
                proof?: string;
                redirectUrl?: string;
              }>(`/proof-requests/${request.id}/approve`, "POST", {
                previewHash: resource.data!.previewHash,
              });
              if (result.redirectUrl)
                window.location.assign(result.redirectUrl);
              else if (result.proof) setProof(result.proof);
              else done();
            }}
          />
        </>
      )}
      {!proof && (
        <Form
          submit="Deny request"
          onSubmit={async () => {
            const result = await api<{ redirectUrl?: string }>(
              `/proof-requests/${request.id}/deny`,
              "POST",
              {},
            );
            if (result.redirectUrl) window.location.assign(result.redirectUrl);
            else done();
          }}
        />
      )}{" "}
      {proof && (
        <>
          <Secret title="One-time proof for your verifier" value={proof} />
          <button onClick={done}>Done</button>
        </>
      )}
    </section>
  );
}
export function Proofs({ authorization }: { authorization?: URLSearchParams }) {
  const [request, setRequest] = useState<Request>(),
    [version, setVersion] = useState(0);
  if (request)
    return (
      <Consent
        key={request.id}
        request={request}
        done={() => {
          setRequest(undefined);
          setVersion((v) => v + 1);
        }}
      />
    );
  return (
    <>
      <h1>Proofs and consent</h1>
      <p>
        Approve a minimal set of claims for a reviewed verifier. Each approval
        counts toward your monthly allowance.
      </p>
      <section className="panel">
        <h2>
          {authorization?.get("client_id")
            ? "Application sign-in request"
            : "Prepare a proof"}
        </h2>
        <Form
          submit="Review disclosure"
          onSubmit={async (form) => {
            const claims =
              authorization?.get("scope")?.split(" ").filter(Boolean) ??
              form.getAll("claims").map(String);
            setRequest(
              await api("/proof-requests", "POST", {
                clientId:
                  authorization?.get("client_id") ?? text(form, "clientId"),
                requestedClaims: claims,
                ...(authorization?.get("client_id")
                  ? {
                      redirectUri:
                        authorization.get("redirect_uri") ?? undefined,
                      state: authorization.get("state") ?? undefined,
                      nonce: authorization.get("nonce") ?? undefined,
                      codeChallenge:
                        authorization.get("code_challenge") ?? undefined,
                    }
                  : {}),
              }),
            );
          }}
        >
          {authorization?.get("client_id") ? (
            <>
              <p>
                Application: <strong>{authorization.get("client_id")}</strong>
              </p>
              <p>
                The next step shows the reviewed purpose and exact values.
                Nothing is shared until approval.
              </p>
            </>
          ) : (
            <>
              <Field
                label="Reviewed verifier client ID"
                name="clientId"
                required
                minLength={3}
                maxLength={60}
                placeholder="example-verifier"
              />
              <ClaimSelection selected={["account_valid"]} />
            </>
          )}
        </Form>
      </section>
      <h2>Consent history</h2>
      <Collection<Request>
        key={version}
        path="/proof-requests"
        empty="No requests yet."
      >
        {(row) => (
          <>
            <h3>
              {row.clientName} <Badge>{row.status}</Badge>
            </h3>
            <p>{row.requestedClaims.map((c) => claimLabels[c]).join(", ")}</p>
            <p>
              {date(row.createdAt)} · {row.purpose}
            </p>
            {row.status === "PENDING" && (
              <button onClick={() => setRequest(row)}>Review request</button>
            )}
          </>
        )}
      </Collection>
    </>
  );
}
export function Billing() {
  const plans = useResource<Plan[]>("/billing/plans"),
    subscription = useResource<Subscription>("/billing/subscription");
  return (
    <>
      <h1>Billing and plans</h1>
      <Status {...subscription} />
      {subscription.data && (
        <section className="panel">
          <h2>Current access: {subscription.data.planId}</h2>
          <p>
            Status: {subscription.data.status}
            {subscription.data.currentPeriodEnd
              ? ` · current period ends ${date(subscription.data.currentPeriodEnd)}`
              : ""}
            {subscription.data.cancelAtPeriodEnd
              ? " · cancellation scheduled"
              : ""}
          </p>
          <div className="actions">
            <Form
              submit="Open billing portal"
              onSubmit={async () => {
                const result = await api<{ url: string }>(
                  "/billing/portal",
                  "POST",
                  {},
                );
                window.location.assign(result.url);
              }}
            />
            <Action
              label="Refresh payment status"
              path="/billing/reconcile"
              done={subscription.reload}
            />
          </div>
          <p className="muted">
            Manage changes, cancellation, and payment methods in the portal.
            Access follows active, unexpired subscriptions. A checkout return
            alone does not activate a plan.
          </p>
        </section>
      )}
      <Status {...plans} />
      <div className="plan-grid">
        {plans.data?.map((plan) => (
          <article className="panel" key={plan.id}>
            <h2>{plan.name}</h2>
            <p className="price">
              {money(plan.priceMonthly, plan.currency)}
              <span> / month</span>
            </p>
            <ul>
              {plan.features.map((feature) => (
                <li key={feature}>{feature}</li>
              ))}
            </ul>
            {plan.priceMonthly > 0 &&
              (plan.checkoutEnabled ? (
                <Form
                  submit={`Choose ${plan.name}`}
                  onSubmit={async () => {
                    const result = await api<{
                      url?: string;
                      message?: string;
                    }>("/billing/checkout", "POST", { planId: plan.id });
                    if (result.url) window.location.assign(result.url);
                    return result.message;
                  }}
                />
              ) : (
                <p>Paid checkout is unavailable on this deployment.</p>
              ))}
          </article>
        ))}
      </div>
      <h2>Invoices</h2>
      <Collection<{
        id: string;
        amountPaid: number;
        amountDue: number;
        currency: string;
        status: string;
        createdAt: string;
      }>
        path="/billing/invoices"
        empty="No invoices yet."
      >
        {(invoice) => (
          <>
            <h3>
              {money(invoice.amountPaid, invoice.currency)} paid{" "}
              <Badge>{invoice.status}</Badge>
            </h3>
            <p>
              {money(invoice.amountDue, invoice.currency)} due ·{" "}
              {date(invoice.createdAt)}
            </p>
            <p className="muted break">{invoice.id}</p>
          </>
        )}
      </Collection>
    </>
  );
}
