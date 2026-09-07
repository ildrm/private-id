import {
  api,
  date,
  text,
  money,
  useResource,
  type User,
  type Audit,
} from "./api";
import {
  Badge,
  Collection,
  Form,
  LongText,
  Select,
  Action,
  Status,
} from "./components";
export function Customers({ user }: { user: User }) {
  return (
    <>
      <h1>Account administration</h1>
      <p>
        Staff authority is separate from subscription plans. Sensitive changes
        require a reason and are recorded in the audit trail.
      </p>
      <Collection<User> path="/admin/customers">
        {(customer, reload) => (
          <>
            <h2>
              {customer.email} <Badge>{customer.status}</Badge>
            </h2>
            <p>
              {customer.roles.join(", ")} · email{" "}
              {customer.emailVerified ? "verified" : "unverified"} · MFA{" "}
              {customer.mfaEnabled ? "enabled" : "disabled"}
            </p>
            <p className="break">Account ID: {customer.id}</p>
            {customer.id !== user.id &&
              ["ACTIVE", "SUSPENDED"].includes(customer.status) && (
                <Form
                  submit="Update account status"
                  onSubmit={async (form) => {
                    await api(`/admin/customers/${customer.id}/status`, "PUT", {
                      status: text(form, "status"),
                      reason: text(form, "reason"),
                    });
                    reload();
                  }}
                >
                  <Select
                    label="Account status"
                    name="status"
                    defaultValue={customer.status}
                  >
                    <option>ACTIVE</option>
                    <option>SUSPENDED</option>
                  </Select>
                  <LongText label="Reason for changing status" name="reason" />
                </Form>
              )}
            {user.roles.includes("SECURITY_ADMIN") &&
              customer.status === "ACTIVE" && (
                <details>
                  <summary>Change staff roles</summary>
                  <Form
                    submit="Apply roles and revoke sessions"
                    onSubmit={async (form) => {
                      await api(
                        `/admin/customers/${customer.id}/roles`,
                        "PUT",
                        {
                          roles: form.getAll("roles"),
                          reason: text(form, "reason"),
                        },
                      );
                      reload();
                    }}
                  >
                    <fieldset className="claim-options">
                      <legend>Roles</legend>
                      {[
                        "USER",
                        "ISSUER_ADMIN",
                        "VERIFIER_ADMIN",
                        "IDENTITY_ADMIN",
                        "SECURITY_ADMIN",
                      ].map((role) => (
                        <label key={role}>
                          <input
                            type="checkbox"
                            name="roles"
                            value={role}
                            defaultChecked={customer.roles.includes(
                              role as User["roles"][number],
                            )}
                          />
                          {role}
                        </label>
                      ))}
                    </fieldset>
                    <LongText label="Reason for role change" name="reason" />
                  </Form>
                </details>
              )}
          </>
        )}
      </Collection>
    </>
  );
}
export function AuditLog() {
  return (
    <>
      <h1>Security audit</h1>
      <p>
        Append-only events show sensitive changes and rejected operations.
        Pagination keeps exports bounded; operational retention uses a separate
        database role.
      </p>
      <Collection<Audit> path="/audit">
        {(event) => (
          <>
            <h2>
              {event.event} <Badge>{event.outcome}</Badge>
            </h2>
            <p>{date(event.createdAt)}</p>
            <p className="break">
              Actor {event.actorId ?? "system"} · target{" "}
              {event.targetId ?? "none"}
            </p>
            <dl>
              {Object.entries(event.metadata).map(([key, value]) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd className="break">
                    {Array.isArray(value) ? value.join(", ") : String(value)}
                  </dd>
                </div>
              ))}
            </dl>
          </>
        )}
      </Collection>
    </>
  );
}
export function BillingOperations() {
  return (
    <>
      <h1>Billing event operations</h1>
      <p>
        Failures remain durable and retry with backoff. Correct the underlying
        mapping, provider, or database problem before manually retrying
        exhausted events.
      </p>
      <Collection<{
        id: string;
        type: string;
        status: string;
        attempts: number;
        error?: string;
        nextAttemptAt: string;
      }> path="/admin/billing/events">
        {(event, reload) => (
          <>
            <h2>
              {event.type} <Badge>{event.status}</Badge>
            </h2>
            <p className="break">{event.id}</p>
            <p>
              Attempts: {event.attempts} · next attempt{" "}
              {date(event.nextAttemptAt)} {event.error}
            </p>
            {["PENDING", "FAILED"].includes(event.status) && (
              <Action
                label="Queue retry"
                path={`/admin/billing/events/${encodeURIComponent(event.id)}/retry`}
                done={reload}
              />
            )}
          </>
        )}
      </Collection>
    </>
  );
}

export function Operations() {
  const resource = useResource<{
    accounts: number;
    credentials: number;
    pendingIssuers: number;
    pendingVerifiers: number;
    failedMail: number;
    workerUpdatedAt?: string;
    billing: {
      pendingEvents: number;
      failedEvents: number;
      definition: string;
      currencies: {
        currency: string;
        grossPaid: number;
        refunded: number;
        disputed: number;
      }[];
    };
  }>("/admin/overview");
  return (
    <>
      <h1>Operations</h1>
      <Status {...resource} />
      {resource.data && (
        <>
          <div className="stats">
            <article>
              <span>Accounts</span>
              <strong>{resource.data.accounts}</strong>
            </article>
            <article>
              <span>Pending issuer reviews</span>
              <strong>{resource.data.pendingIssuers}</strong>
            </article>
            <article>
              <span>Pending verifier reviews</span>
              <strong>{resource.data.pendingVerifiers}</strong>
            </article>
            <article>
              <span>Failed mail deliveries</span>
              <strong>{resource.data.failedMail}</strong>
            </article>
          </div>
          <section className="panel">
            <h2>Background processing</h2>
            <p>
              Last worker tick:{" "}
              {resource.data.workerUpdatedAt
                ? date(resource.data.workerUpdatedAt)
                : "No heartbeat recorded"}
            </p>
            <p>
              Billing receipts: {resource.data.billing.pendingEvents} pending ·{" "}
              {resource.data.billing.failedEvents} failed
            </p>
          </section>
          <section className="panel">
            <h2>Payment totals</h2>
            <p>{resource.data.billing.definition}</p>
            {resource.data.billing.currencies.map((value) => (
              <article key={value.currency}>
                <h3>{value.currency}</h3>
                <p>
                  Gross paid {money(value.grossPaid, value.currency)} · refunded{" "}
                  {money(value.refunded, value.currency)} · disputed{" "}
                  {money(value.disputed, value.currency)}
                </p>
              </article>
            ))}
          </section>
          <button onClick={resource.reload}>Refresh operations</button>
        </>
      )}
    </>
  );
}
