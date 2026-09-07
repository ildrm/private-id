import { useState } from "react";
import {
  api,
  useResource,
  text,
  optional,
  claimLabels,
  date,
  type Claim,
  type Issuer,
  type Verifier,
  type Organization,
  type Credential,
  type Audit,
  type User,
} from "./api";
import {
  Action,
  Badge,
  Claims,
  ClaimSelection,
  Collection,
  Field,
  Form,
  LongText,
  Secret,
  Select,
  Status,
} from "./components";
function Assurance() {
  return (
    <Select name="assuranceLevel" label="Assurance level" defaultValue="LOW">
      <option>LOW</option>
      <option>SUBSTANTIAL</option>
      <option>HIGH</option>
    </Select>
  );
}
function Reason({
  action,
  path,
  statuses,
  done,
}: {
  action: string;
  path: string;
  statuses: string[];
  done: () => void;
}) {
  return (
    <details>
      <summary>{action}</summary>
      <Form
        submit="Save review decision"
        onSubmit={async (form) => {
          await api(path, "PUT", {
            status: text(form, "status"),
            reason: text(form, "reason"),
          });
          done();
        }}
      >
        <Select name="status" label="Decision">
          {statuses.map((status) => (
            <option key={status}>{status}</option>
          ))}
        </Select>
        <LongText label="Evidence and reason for this decision" name="reason" />
      </Form>
    </details>
  );
}
export function Issuers({ user }: { user: User }) {
  const [scope, setScope] = useState(""),
    organizations = useResource<Organization[]>("/organizations");
  const [version, setVersion] = useState(0),
    [issuer, setIssuer] = useState<Issuer>();
  return (
    <>
      <h1>Issuer workspace</h1>
      <p>
        Enrollment requires MFA and independent identity or security review. A
        policy and evidence reference document an assertion; the platform does
        not perform KYC, uniqueness checks, or eligibility investigations
        itself.
      </p>
      <details className="panel">
        <summary>Submit an issuer identity</summary>
        <Form
          submit="Submit for review"
          onSubmit={async (form) => {
            await api("/issuers", "POST", {
              issuerName: text(form, "issuerName"),
              organizationId: optional(form, "organizationId"),
              jurisdiction: text(form, "jurisdiction").toUpperCase(),
              supportedClaims: form.getAll("claims"),
              assuranceLevel: text(form, "assuranceLevel"),
              policy: text(form, "policy"),
            });
            setVersion((v) => v + 1);
          }}
        >
          <Field
            label="Issuer name"
            name="issuerName"
            required
            minLength={2}
            maxLength={120}
          />
          <Field label="Organization ID (optional)" name="organizationId" />
          <Field
            label="Jurisdiction (two-letter code)"
            name="jurisdiction"
            required
            pattern="[A-Za-z]{2}"
            maxLength={2}
          />
          <Assurance />
          <ClaimSelection />
          <LongText
            label="Evidence policy, procedure, and freshness requirements"
            name="policy"
            hint="Describe how your organization verifies each claim and handles revocation. Do not paste personal evidence here."
          />
        </Form>
      </details>
      <label>
        Workspace scope{" "}
        <select
          value={scope}
          onChange={(event) => {
            setScope(event.target.value);
            setIssuer(undefined);
          }}
        >
          <option value="">My issuers / staff review queue</option>
          {organizations.data
            ?.filter((org) => ["OWNER", "ISSUER"].includes(org.role))
            .map((org) => (
              <option key={org.id} value={org.id}>
                {org.name}
              </option>
            ))}
        </select>
      </label>
      <Collection<Issuer>
        key={`${version}:${scope}`}
        path={`/issuers${scope ? `?organizationId=${scope}` : ""}`}
        empty="No issuer submissions yet."
      >
        {(row, reload) => (
          <>
            <h2>
              {row.issuerName} <Badge>{row.status}</Badge>
            </h2>
            <p>{row.policy}</p>
            <p>
              {row.supportedClaims.map((c) => claimLabels[c]).join(", ")} ·{" "}
              {row.assuranceLevel}
            </p>
            <p className="muted break">Issuer ID: {row.id}</p>
            {(row.ownerId === user.id || row.organizationId) && (
              <button onClick={() => setIssuer(row)}>
                Open issuing workspace
              </button>
            )}
            {user.roles.some((r) =>
              ["IDENTITY_ADMIN", "SECURITY_ADMIN"].includes(r),
            ) &&
              row.ownerId !== user.id &&
              row.status !== "REVOKED" && (
                <Reason
                  action="Review issuer"
                  path={`/issuers/${row.id}/review`}
                  statuses={["TRUSTED", "SUSPENDED", "REVOKED"]}
                  done={reload}
                />
              )}
          </>
        )}
      </Collection>
      {issuer && (
        <section className="panel">
          <h2>Issue with {issuer.issuerName}</h2>
          <Form
            submit="Issue credential"
            onSubmit={async (form) => {
              const name = text(form, "claim") as Claim,
                value =
                  name === "jurisdiction"
                    ? text(form, "jurisdiction").toUpperCase()
                    : text(form, "value") === "true";
              await api("/credentials", "POST", {
                issuerId: issuer.id,
                userId: text(form, "userId"),
                type: text(form, "type"),
                claims: { [name]: value },
                birthDate: optional(form, "birthDate"),
                assuranceLevel: text(form, "assuranceLevel"),
                evidenceReference: text(form, "evidenceReference"),
                expiresInSeconds: Number(text(form, "days")) * 86400,
                supersedes: text(form, "supersedes")
                  .split(",")
                  .map((x) => x.trim())
                  .filter(Boolean),
              });
              setVersion((v) => v + 1);
              return "Credential issued. The customer can now review it in their wallet.";
            }}
          >
            <Field label="Customer account ID" name="userId" required />
            <Field
              label="Credential type"
              name="type"
              required
              maxLength={100}
            />
            <Select label="Claim" name="claim">
              {issuer.supportedClaims.map((name) => (
                <option key={name} value={name}>
                  {claimLabels[name]}
                </option>
              ))}
            </Select>
            <Select label="Boolean claim value" name="value">
              <option value="true">Yes</option>
              <option value="false">No</option>
            </Select>
            <Field
              label="Jurisdiction value (for jurisdiction claim)"
              name="jurisdiction"
              maxLength={2}
            />
            <Field
              label="Evidence-backed date of birth (for adult claim only)"
              name="birthDate"
              type="date"
              hint="Used to derive 18+ status and immediately discarded."
            />
            <Assurance />
            <Field
              label="Valid for days"
              name="days"
              type="number"
              min={1}
              max={365}
              defaultValue={30}
              required
            />
            <Field
              label="Evidence reference"
              name="evidenceReference"
              required
              minLength={10}
              maxLength={2000}
              hint="Use a reference to your controlled evidence store, never a document or full personal record."
            />
            <Field
              label="Credentials to supersede (comma-separated IDs, optional)"
              name="supersedes"
            />
          </Form>
          <h3>Issued credentials</h3>
          <Collection<Credential>
            key={`${issuer.id}:${version}`}
            path={`/issuers/${issuer.id}/credentials`}
          >
            {(credential, reload) => (
              <>
                <h3>
                  {credential.type} <Badge>{credential.status}</Badge>
                </h3>
                <Claims values={credential.claims} />
                <p className="break">
                  {credential.id} · subject {credential.userId}
                </p>
                {credential.status === "ACTIVE" && (
                  <Form
                    submit="Revoke credential"
                    danger
                    onSubmit={async (form) => {
                      await api(
                        `/credentials/${credential.id}/revoke`,
                        "POST",
                        { reason: text(form, "reason") },
                      );
                      reload();
                    }}
                  >
                    <Field
                      label="Revocation reason"
                      name="reason"
                      minLength={10}
                      maxLength={1000}
                      required
                    />
                  </Form>
                )}
              </>
            )}
          </Collection>
        </section>
      )}
    </>
  );
}
export function Verifiers({ user }: { user: User }) {
  const [scope, setScope] = useState(""),
    organizations = useResource<Organization[]>("/organizations");
  const [version, setVersion] = useState(0),
    [secret, setSecret] = useState<string>();
  const fields = (v?: Verifier) => (
    <>
      <Field
        label="Application name"
        name="name"
        defaultValue={v?.name}
        required
        minLength={2}
        maxLength={120}
      />
      <Field
        label="Exact redirect URL"
        name="redirectUri"
        type="url"
        defaultValue={v?.redirectUris[0]}
        required
        hint="HTTPS required in production. No query strings, fragments, or wildcards."
      />
      <Select
        label="Environment"
        name="environment"
        defaultValue={v?.environment ?? "SANDBOX"}
      >
        <option>SANDBOX</option>
        <option>PRODUCTION</option>
      </Select>
      <ClaimSelection selected={v?.allowedClaims} />
      <LongText
        label="Purpose shown to customers during consent"
        name="purpose"
        defaultValue={v?.purpose}
      />
    </>
  );
  const values = (form: FormData) => ({
    name: text(form, "name"),
    redirectUris: [text(form, "redirectUri")],
    allowedClaims: form.getAll("claims"),
    environment: text(form, "environment"),
    purpose: text(form, "purpose"),
  });
  return (
    <>
      <h1>Verifier workspace</h1>
      <p>
        Applications require independent identity review. Keep the client secret
        on your server. Use exact redirects, a fresh state and nonce, and S256
        PKCE for every authorization transaction.
      </p>
      <p>
        <a href="/openapi.json" target="_blank" rel="noreferrer">
          API contract
        </a>{" "}
        · See the integration guide in the repository for the complete client
        sequence.
      </p>
      {secret && <Secret title="Verifier client secret" value={secret} />}
      <details className="panel">
        <summary>Register an application</summary>
        <Form
          submit="Submit application"
          onSubmit={async (form) => {
            const result = await api<{ clientSecret: string }>(
              "/verifiers",
              "POST",
              {
                ...values(form),
                clientId: text(form, "clientId"),
                organizationId: optional(form, "organizationId"),
              },
            );
            setSecret(result.clientSecret);
            setVersion((v) => v + 1);
          }}
        >
          <Field
            label="Client ID"
            name="clientId"
            pattern="[a-z][a-z0-9-]{2,59}"
            required
          />
          <Field label="Organization ID (optional)" name="organizationId" />
          {fields()}
        </Form>
      </details>
      <label>
        Workspace scope{" "}
        <select
          value={scope}
          onChange={(event) => setScope(event.target.value)}
        >
          <option value="">My verifiers / staff review queue</option>
          {organizations.data
            ?.filter((org) => ["OWNER", "VERIFIER"].includes(org.role))
            .map((org) => (
              <option key={org.id} value={org.id}>
                {org.name}
              </option>
            ))}
        </select>
      </label>
      <Collection<Verifier>
        key={`${version}:${scope}`}
        path={`/verifiers${scope ? `?organizationId=${scope}` : ""}`}
        empty="No applications yet."
      >
        {(v, reload) => (
          <>
            <h2>
              {v.name} <Badge>{v.status}</Badge>
            </h2>
            <p>{v.purpose}</p>
            <p className="break">
              Client ID: {v.id} · {v.environment}
            </p>
            <p>{v.allowedClaims.map((c) => claimLabels[c]).join(", ")}</p>
            {v.redirectUris.map((uri) => (
              <p className="break" key={uri}>
                {uri}
              </p>
            ))}
            {(v.ownerId === user.id || !!scope) && (
              <>
                <Form
                  submit="Rotate client secret"
                  onSubmit={async () => {
                    const result = await api<{ clientSecret: string }>(
                      `/verifiers/${v.id}/rotate-secret`,
                      "POST",
                      {},
                    );
                    setSecret(result.clientSecret);
                    reload();
                  }}
                />
                {v.status !== "REVOKED" && (
                  <details>
                    <summary>Edit and request new review</summary>
                    <Form
                      submit="Save and submit for review"
                      onSubmit={async (form) => {
                        await api(`/verifiers/${v.id}`, "PUT", values(form));
                        reload();
                      }}
                    >
                      {fields(v)}
                    </Form>
                  </details>
                )}
              </>
            )}
            {user.roles.includes("IDENTITY_ADMIN") &&
              v.ownerId !== user.id &&
              v.status !== "REVOKED" && (
                <Reason
                  action="Review application"
                  path={`/verifiers/${v.id}/review`}
                  statuses={["ACTIVE", "SUSPENDED", "REVOKED"]}
                  done={reload}
                />
              )}
          </>
        )}
      </Collection>
    </>
  );
}
export function Organizations() {
  const resource = useResource<Organization[]>("/organizations"),
    [selected, setSelected] = useState<Organization>();
  return (
    <>
      <h1>Organization workspace</h1>
      <p>
        A Business owner can manage ten members, including the owner. Workspace
        membership never grants platform staff authority.
      </p>
      <Form
        submit="Create workspace"
        onSubmit={async (form) => {
          await api("/organizations", "POST", { name: text(form, "name") });
          resource.reload();
        }}
      >
        <Field
          label="Organization name"
          name="name"
          required
          minLength={2}
          maxLength={120}
        />
      </Form>
      <Status {...resource} />
      {resource.data?.map((org) => (
        <article className="record" key={org.id}>
          <h2>
            {org.name} <Badge>{org.status}</Badge>
          </h2>
          <p>Your role: {org.role}</p>
          <p className="break">Organization ID: {org.id}</p>
          {org.role !== "OWNER" && (
            <Action
              label="Leave workspace"
              path={`/organizations/${org.id}/leave`}
              done={resource.reload}
            />
          )}{" "}
          {org.role === "OWNER" && org.status === "ACTIVE" && (
            <button onClick={() => setSelected(org)}>
              Manage members and activity
            </button>
          )}
        </article>
      ))}
      {selected && (
        <Members
          key={selected.id}
          org={selected}
          closed={() => {
            setSelected(undefined);
            resource.reload();
          }}
        />
      )}
    </>
  );
}
function Members({ org, closed }: { org: Organization; closed: () => void }) {
  const members = useResource<
    { id: string; userId: string; email: string; role: string }[]
  >(`/organizations/${org.id}/members`);
  return (
    <section className="panel">
      <h2>{org.name} members</h2>
      <Status {...members} />
      {members.data?.map((member) => (
        <article className="record" key={member.id}>
          <h3>
            {member.email} <Badge>{member.role}</Badge>
          </h3>
          <p className="break">Account ID: {member.userId}</p>
          {member.role !== "OWNER" && (
            <Action
              label="Remove member"
              path={`/organizations/${org.id}/members/${member.userId}`}
              method="DELETE"
              done={members.reload}
            />
          )}
        </article>
      ))}
      <Form
        submit="Add verified member"
        onSubmit={async (form) => {
          await api(`/organizations/${org.id}/members`, "POST", {
            email: text(form, "email"),
            role: text(form, "role"),
          });
          members.reload();
        }}
      >
        <Field label="Member email" name="email" type="email" required />
        <Select label="Workspace role" name="role">
          <option>MEMBER</option>
          <option>ISSUER</option>
          <option>VERIFIER</option>
        </Select>
      </Form>
      <details>
        <summary>Transfer ownership</summary>
        <Form
          submit="Transfer ownership"
          onSubmit={async (form) => {
            await api(`/organizations/${org.id}/transfer`, "POST", {
              userId: text(form, "userId"),
            });
            closed();
          }}
        >
          <Field
            label="New owner account ID"
            name="userId"
            required
            hint="Must be a verified member with MFA and a Business plan."
          />
        </Form>
      </details>
      <details>
        <summary>Close workspace</summary>
        <p>
          Closing revokes all issuer and verifier authority belonging to this
          workspace.
        </p>
        <Action
          label="Close this workspace"
          path={`/organizations/${org.id}/close`}
          danger
          done={closed}
        />
      </details>
      <h3>Workspace audit</h3>
      <Collection<Audit> path={`/organizations/${org.id}/audit`}>
        {(event) => (
          <>
            <h4>{event.event}</h4>
            <p>
              {date(event.createdAt)} · {event.outcome}
            </p>
          </>
        )}
      </Collection>
    </section>
  );
}
