import {
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
  type InputHTMLAttributes,
} from "react";
import { api, useResource, claimLabels, type Claim, type Page } from "./api";
export function Field({
  label,
  hint,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        aria-describedby={hint ? `${id}-hint` : undefined}
        {...props}
      />
      {hint && <small id={`${id}-hint`}>{hint}</small>}
    </div>
  );
}
export function Select({
  label,
  name,
  children,
  defaultValue,
}: {
  label: string;
  name: string;
  children: ReactNode;
  defaultValue?: string;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select id={id} name={name} defaultValue={defaultValue}>
        {children}
      </select>
    </div>
  );
}
export function LongText({
  label,
  name,
  defaultValue,
  hint,
}: {
  label: string;
  name: string;
  defaultValue?: string;
  hint?: string;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        name={name}
        minLength={10}
        maxLength={2000}
        required
        defaultValue={defaultValue}
        aria-describedby={hint ? `${id}-hint` : undefined}
      />
      {hint && <small id={`${id}-hint`}>{hint}</small>}
    </div>
  );
}
export function ClaimSelection({
  selected = [],
  name = "claims",
}: {
  selected?: Claim[];
  name?: string;
}) {
  return (
    <fieldset className="claim-options">
      <legend>Claim scope</legend>
      {Object.entries(claimLabels).map(([value, label]) => (
        <label key={value}>
          <input
            type="checkbox"
            name={name}
            value={value}
            defaultChecked={selected.includes(value as Claim)}
          />
          {label}
        </label>
      ))}
    </fieldset>
  );
}
export function Form({
  children,
  submit,
  onSubmit,
  danger = false,
}: {
  children?: ReactNode;
  submit: string;
  onSubmit: (data: FormData) => Promise<string | void>;
  danger?: boolean;
}) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [message, setMessage] = useState(""),
    errorRef = useRef<HTMLDivElement>(null),
    mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);
  return (
    <form
      onSubmit={async (event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        setBusy(true);
        setError("");
        setMessage("");
        try {
          const result = await onSubmit(data);
          if (mounted.current) setMessage(result ?? "Saved.");
        } catch (error) {
          if (mounted.current)
            setError(
              error instanceof Error
                ? error.message
                : "The request failed. Please retry.",
            );
        } finally {
          if (mounted.current) setBusy(false);
        }
      }}
    >
      <fieldset disabled={busy}>
        {children}
        <button className={danger ? "danger" : "primary"} type="submit">
          {busy ? "Working…" : submit}
        </button>
      </fieldset>
      {error && (
        <div className="error" role="alert" tabIndex={-1} ref={errorRef}>
          {error}
        </div>
      )}
      {message && (
        <p className="notice" role="status">
          {message}
        </p>
      )}
    </form>
  );
}
export function Action({
  label,
  path,
  method = "POST",
  body = {},
  done,
  danger = false,
}: {
  label: string;
  path: string;
  method?: string;
  body?: unknown;
  done?: () => void;
  danger?: boolean;
}) {
  return (
    <Form
      submit={label}
      danger={danger}
      onSubmit={async () => {
        await api(path, method, body);
        done?.();
      }}
    />
  );
}
export function Status({
  loading,
  error,
  reload,
}: {
  loading: boolean;
  error: string;
  reload: () => void;
}) {
  return (
    <>
      {loading && <p role="status">Loading…</p>}
      {error && (
        <div className="error" role="alert">
          {error} <button onClick={reload}>Retry</button>
        </div>
      )}
    </>
  );
}
export function Collection<T extends { id: string }>({
  path,
  empty = "No records yet.",
  children,
}: {
  path: string;
  empty?: string;
  children: (item: T, reload: () => void) => ReactNode;
}) {
  const [cursor, setCursor] = useState(""),
    [previous, setPrevious] = useState<string[]>([]);
  const resource = useResource<Page<T>>(
    `${path}${path.includes("?") ? "&" : "?"}limit=25${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
  );
  return (
    <>
      <Status {...resource} />
      {resource.data && (
        <>
          {!resource.data.items.length && <p className="empty">{empty}</p>}
          <div className="record-list">
            {resource.data.items.map((item) => (
              <article key={item.id} className="record">
                {children(item, resource.reload)}
              </article>
            ))}
          </div>
        </>
      )}
      <div className="pagination">
        {previous.length > 0 && (
          <button
            onClick={() => {
              setCursor(previous.at(-1)!);
              setPrevious((p) => p.slice(0, -1));
            }}
          >
            Previous page
          </button>
        )}
        {resource.data?.nextCursor && (
          <button
            onClick={() => {
              setPrevious((p) => [...p, cursor]);
              setCursor(resource.data!.nextCursor!);
            }}
          >
            Next page
          </button>
        )}
      </div>
    </>
  );
}
export function Badge({ children }: { children: ReactNode }) {
  return <span className="badge">{children}</span>;
}
export function Claims({
  values,
}: {
  values: Partial<Record<Claim, string | boolean>>;
}) {
  return (
    <dl className="claims">
      {Object.entries(values).map(([name, value]) => (
        <div key={name}>
          <dt>{claimLabels[name as Claim] ?? name}</dt>
          <dd>{typeof value === "boolean" ? (value ? "Yes" : "No") : value}</dd>
        </div>
      ))}
    </dl>
  );
}
export function Secret({ title, value }: { title: string; value: string }) {
  return (
    <section className="secret" aria-label={title}>
      <h3>{title}</h3>
      <p>Shown only now. Save this securely before leaving this page.</p>
      <pre>{value}</pre>
    </section>
  );
}
