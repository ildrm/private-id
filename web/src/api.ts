import { useCallback, useEffect, useState } from "react";
import type { PublicAccount, Records } from "../../src/models.js";
import type { Services } from "../../src/services.js";
export type User = PublicAccount;
export type Credential = Awaited<
  ReturnType<Services["credentials"]["list"]>
>[number];
export type Request = Awaited<ReturnType<Services["proofs"]["get"]>>;
export type Preview = Awaited<ReturnType<Services["proofs"]["preview"]>>;
export type Dashboard = Awaited<ReturnType<Services["proofs"]["dashboard"]>>;
export type Plan = ReturnType<Services["billing"]["listPlans"]>[number];
export type Subscription = Awaited<
  ReturnType<Services["billing"]["subscription"]>
>;
export type Verifier = Awaited<
  ReturnType<Services["verifiers"]["list"]>
>[number];
export type Issuer = Records["issuers"];
export type Connection = Records["access"];
export type Organization = Records["organizations"] & { role: string };
export type Audit = Records["audit"];
export type Page<T> = { items: T[]; nextCursor?: string };
export class ApiError extends Error {
  constructor(
    message: string,
    public code: string,
    public status: number,
  ) {
    super(message);
  }
}
export async function api<T>(
  path: string,
  method = "GET",
  data?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const csrf = document.cookie
    .split("; ")
    .find((c) => c.startsWith("pid_csrf="))
    ?.slice("pid_csrf=".length);
  const response = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    signal,
    headers: {
      ...(data !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(csrf && method !== "GET"
        ? { "X-CSRF-Token": decodeURIComponent(csrf) }
        : {}),
    },
    ...(data !== undefined ? { body: JSON.stringify(data) } : {}),
  });
  const value = await response.json().catch(() => undefined);
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/auth/"))
      window.dispatchEvent(new Event("privateid:expired"));
    throw new ApiError(
      `${value?.error?.message ?? "The service is unavailable."}${value?.error?.fields?.filter(Boolean).length ? ` Fields: ${value.error.fields.filter(Boolean).join(", ")}.` : ""}${response.status >= 500 ? ` Request: ${value?.error?.requestId ?? "unavailable"}.` : ""}`,
      value?.error?.code ?? "REQUEST_FAILED",
      response.status,
    );
  }
  return value as T;
}
export function useResource<T>(path: string) {
  const [data, setData] = useState<T>(),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [version, setVersion] = useState(0);
  const reload = useCallback(() => setVersion((v) => v + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    setData(undefined);
    setError("");
    setLoading(true);
    api<T>(path, "GET", undefined, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setData(value);
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setError(
            error instanceof Error ? error.message : "Unable to load this page",
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [path, version]);
  return { data, error, loading, reload };
}
export const text = (form: FormData, name: string) =>
  String(form.get(name) ?? "").trim();
export const optional = (form: FormData, name: string) =>
  text(form, name) || undefined;
export const date = (value: string) =>
  new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
export const money = (amount: number, currency: string) =>
  new Intl.NumberFormat(undefined, { style: "currency", currency }).format(
    amount /
      10 **
        (new Intl.NumberFormat(undefined, {
          style: "currency",
          currency,
        }).resolvedOptions().maximumFractionDigits ?? 2),
  );
export const claimLabels = {
  adult_verified: "Adult (18 or older)",
  unique_person: "Unique person",
  account_valid: "Active PrivateID account",
  identity_verified: "Verified identity",
  kyc_valid: "Current KYC",
  jurisdiction: "Jurisdiction",
  investor_eligible: "Investor eligibility",
  authorized_company_signatory: "Authorized company signatory",
  asset_owner_verified: "Verified asset owner",
  employment_verified: "Verified employment",
  degree_verified: "Verified degree",
};
export type Claim = keyof typeof claimLabels;
