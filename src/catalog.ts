import type { Config } from "./config.js";
import type { Transaction } from "./repository.js";
import { requireThat } from "./errors.js";
export type Plan = {
  id: "free" | "professional" | "business";
  name: string;
  priceMonthly: number;
  currency: string;
  features: string[];
  limits: {
    proofs: number;
    credentials: number;
    connections: number;
    teamMembers: number;
  };
  stripePriceId?: string;
};
export function planCatalog(config: Config): Plan[] {
  return [
    {
      id: "free",
      name: "Free",
      priceMonthly: 0,
      currency: "USD",
      features: [
        "Identity wallet",
        "20 proofs per UTC calendar month",
        "5 connected applications",
        "Session and privacy controls",
      ],
      limits: { proofs: 20, credentials: 5, connections: 5, teamMembers: 1 },
    },
    {
      id: "professional",
      name: "Professional",
      priceMonthly: 1200,
      currency: "USD",
      stripePriceId: config.stripePrices.professional,
      features: [
        "50 active credentials",
        "100 proofs per UTC calendar month",
        "10 connected applications",
      ],
      limits: { proofs: 100, credentials: 50, connections: 10, teamMembers: 1 },
    },
    {
      id: "business",
      name: "Business",
      priceMonthly: 4900,
      currency: "USD",
      stripePriceId: config.stripePrices.business,
      features: [
        "500 active credentials",
        "1,000 proofs per UTC calendar month",
        "100 connected applications",
        "Organization workspace for 10 members",
      ],
      limits: {
        proofs: 1000,
        credentials: 500,
        connections: 100,
        teamMembers: 10,
      },
    },
  ];
}
export async function effectivePlan(
  tx: Transaction,
  accountId: string,
  plans: Plan[],
  now = new Date().toISOString(),
) {
  const subscriptions = await tx.list("subscriptions", {
    where: { accountId },
    limit: 100,
  });
  const candidates = [
    ...(await tx.list("subscriptions", {
      where: { accountId, status: "active" },
      limit: 100,
    })),
    ...(await tx.list("subscriptions", {
      where: { accountId, status: "trialing" },
      limit: 100,
    })),
  ];
  const eligible = candidates.filter(
    (s) =>
      ["active", "trialing"].includes(s.status) &&
      !!s.currentPeriodEnd &&
      s.currentPeriodEnd > now &&
      plans.some((p) => p.id === s.planId),
  );
  eligible.sort(
    (a, b) =>
      (plans.find((p) => p.id === b.planId)?.priceMonthly ?? 0) -
        (plans.find((p) => p.id === a.planId)?.priceMonthly ?? 0) ||
      b.updatedAt.localeCompare(a.updatedAt),
  );
  const subscription = eligible[0];
  return {
    plan: plans.find((p) => p.id === subscription?.planId) ?? plans[0],
    subscription,
    subscriptions,
  };
}
export async function consumeProofAllowance(
  tx: Transaction,
  accountId: string,
  plans: Plan[],
  now: string,
) {
  const { plan } = await effectivePlan(tx, accountId, plans, now),
    period = now.slice(0, 7),
    id = `${accountId}:${period}`;
  const usage = (await tx.get("usage", id)) ?? {
    id,
    createdAt: now,
    accountId,
    period,
    proofs: 0,
  };
  requireThat(
    usage.proofs < plan.limits.proofs,
    "QUOTA_EXCEEDED",
    "Your monthly proof allowance is exhausted",
    429,
  );
  usage.proofs++;
  await tx.put("usage", usage);
  return usage;
}
