import { randomUUID } from "node:crypto";
import type { Transaction } from "./repository.js";
import type { Audit } from "./models.js";
export async function audit(
  tx: Transaction,
  event: string,
  actorId?: string,
  targetId?: string,
  metadata: Audit["metadata"] = {},
  organizationId?: string,
  outcome: Audit["outcome"] = "SUCCESS",
  now = new Date().toISOString(),
) {
  await tx.insert("audit", {
    id: `${now}-${randomUUID()}`,
    createdAt: now,
    event,
    actorId,
    targetId,
    metadata,
    organizationId,
    outcome,
  });
}
