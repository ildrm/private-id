import type { Config } from "./config.js";
import type { Database } from "./repository.js";
import { AccountService } from "./accounts.js";
import { CredentialService } from "./credentials.js";
import { VerifierService } from "./verifiers.js";
import { OrganizationService } from "./organizations.js";
import { ProofService } from "./proofs.js";
import { ProofProvider } from "./proof-provider.js";
import { BillingService } from "./payments.js";
import {
  StripeGateway,
  UnavailableBillingGateway,
  type BillingGateway,
} from "./stripe-gateway.js";
import { planCatalog } from "./catalog.js";
import { AbuseLimiter } from "./jobs.js";
export async function createServices(
  db: Database,
  config: Config,
  gateway?: BillingGateway,
  clock = () => Date.now(),
) {
  const plans = planCatalog(config),
    provider = await ProofProvider.create(config, clock);
  const billing = new BillingService(
    db,
    plans,
    gateway ??
      (config.enableBilling
        ? new StripeGateway(config, plans)
        : new UnavailableBillingGateway()),
    config,
    clock,
  );
  return {
    db,
    config,
    clock,
    plans,
    provider,
    billing,
    accounts: new AccountService(db, config, clock),
    credentials: new CredentialService(db, config, plans, clock),
    verifiers: new VerifierService(db, config, clock),
    organizations: new OrganizationService(db, plans, clock),
    proofs: new ProofService(db, config, plans, provider, clock),
    limiter: new AbuseLimiter(db, clock),
  };
}
export type Services = Awaited<ReturnType<typeof createServices>>;
