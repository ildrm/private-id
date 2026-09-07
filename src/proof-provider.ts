import { createHmac, createPublicKey } from "node:crypto";
import {
  SignJWT,
  jwtVerify,
  importPKCS8,
  importSPKI,
  exportJWK,
  type CryptoKey,
} from "jose";
import { z } from "zod";
import type { Config } from "./config.js";
import { claimsSchema, type Claims } from "./models.js";
import { AppError, requireThat } from "./errors.js";
const payloadSchema = z
  .object({
    iss: z.string(),
    aud: z.string(),
    sub: z.string().min(20),
    iat: z.number().int(),
    exp: z.number().int(),
    jti: z.string(),
    request_id: z.string(),
    nonce: z.string().optional(),
    claims: claimsSchema,
  })
  .strict();
export type ProofPayload = z.infer<typeof payloadSchema>;
export class ProofProvider {
  private constructor(
    private config: Config,
    private signingKey: CryptoKey | Uint8Array,
    private publicKeys: Map<string, CryptoKey | Uint8Array>,
    private algorithm: "EdDSA" | "HS256",
    private clock: () => number,
  ) {}
  static async create(config: Config, clock = () => Date.now()) {
    if (config.signingPrivateKey) {
      const privateKey = await importPKCS8(config.signingPrivateKey, "EdDSA"),
        publicKeys = new Map<string, CryptoKey | Uint8Array>();
      for (const [id, pem] of Object.entries(config.signingPublicKeys))
        publicKeys.set(id, await importSPKI(pem, "EdDSA"));
      publicKeys.set(
        config.signingKeyId,
        await importSPKI(
          createPublicKey(config.signingPrivateKey)
            .export({ type: "spki", format: "pem" })
            .toString(),
          "EdDSA",
        ),
      );
      return new ProofProvider(config, privateKey, publicKeys, "EdDSA", clock);
    }
    requireThat(
      config.mode !== "production",
      "CONFIGURATION",
      "Production requires an asymmetric signing provider",
    );
    const key = new TextEncoder().encode(config.signingSecret);
    requireThat(
      key.length >= 32,
      "CONFIGURATION",
      "Development signing secret is too short",
    );
    return new ProofProvider(
      config,
      key,
      new Map([[config.signingKeyId, key]]),
      "HS256",
      clock,
    );
  }
  subject(userId: string, clientId: string) {
    return `sub_${createHmac("sha256", this.config.subjectSecret).update(`privateid-subject-v1\0${clientId}\0${userId}`).digest("base64url")}`;
  }
  async sign(input: {
    userId: string;
    clientId: string;
    requestId: string;
    jti: string;
    claims: Claims;
    expiresAt: number;
    nonce?: string;
  }) {
    const now = Math.floor(this.clock() / 1000);
    requireThat(
      input.expiresAt > now &&
        input.expiresAt <= now + this.config.proofSeconds,
      "INVALID_EXPIRY",
      "Proof lifetime is outside policy",
    );
    const claims = claimsSchema.parse(input.claims);
    return new SignJWT({
      request_id: input.requestId,
      claims,
      ...(input.nonce ? { nonce: input.nonce } : {}),
    })
      .setProtectedHeader({
        alg: this.algorithm,
        typ: "privateid-proof+jwt",
        kid: this.config.signingKeyId,
      })
      .setIssuer(this.config.issuer)
      .setAudience(input.clientId)
      .setSubject(this.subject(input.userId, input.clientId))
      .setIssuedAt(now)
      .setExpirationTime(input.expiresAt)
      .setJti(input.jti)
      .sign(this.signingKey);
  }
  async verify(token: string, audience: string): Promise<ProofPayload> {
    requireThat(token.length <= 16384, "INVALID_PROOF", "Proof is too large");
    try {
      const { payload } = await jwtVerify(
        token,
        async (header) => {
          requireThat(
            header.typ === "privateid-proof+jwt" &&
              header.kid &&
              this.publicKeys.has(header.kid),
            "INVALID_PROOF",
            "Unrecognized proof key or type",
          );
          return this.publicKeys.get(header.kid)!;
        },
        {
          issuer: this.config.issuer,
          audience,
          algorithms: [this.algorithm],
          typ: "privateid-proof+jwt",
          requiredClaims: [
            "iss",
            "aud",
            "sub",
            "iat",
            "exp",
            "jti",
            "request_id",
          ],
          maxTokenAge: this.config.proofSeconds,
          clockTolerance: 0,
          currentDate: new Date(this.clock()),
        },
      );
      const result = payloadSchema.parse(payload),
        now = Math.floor(this.clock() / 1000);
      requireThat(
        result.iat <= now &&
          result.exp > now &&
          result.exp - result.iat <= this.config.proofSeconds,
        "INVALID_PROOF",
        "Proof lifetime is invalid",
      );
      return result;
    } catch {
      throw new AppError(
        "INVALID_PROOF",
        "Proof signature, audience, issuer, or lifetime is invalid",
        400,
      );
    }
  }
  async jwks() {
    if (this.algorithm !== "EdDSA") return { keys: [] };
    return {
      keys: await Promise.all(
        [...this.publicKeys].map(async ([kid, key]) => ({
          ...(await exportJWK(key as CryptoKey)),
          kid,
          alg: "EdDSA",
          use: "sig",
        })),
      ),
    };
  }
}
