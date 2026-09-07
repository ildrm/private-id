import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt as callbackScrypt,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import { requireThat } from "./errors.js";
const scrypt = promisify(callbackScrypt);
export const secret = () => randomBytes(32).toString("base64url");
export const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export const canonicalEmail = (email: string) =>
  email.trim().normalize("NFKC").toLowerCase();
export function equal(a: string, b: string) {
  const x = Buffer.from(a),
    y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export async function hashPassword(password: string) {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${((await scrypt(password, salt, 64)) as Buffer).toString("hex")}`;
}
const dummyHash = `00000000000000000000000000000000:${"0".repeat(128)}`;
export async function verifyPassword(password: string, encoded = dummyHash) {
  const [salt, hash] = encoded.split(":");
  const actual = (await scrypt(password, salt || "invalid", 64)) as Buffer;
  const expected = Buffer.from(hash ?? "", "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
export function seal(value: string, key: string) {
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", Buffer.from(key, "base64"), iv);
  const body = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), body]
    .map((x) => x.toString("base64url"))
    .join(".");
}
export function unseal(value: string, key: string) {
  const [iv, tag, body] = value
    .split(".")
    .map((x) => Buffer.from(x, "base64url"));
  const cipher = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(key, "base64"),
    iv,
  );
  cipher.setAuthTag(tag);
  return Buffer.concat([cipher.update(body), cipher.final()]).toString("utf8");
}
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function base32(bytes: Buffer) {
  let bits = 0,
    value = 0,
    out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
function decode32(input: string) {
  let bits = 0,
    value = 0;
  const out: number[] = [];
  for (const char of input) {
    const n = alphabet.indexOf(char);
    requireThat(n >= 0, "INVALID_MFA_SECRET", "Invalid MFA secret");
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
export const newTotpSecret = () => base32(randomBytes(20));
export function totp(secretValue: string, step: number) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(step));
  const hash = createHmac("sha1", decode32(secretValue))
    .update(message)
    .digest();
  const offset = hash[hash.length - 1] & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(
    6,
    "0",
  );
}
export function verifyTotp(
  secretValue: string,
  code: string,
  now: number,
  lastStep = -1,
) {
  if (!/^\d{6}$/.test(code)) return undefined;
  const current = Math.floor(now / 30000);
  return [current - 1, current, current + 1].find(
    (step) => step > lastStep && equal(totp(secretValue, step), code),
  );
}
