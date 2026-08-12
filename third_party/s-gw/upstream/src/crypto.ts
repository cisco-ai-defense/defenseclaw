import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scryptSync
} from "node:crypto";
import type { EncryptedBox } from "./types.js";
import { requireUnlockPassphrase } from "./unlock.js";

const keyLen = 32;

export function requirePassphrase(): string {
  return requireUnlockPassphrase();
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, keyLen);
}

export function encryptSecret(plainText: string): EncryptedBox {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(requirePassphrase(), salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);

  return {
    alg: "aes-256-gcm",
    kdf: "scrypt",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64")
  };
}

export function decryptSecret(box: EncryptedBox): string {
  if (box.alg !== "aes-256-gcm" || box.kdf !== "scrypt") {
    throw new Error("Unsupported encrypted secret format.");
  }

  const salt = Buffer.from(box.salt, "base64");
  const iv = Buffer.from(box.iv, "base64");
  const authTag = Buffer.from(box.authTag, "base64");
  const key = deriveKey(requirePassphrase(), salt);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  const plain = Buffer.concat([
    decipher.update(Buffer.from(box.ciphertext, "base64")),
    decipher.final()
  ]);

  return plain.toString("utf8");
}

export function fingerprintSecret(value: string): string {
  const passphrase = requirePassphrase();
  const fpKey = createHash("sha256")
    .update("s-gw-fingerprint-v1:")
    .update(passphrase)
    .digest();

  return createHmac("sha256", fpKey).update(value).digest("base64url").slice(0, 24);
}

export function shortId(prefix = ""): string {
  const id = randomBytes(9).toString("base64url");
  return prefix ? `${prefix}_${id}` : id;
}
