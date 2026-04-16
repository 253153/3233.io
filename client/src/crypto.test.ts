import { describe, it, expect } from "vitest";
import {
  b64decode,
  b64encode,
  decryptFromSender,
  encryptForRecipient,
  fingerprintFromPublicKey,
  generateKeyPair,
  shortFingerprint,
} from "./crypto";

describe("b64 round-trip", () => {
  it("encodes and decodes a plain ASCII string", () => {
    const input = new TextEncoder().encode("hello world");
    expect(new TextDecoder().decode(b64decode(b64encode(input)))).toBe(
      "hello world",
    );
  });

  it("preserves random bytes", () => {
    const random = new Uint8Array(256);
    crypto.getRandomValues(random);
    const out = b64decode(b64encode(random));
    expect(out).toEqual(random);
  });

  it("preserves bytes with the full 0-255 range", () => {
    const u = new Uint8Array(256);
    for (let i = 0; i < 256; i++) u[i] = i;
    const round = b64decode(b64encode(u));
    expect(round).toEqual(u);
  });
});

describe("fingerprintFromPublicKey", () => {
  it("produces 64-char lowercase hex", async () => {
    const fp = await fingerprintFromPublicKey(new Uint8Array(32));
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input", async () => {
    const pk = new Uint8Array(32);
    pk[0] = 42;
    const a = await fingerprintFromPublicKey(pk);
    const b = await fingerprintFromPublicKey(pk);
    expect(a).toBe(b);
  });

  it("differs for different inputs", async () => {
    const a = await fingerprintFromPublicKey(new Uint8Array(32));
    const pk2 = new Uint8Array(32);
    pk2[0] = 1;
    const b = await fingerprintFromPublicKey(pk2);
    expect(a).not.toBe(b);
  });

  it("matches the server-side SHA-256 vector (all-zero pubkey)", async () => {
    expect(await fingerprintFromPublicKey(new Uint8Array(32))).toBe(
      "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
    );
  });
});

describe("shortFingerprint", () => {
  it("formats as 3233:<first 32 hex chars>", () => {
    const fp = "a".repeat(64);
    expect(shortFingerprint(fp)).toBe("3233:" + "a".repeat(32));
  });
});

describe("NaCl box round-trip", () => {
  it("encrypts and decrypts a text payload between two pairs", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const msg = new TextEncoder().encode("ping from alice");

    const { ciphertext, nonce } = encryptForRecipient(
      msg,
      bob.publicKey,
      alice,
    );

    const opened = decryptFromSender(ciphertext, nonce, alice.publicKey, bob);
    expect(opened).not.toBeNull();
    expect(new TextDecoder().decode(opened!)).toBe("ping from alice");
  });

  it("fails to decrypt with the wrong recipient key", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const eve = generateKeyPair();
    const { ciphertext, nonce } = encryptForRecipient(
      new TextEncoder().encode("secret"),
      bob.publicKey,
      alice,
    );
    expect(decryptFromSender(ciphertext, nonce, alice.publicKey, eve)).toBeNull();
  });

  it("fails with a tampered ciphertext", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const { ciphertext, nonce } = encryptForRecipient(
      new TextEncoder().encode("secret"),
      bob.publicKey,
      alice,
    );
    // Flip one byte.
    ciphertext[0] ^= 0xff;
    expect(decryptFromSender(ciphertext, nonce, alice.publicKey, bob)).toBeNull();
  });

  it("generates a distinct nonce per encryption", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const msg = new TextEncoder().encode("x");
    const a = encryptForRecipient(msg, bob.publicKey, alice);
    const b = encryptForRecipient(msg, bob.publicKey, alice);
    expect(a.nonce).not.toEqual(b.nonce);
  });
});
