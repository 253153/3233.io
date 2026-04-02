import nacl from "tweetnacl";

export type BoxKeyPair = { publicKey: Uint8Array; secretKey: Uint8Array };

export function generateKeyPair(): BoxKeyPair {
  return nacl.box.keyPair();
}

export async function fingerprintFromPublicKey(pub: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", pub);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function shortFingerprint(fullHex: string): string {
  return `3233:${fullHex.slice(0, 32)}`;
}

export function b64encode(u8: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export function encryptForRecipient(
  plaintextUtf8: Uint8Array,
  recipientPk: Uint8Array,
  sender: BoxKeyPair,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = nacl.randomBytes(24);
  const boxed = nacl.box(plaintextUtf8, nonce, recipientPk, sender.secretKey);
  if (!boxed) throw new Error("encryption failed");
  return { ciphertext: boxed, nonce };
}

export function decryptFromSender(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  senderPk: Uint8Array,
  recipient: BoxKeyPair,
): Uint8Array | null {
  return nacl.box.open(ciphertext, nonce, senderPk, recipient.secretKey);
}
