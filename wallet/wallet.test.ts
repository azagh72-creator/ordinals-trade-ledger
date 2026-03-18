import { describe, it, expect } from "vitest";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { randomBytes } from "@noble/curves/utils.js";
import { bech32m } from "@scure/base";
import { verifySig, decodeWitness } from "./wallet.js";
import { bip341SighashForBip322, bip322MessageHash } from "./bip322.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function encodeWitness(items: Uint8Array[]): string {
  const parts: number[] = [];
  function pushVarInt(n: number) {
    if (n < 0xfd) { parts.push(n); return; }
    parts.push(0xfd, n & 0xff, (n >> 8) & 0xff);
  }
  pushVarInt(items.length);
  for (const item of items) {
    pushVarInt(item.length);
    parts.push(...item);
  }
  return btoa(String.fromCharCode(...parts));
}

function xOnlyToP2TR(xOnlyPubkey: Uint8Array): string {
  const words = [1, ...bech32m.toWords(xOnlyPubkey)];
  return bech32m.encode("bc", words);
}

// ---------------------------------------------------------------------------
// decodeWitness
// ---------------------------------------------------------------------------

describe("decodeWitness", () => {
  it("round-trips a 1-item witness", () => {
    const sig = randomBytes(64);
    const encoded = encodeWitness([sig]);
    const decoded = decodeWitness(encoded);
    expect(decoded).toHaveLength(1);
    expect(decoded[0]).toEqual(sig);
  });

  it("round-trips a 2-item witness", () => {
    const sig    = randomBytes(71);
    const pubkey = randomBytes(33);
    const encoded = encodeWitness([sig, pubkey]);
    const decoded = decodeWitness(encoded);
    expect(decoded).toHaveLength(2);
    expect(decoded[0]).toEqual(sig);
    expect(decoded[1]).toEqual(pubkey);
  });
});

// ---------------------------------------------------------------------------
// P2TR (bc1p) — Schnorr
// ---------------------------------------------------------------------------

describe("verifySig — P2TR (bc1p) Schnorr", () => {
  async function makeP2TRFixture(message: string) {
    const privkey = randomBytes(32);
    const xOnlyPubkey = secp256k1.getPublicKey(privkey, true).slice(1);
    const address = xOnlyToP2TR(xOnlyPubkey);
    const scriptPubKey = new Uint8Array([0x51, 0x20, ...xOnlyPubkey]);
    const sighash = await bip341SighashForBip322(message, scriptPubKey);
    const sig = await schnorr.sign(sighash, privkey);
    const witnessBase64 = encodeWitness([sig]);
    return { address, witnessBase64, privkey, xOnlyPubkey };
  }

  it("accepts a valid Schnorr signature", async () => {
    const { address, witnessBase64 } = await makeP2TRFixture("Hello World");
    const result = await verifySig("Hello World", address, witnessBase64);
    expect(result.valid).toBe(true);
  });

  it("accepts a valid signature with SIGHASH_ALL suffix byte (0x00)", async () => {
    const privkey = randomBytes(32);
    const xOnlyPubkey = secp256k1.getPublicKey(privkey, true).slice(1);
    const address = xOnlyToP2TR(xOnlyPubkey);
    const scriptPubKey = new Uint8Array([0x51, 0x20, ...xOnlyPubkey]);
    const sighash = await bip341SighashForBip322("trade:offer:42", scriptPubKey);
    const sig64 = await schnorr.sign(sighash, privkey);
    const sig65 = new Uint8Array(65);
    sig65.set(sig64);
    sig65[64] = 0x00;
    const result = await verifySig("trade:offer:42", address, encodeWitness([sig65]));
    expect(result.valid).toBe(true);
  });

  it("rejects a signature over a different message", async () => {
    const { address, witnessBase64 } = await makeP2TRFixture("Hello World");
    const result = await verifySig("Not the same message", address, witnessBase64);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/Schnorr/i);
  });

  it("rejects a signature from a different key", async () => {
    const { address } = await makeP2TRFixture("Hello World");
    const otherPrivkey = randomBytes(32);
    const otherXOnly   = secp256k1.getPublicKey(otherPrivkey, true).slice(1);
    const otherSpk     = new Uint8Array([0x51, 0x20, ...otherXOnly]);
    const sighash      = await bip341SighashForBip322("Hello World", otherSpk);
    const sig          = await schnorr.sign(sighash, otherPrivkey);
    const result = await verifySig("Hello World", address, encodeWitness([sig]));
    expect(result.valid).toBe(false);
  });

  it("rejects a witness with wrong item count (2 items on a bc1p address)", async () => {
    const { address } = await makeP2TRFixture("test");
    const fakeWitness = encodeWitness([new Uint8Array(64), new Uint8Array(33)]);
    const result = await verifySig("test", address, fakeWitness);
    expect(result.valid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("rejects a 65-byte sig with a non-zero sighash type", async () => {
    const { address, privkey, xOnlyPubkey } = await makeP2TRFixture("msg");
    const scriptPubKey = new Uint8Array([0x51, 0x20, ...xOnlyPubkey]);
    const sighash = await bip341SighashForBip322("msg", scriptPubKey);
    const sig64 = await schnorr.sign(sighash, privkey);
    const sig65 = new Uint8Array(65);
    sig65.set(sig64);
    sig65[64] = 0x01;
    const result = await verifySig("msg", address, encodeWitness([sig65]));
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/sighash type/i);
  });

  it("rejects a signature of wrong length", async () => {
    const privkey = randomBytes(32);
    const xOnlyPubkey = secp256k1.getPublicKey(privkey, true).slice(1);
    const address = xOnlyToP2TR(xOnlyPubkey);
    const result = await verifySig("msg", address, encodeWitness([new Uint8Array(63)]));
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/64 or 65 bytes/);
  });

  it("signs and verifies multiple messages with the same key", async () => {
    const privkey = randomBytes(32);
    const xOnlyPubkey = secp256k1.getPublicKey(privkey, true).slice(1);
    const address = xOnlyToP2TR(xOnlyPubkey);
    const scriptPubKey = new Uint8Array([0x51, 0x20, ...xOnlyPubkey]);
    const messages = [
      "offer:inscription:abc123i0:50000",
      "counter:inscription:abc123i0:45000",
      "accept:inscription:abc123i0:45000",
    ];
    for (const msg of messages) {
      const sighash = await bip341SighashForBip322(msg, scriptPubKey);
      const sig = await schnorr.sign(sighash, privkey);
      const result = await verifySig(msg, address, encodeWitness([sig]));
      expect(result.valid).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// P2WPKH (bc1q) — ECDSA regression
// ---------------------------------------------------------------------------

describe("verifySig — P2WPKH (bc1q) ECDSA regression", () => {
  async function makeP2WPKHFixture(message: string) {
    const { ripemd160 } = await import("@noble/hashes/legacy.js");
    const { bech32 } = await import("@scure/base");
    const privkey  = randomBytes(32);
    const pubkey   = secp256k1.getPublicKey(privkey, true);
    const sha256Hash = new Uint8Array(await crypto.subtle.digest("SHA-256", pubkey));
    const hash160    = ripemd160(sha256Hash);
    const words = bech32.toWords(hash160);
    const address = bech32.encode("bc", [0x00, ...words]);
    const msgHash = await bip322MessageHash(message);
    const sig = secp256k1.sign(msgHash, privkey, { format: 'der' });
    const derSig = sig;
    const sigWithSighash = new Uint8Array(derSig.length + 1);
    sigWithSighash.set(derSig);
    sigWithSighash[derSig.length] = 0x01;
    const witnessBase64 = encodeWitness([sigWithSighash, pubkey]);
    return { address, witnessBase64 };
  }

  it("accepts a valid P2WPKH signature", async () => {
    const { address, witnessBase64 } = await makeP2WPKHFixture("Hello World");
    const result = await verifySig("Hello World", address, witnessBase64);
    expect(result.valid).toBe(true);
  });

  it("rejects a P2WPKH sig over a different message", async () => {
    const { address, witnessBase64 } = await makeP2WPKHFixture("Hello World");
    const result = await verifySig("Wrong message", address, witnessBase64);
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Dispatch edge-cases
// ---------------------------------------------------------------------------

describe("verifySig — dispatch", () => {
  it("returns an error for a 0-item witness", async () => {
    const result = await verifySig("msg", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", encodeWitness([]));
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/unsupported witness/);
  });

  it("returns an error for a 3-item witness", async () => {
    const result = await verifySig(
      "msg",
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
      encodeWitness([new Uint8Array(1), new Uint8Array(1), new Uint8Array(1)])
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/unsupported witness/);
  });
});