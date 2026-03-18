import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { bech32, bech32m } from "@scure/base";
import { bip341SighashForBip322, bip322MessageHash } from "./bip322.js";

export interface VerifyResult {
  valid: boolean;
  reason?: string;
}

function p2wpkhScriptPubKey(address: string): Uint8Array {
  const { words } = bech32.decode(address);
  const program = bech32.fromWords(words.slice(1));
  if (program.length !== 20) throw new Error("P2WPKH: expected 20-byte program");
  return new Uint8Array([0x00, 0x14, ...program]);
}

function p2trScriptPubKey(address: string): Uint8Array {
  const { words } = bech32m.decode(address);
  const program = bech32m.fromWords(words.slice(1));
  if (program.length !== 32) throw new Error("P2TR: expected 32-byte witness program");
  return new Uint8Array([0x51, 0x20, ...program]);
}

function xOnlyPubkeyFromP2TR(address: string): Uint8Array {
  return p2trScriptPubKey(address).slice(2);
}

export function decodeWitness(witnessBase64: string): Uint8Array[] {
  const raw = Uint8Array.from(atob(witnessBase64), c => c.charCodeAt(0));
  let offset = 0;

  function readVarInt(): number {
    const first = raw[offset++];
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const v = new DataView(raw.buffer, raw.byteOffset + offset, 2).getUint16(0, true);
      offset += 2;
      return v;
    }
    throw new Error("decodeWitness: varint too large");
  }

  const count = readVarInt();
  const items: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const len = readVarInt();
    items.push(raw.slice(offset, offset + len));
    offset += len;
  }
  return items;
}

async function verifyP2WPKH(
  message: string,
  address: string,
  witnessItems: Uint8Array[]
): Promise<VerifyResult> {
  if (witnessItems.length !== 2) {
    return { valid: false, reason: `P2WPKH witness must have 2 items, got ${witnessItems.length}` };
  }

  const [derSig, pubkeyBytes] = witnessItems;

  const pubkeyHash = await crypto.subtle.digest("SHA-256", pubkeyBytes);
  const { ripemd160: r160 } = await import("@noble/hashes/legacy.js");
  const ripe = r160(new Uint8Array(pubkeyHash));
  const expectedSpk = new Uint8Array([0x00, 0x14, ...ripe]);

  let actualSpk: Uint8Array;
  try {
    actualSpk = p2wpkhScriptPubKey(address);
  } catch {
    return { valid: false, reason: "P2WPKH: invalid bc1q address" };
  }

  if (!bytesEqual(expectedSpk, actualSpk)) {
    return { valid: false, reason: "P2WPKH: pubkey does not match address" };
  }

  const msgHash = await bip322MessageHash(message);

  const sigDer = derSig[derSig.length - 1] === 0x01
    ? derSig.slice(0, -1)
    : derSig;

  try {
    const valid = secp256k1.verify(sigDer, msgHash, pubkeyBytes, { format: 'der' });
    return valid
      ? { valid: true }
      : { valid: false, reason: "P2WPKH: ECDSA signature invalid" };
  } catch (e) {
    return { valid: false, reason: `P2WPKH: ${(e as Error).message}` };
  }
}

async function verifyP2TR(
  message: string,
  address: string,
  witnessItems: Uint8Array[]
): Promise<VerifyResult> {
  if (witnessItems.length !== 1) {
    return { valid: false, reason: `P2TR witness must have 1 item, got ${witnessItems.length}` };
  }

  const sigBytes = witnessItems[0];

  if (sigBytes.length !== 64 && sigBytes.length !== 65) {
    return { valid: false, reason: `P2TR: signature must be 64 or 65 bytes, got ${sigBytes.length}` };
  }
  if (sigBytes.length === 65 && sigBytes[64] !== 0x00) {
    return { valid: false, reason: `P2TR: unsupported sighash type 0x${sigBytes[64].toString(16)}` };
  }

  const schnorrSig = sigBytes.slice(0, 64);

  let xOnlyPubkey: Uint8Array;
  let scriptPubKey: Uint8Array;
  try {
    xOnlyPubkey = xOnlyPubkeyFromP2TR(address);
    scriptPubKey = p2trScriptPubKey(address);
  } catch (e) {
    return { valid: false, reason: `P2TR: invalid bc1p address — ${(e as Error).message}` };
  }

  let sighash: Uint8Array;
  try {
    sighash = await bip341SighashForBip322(message, scriptPubKey);
  } catch (e) {
    return { valid: false, reason: `P2TR: sighash computation failed — ${(e as Error).message}` };
  }

  try {
    const valid = schnorr.verify(schnorrSig, sighash, xOnlyPubkey);
    return valid
      ? { valid: true }
      : { valid: false, reason: "P2TR: Schnorr signature invalid" };
  } catch (e) {
    return { valid: false, reason: `P2TR: ${(e as Error).message}` };
  }
}

export async function verifySig(
  message: string,
  address: string,
  witnessBase64: string
): Promise<VerifyResult> {
  let witnessItems: Uint8Array[];
  try {
    witnessItems = decodeWitness(witnessBase64);
  } catch (e) {
    return { valid: false, reason: `witness decode failed: ${(e as Error).message}` };
  }

  if (witnessItems.length === 1) {
    return verifyP2TR(message, address, witnessItems);
  }
  if (witnessItems.length === 2) {
    return verifyP2WPKH(message, address, witnessItems);
  }

  return {
    valid: false,
    reason: `unsupported witness: ${witnessItems.length} items (expected 1 for P2TR or 2 for P2WPKH)`,
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}