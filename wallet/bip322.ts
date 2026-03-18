/**
 * BIP-322 generic message signing helpers.
 *
 * Implements the "simple" variant used by both P2WPKH (bc1q) and P2TR (bc1p)
 * addresses. The same tagged-hash approach is used for both; the difference is
 * only in how the resulting sighash is signed and how the witness is structured.
 *
 * Spec: https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki
 */

// ---------------------------------------------------------------------------
// Tagged SHA-256 (BIP-340 §  "Tagged hashes")
// ---------------------------------------------------------------------------

/**
 * Returns SHA-256(SHA-256(tag) || SHA-256(tag) || data).
 * We implement this with the Web Crypto API so it runs in both Node ≥18
 * and the Cloudflare Workers runtime.
 */
export async function taggedHash(tag: string, data: Uint8Array): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const tagBytes = enc.encode(tag);

  const tagHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", tagBytes)
  );

  const preimage = new Uint8Array(tagHash.length * 2 + data.length);
  preimage.set(tagHash, 0);
  preimage.set(tagHash, tagHash.length);
  preimage.set(data, tagHash.length * 2);

  return new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
}

// ---------------------------------------------------------------------------
// BIP-322 "to_sign" transaction hash
// ---------------------------------------------------------------------------

/**
 * Encodes a var-int as used in Bitcoin serialisation.
 */
function varInt(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    new DataView(b.buffer).setUint16(1, n, true);
    return b;
  }
  if (n <= 0xffffffff) {
    const b = new Uint8Array(5);
    b[0] = 0xfe;
    new DataView(b.buffer).setUint32(1, n, true);
    return b;
  }
  throw new RangeError("varInt: value too large");
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function u32LE(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function u64LE(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}

/**
 * BIP-322 "message hash" used as the sighash for both P2WPKH and P2TR.
 *
 * Produces: SHA-256(SHA-256("BIP0322-signed-message") || SHA-256(message))
 * which is identical to a BIP-340 tagged hash with tag "BIP0322-signed-message".
 *
 * The resulting 32-byte digest is what gets signed.
 */
export async function bip322MessageHash(message: string): Promise<Uint8Array> {
  const msgBytes = new TextEncoder().encode(message);
  const msgHash = new Uint8Array(await crypto.subtle.digest("SHA-256", msgBytes));
  return taggedHash("BIP0322-signed-message", msgHash);
}

/**
 * Serialises the BIP-322 "to_spend" transaction for a given scriptPubKey.
 * This is the transaction that the "to_sign" transaction spends from.
 *
 *   version:  0
 *   locktime: 0
 *   input[0]: prevout = 0x000…00:ffffffff, sequence = 0
 *             scriptSig = OP_0 <32-byte message hash>
 *   output[0]: value = 0, scriptPubKey = <address scriptPubKey>
 */
export async function toSpendTx(
  message: string,
  scriptPubKey: Uint8Array
): Promise<Uint8Array> {
  const msgHash = await bip322MessageHash(message);

  // scriptSig: OP_0 (0x00) + PUSH32 (0x20) + msgHash
  const scriptSig = concat(new Uint8Array([0x00, 0x20]), msgHash);

  return concat(
    u32LE(0),                      // version
    varInt(1),                     // input count
    new Uint8Array(32),            // prevout txid (all zeros)
    new Uint8Array([0xff, 0xff, 0xff, 0xff]), // prevout vout (0xffffffff)
    varInt(scriptSig.length),
    scriptSig,
    new Uint8Array([0x00, 0x00, 0x00, 0x00]), // sequence
    varInt(1),                     // output count
    u64LE(0n),                     // value 0
    varInt(scriptPubKey.length),
    scriptPubKey,
    u32LE(0),                      // locktime
  );
}

// ---------------------------------------------------------------------------
// BIP-341 sighash for Taproot key-path spending (used by P2TR BIP-322)
// ---------------------------------------------------------------------------

/**
 * Computes the BIP-341 sighash (SIGHASH_ALL, key-path) for the BIP-322
 * "to_sign" transaction spending the "to_spend" output.
 *
 * This is what the Schnorr signature must sign for a P2TR BIP-322 proof.
 *
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message
 */
export async function bip341SighashForBip322(
  message: string,
  scriptPubKey: Uint8Array  // the P2TR scriptPubKey: OP_1 <32-byte x-only pubkey>
): Promise<Uint8Array> {
  const toSpend = await toSpendTx(message, scriptPubKey);
  const toSpendTxid = new Uint8Array(
    await crypto.subtle.digest("SHA-256",
      new Uint8Array(await crypto.subtle.digest("SHA-256", toSpend))
    )
  );

  // BIP-341 sighash preimage components for SIGHASH_ALL (0x00), key-path
  // epoch (1) || sighash_type (1) || nVersion (4) || nLocktime (4)
  // || sha_prevouts (32) || sha_amounts (32) || sha_scriptpubkeys (32)
  // || sha_sequences (32) || sha_outputs (32)
  // || spend_type (1) || input_index (4)
  // [annex omitted — BIP-322 never includes one]

  // "to_sign" tx:  version=0, locktime=0, 1 input, 1 output (OP_RETURN)
  // input spends toSpend:vout=0, sequence=0, no scriptSig, empty witness initially

  const nVersion  = u32LE(0);
  const nLocktime = u32LE(0);

  // sha_prevouts = SHA-256(prevout txid || prevout vout)
  const prevout = concat(toSpendTxid, u32LE(0));
  const sha_prevouts = new Uint8Array(await crypto.subtle.digest("SHA-256", prevout));

  // sha_amounts = SHA-256(amount of each input as 8-byte LE)  — value is 0
  const sha_amounts = new Uint8Array(
    await crypto.subtle.digest("SHA-256", u64LE(0n))
  );

  // sha_scriptpubkeys = SHA-256(varint+scriptPubKey for each input)
  const spkWithLen = concat(varInt(scriptPubKey.length), scriptPubKey);
  const sha_scriptpubkeys = new Uint8Array(
    await crypto.subtle.digest("SHA-256", spkWithLen)
  );

  // sha_sequences = SHA-256(sequence of each input as 4-byte LE) — sequence=0
  const sha_sequences = new Uint8Array(
    await crypto.subtle.digest("SHA-256", u32LE(0))
  );

  // output for "to_sign": OP_RETURN (0x6a), value=0
  // scriptPubKey: 0x6a (1 byte)
  const outputSpk = new Uint8Array([0x6a]);
  const outputData = concat(u64LE(0n), varInt(outputSpk.length), outputSpk);
  const sha_outputs = new Uint8Array(
    await crypto.subtle.digest("SHA-256", outputData)
  );

  // spend_type: key-path = 0x00 (no annex, no script)
  const spend_type = new Uint8Array([0x00]);

  const preimage = concat(
    new Uint8Array([0x00]),  // epoch
    new Uint8Array([0x00]),  // sighash_type SIGHASH_ALL
    nVersion,
    nLocktime,
    sha_prevouts,
    sha_amounts,
    sha_scriptpubkeys,
    sha_sequences,
    sha_outputs,
    spend_type,
    u32LE(0),                // input index
  );

  return taggedHash("TapSighash", preimage);
}