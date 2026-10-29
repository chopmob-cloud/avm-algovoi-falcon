// SPDX-License-Identifier: Apache-2.0
/**
 * Chain-neutral Falcon attestations.
 *
 * A Falcon key signs the RFC 8785 (JCS) canonical bytes of a payload that binds
 * an action to a chain, an account and a nonce. A relying party recomputes those
 * canonical bytes and verifies the signature fully offline, so the attestation
 * verifies regardless of the settlement chain and needs no on-chain Falcon
 * verifier. Anchor the envelope in a transaction note, memo, calldata or log.
 *
 * The signed bytes are exactly JCS(payload), so the attestation's content
 * address `ref = "sha256:" + SHA-256(JCS(payload))` is the keystone reference of
 * the payload and composes with keystone tooling.
 *
 * Canonicalisation is deliberately restricted to the unambiguous JSON subset:
 * strings, booleans, null, arrays, plain objects, and INTEGERS (a safe-integer
 * `number` or a `bigint`). Non-integer or non-finite numbers are rejected rather
 * than guessed at, so there is no floating-point formatting ambiguity between the
 * signer and the verifier.
 */
import { falconSign, falconVerify, sha256hex, FALCON_PK_SIZE } from "./falcon.js";

/** Signature algorithm identifier carried in the envelope. */
export const ATTESTATION_ALG = "falcon-det1024";
/** Payload type tag, for domain separation from other JCS-signed data. */
export const ATTESTATION_TYP = "algovoi.attestation.v1";

/** A value that can appear in an attestation payload (restricted JSON). */
export type JcsValue =
  | string
  | number
  | bigint
  | boolean
  | null
  | JcsValue[]
  | { [key: string]: JcsValue };

export interface BindActionParams {
  /** Settlement chain the action targets, e.g. "algorand", "voi", "base". */
  chain: string;
  /** Account on that chain the action is bound to. */
  address: string;
  /** The action being attested, e.g. "pay", "transfer", "approve". */
  action: string;
  /** Monotonic nonce binding this attestation to one action (anti-replay). */
  nonce: number | bigint;
  /** Optional amount (integer, e.g. base units / microunits). */
  amount?: number | bigint;
  /** Optional recipient account. */
  recipient?: string;
  /** Optional asset / token identifier (integer). */
  asset?: number | bigint;
  /** Optional free-form note bound into the payload. */
  note?: string;
}

/** A payload produced by {@link bindAction}. */
export interface AttestationPayload {
  typ: string;
  chain: string;
  address: string;
  action: string;
  nonce: number | bigint;
  amount?: number | bigint;
  recipient?: string;
  asset?: number | bigint;
  note?: string;
}

/** The signed envelope returned by {@link attest}. */
export interface Attestation {
  /** The payload exactly as signed (re-canonicalised on verify). */
  payload: AttestationPayload | { [key: string]: JcsValue };
  /** Signature algorithm; always {@link ATTESTATION_ALG}. */
  alg: string;
  /** Key id: SHA-256 hex of the public key, binding the envelope to a key. */
  kid: string;
  /** Base64 of the Falcon signature over JCS(payload). */
  sig: string;
}

/** The result of {@link verifyAttestation} (fail-closed: never throws). */
export interface Verdict {
  /** True only if the signature verifies against the payload and key. */
  ok: boolean;
  /** Content address of the payload: "sha256:" + SHA-256(JCS(payload)). */
  ref?: string;
  /** The key id that was checked. */
  kid?: string;
  /** Why verification failed, when `ok` is false. */
  reason?: string;
}

// -- JCS (RFC 8785) canonicalisation ------------------------------------------

function jcsSerialize(value: JcsValue): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);           // RFC 8785 string escaping
  if (t === "boolean") return value ? "true" : "false";
  if (t === "bigint") return (value as bigint).toString();
  if (t === "number") {
    const n = value as number;
    if (!Number.isFinite(n) || !Number.isInteger(n)) {
      throw new Error(`JCS: only finite integer numbers are supported (got ${String(n)})`);
    }
    if (!Number.isSafeInteger(n)) {
      throw new Error("JCS: integer outside the safe range; pass it as a bigint");
    }
    return n.toString();
  }
  if (Array.isArray(value)) {
    return "[" + value.map(jcsSerialize).join(",") + "]";
  }
  if (t === "object") {
    const obj = value as { [key: string]: JcsValue };
    // RFC 8785: object members sorted by their key's UTF-16 code units, which is
    // exactly what String#< (and therefore Array#sort on strings) compares.
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) {
        throw new Error(`JCS: value for key ${JSON.stringify(k)} is undefined`);
      }
      parts.push(JSON.stringify(k) + ":" + jcsSerialize(v));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`JCS: unsupported value type ${t}`);
}

/** RFC 8785 (JCS) canonical UTF-8 bytes of a value from the supported subset. */
export function canonicalize(value: JcsValue): Uint8Array {
  return new TextEncoder().encode(jcsSerialize(value));
}

// -- base64 (standard alphabet, strict decode) --------------------------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function b64encode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i] << 16;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + "==";
  } else if (rem === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + "=";
  }
  return out;
}

function b64decode(s: string): Uint8Array {
  if (typeof s !== "string" || s.length % 4 !== 0) {
    throw new Error("invalid base64 length");
  }
  const dec: Record<string, number> = {};
  for (let i = 0; i < B64.length; i++) dec[B64[i]] = i;
  let pad = 0;
  if (s.endsWith("==")) pad = 2;
  else if (s.endsWith("=")) pad = 1;
  const body = s.length - pad;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < body; i++) {
    const v = dec[s[i]];
    if (v === undefined) throw new Error("invalid base64 character");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

// -- public API ---------------------------------------------------------------

function requireString(name: string, v: unknown): void {
  if (typeof v !== "string") throw new Error(`${name} must be a string`);
}

function requireInt(name: string, v: unknown): void {
  if (typeof v === "bigint") return;
  if (typeof v === "number" && Number.isSafeInteger(v)) return;
  throw new Error(`${name} must be a safe integer or bigint`);
}

/**
 * Build a canonical attestation payload binding an action to a chain, account
 * and nonce. Required fields: chain, address, action, nonce. Optional: amount,
 * recipient, asset, note (only included when provided, so the canonical form
 * stays tight). The result is a plain object suitable for {@link attest}.
 */
export function bindAction(params: BindActionParams): AttestationPayload {
  requireString("chain", params.chain);
  requireString("address", params.address);
  requireString("action", params.action);
  requireInt("nonce", params.nonce);

  const payload: AttestationPayload = {
    typ: ATTESTATION_TYP,
    chain: params.chain,
    address: params.address,
    action: params.action,
    nonce: params.nonce,
  };
  if (params.amount !== undefined) { requireInt("amount", params.amount); payload.amount = params.amount; }
  if (params.recipient !== undefined) { requireString("recipient", params.recipient); payload.recipient = params.recipient; }
  if (params.asset !== undefined) { requireInt("asset", params.asset); payload.asset = params.asset; }
  if (params.note !== undefined) { requireString("note", params.note); payload.note = params.note; }
  return payload;
}

/**
 * Sign a payload with a Falcon key, producing a self-describing envelope.
 * The signature is over the RFC 8785 (JCS) canonical bytes of `payload`.
 */
export async function attest(
  sk: Uint8Array,
  pk: Uint8Array,
  payload: AttestationPayload | { [key: string]: JcsValue },
): Promise<Attestation> {
  if (!(pk instanceof Uint8Array) || pk.length !== FALCON_PK_SIZE) {
    throw new Error(`attest: public key must be a ${FALCON_PK_SIZE}-byte Uint8Array`);
  }
  const bytes = canonicalize(payload as JcsValue);
  const sig = falconSign(sk, bytes);              // falconSign validates sk length
  const kid = await sha256hex(pk);
  return { payload, alg: ATTESTATION_ALG, kid, sig: b64encode(sig) };
}

/**
 * Verify an attestation against a public key. Fail-closed: any malformed input,
 * mismatched key, wrong payload type, or bad signature yields `{ ok: false }`
 * with a reason, and the function never throws. On a payload that canonicalises,
 * `ref` is returned regardless of the verdict so callers can content-address it.
 */
export async function verifyAttestation(pk: Uint8Array, att: Attestation): Promise<Verdict> {
  try {
    if (!(pk instanceof Uint8Array) || pk.length !== FALCON_PK_SIZE) {
      return { ok: false, reason: `public key must be a ${FALCON_PK_SIZE}-byte Uint8Array` };
    }
    if (att === null || typeof att !== "object") {
      return { ok: false, reason: "malformed envelope" };
    }
    const { payload, alg, kid, sig } = att;
    if (alg !== ATTESTATION_ALG) {
      return { ok: false, reason: `unsupported alg ${String(alg)}` };
    }
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      return { ok: false, reason: "payload must be an object" };
    }

    let bytes: Uint8Array;
    try {
      bytes = canonicalize(payload as JcsValue);
    } catch (e) {
      return { ok: false, reason: `uncanonicalisable payload: ${(e as Error).message}` };
    }
    const ref = "sha256:" + (await sha256hex(bytes));

    if ((payload as { typ?: unknown }).typ !== ATTESTATION_TYP) {
      return { ok: false, ref, reason: "unexpected payload type" };
    }

    const expectedKid = await sha256hex(pk);
    if (typeof kid !== "string" || kid !== expectedKid) {
      return { ok: false, ref, reason: "kid does not match public key" };
    }

    let sigBytes: Uint8Array;
    try {
      sigBytes = b64decode(sig);
    } catch {
      return { ok: false, ref, kid, reason: "signature is not valid base64" };
    }

    const ok = falconVerify(pk, bytes, sigBytes);
    return { ok, ref, kid, reason: ok ? undefined : "signature verification failed" };
  } catch (e) {
    // Defence in depth: verifyAttestation must never throw.
    return { ok: false, reason: `verification error: ${(e as Error).message}` };
  }
}
