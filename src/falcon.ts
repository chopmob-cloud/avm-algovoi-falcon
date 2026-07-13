// SPDX-License-Identifier: Apache-2.0
/**
 * Falcon-1024 keygen / sign / verify over a WebAssembly core.
 *
 * Runtime-agnostic: you supply the WASM binary once via initFalcon(), so the
 * same code runs in a browser, a browser extension, a web worker, or Node with
 * no host-specific loader. Deterministic signatures; PK 1793 B, SK 2305 B.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
import FalconFactory from "./falcon-module-factory.js";

export const FALCON_PK_SIZE = 1793;
export const FALCON_SK_SIZE = 2305;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _module: any = null;

/** SHA-256 hex of a byte buffer (used to pin a known falcon.wasm build). */
export async function sha256hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const src = data instanceof Uint8Array ? data : new Uint8Array(data);
  const bytes = new Uint8Array(src.length);   // fresh ArrayBuffer-backed copy (satisfies BufferSource)
  bytes.set(src);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Initialise the Falcon core. Call once before keygen/sign/verify.
 *
 * @param wasmBinary  the bytes of falcon.wasm (fetch/read them however your
 *                    runtime does: `fetch()` in a page, `chrome.runtime.getURL`
 *                    in an extension, `fs.readFileSync` in Node).
 * @param expectedHash optional SHA-256 hex to pin the binary; throws on mismatch.
 */
export async function initFalcon(wasmBinary: ArrayBuffer | Uint8Array, expectedHash?: string): Promise<void> {
  const bytes = wasmBinary instanceof Uint8Array ? wasmBinary : new Uint8Array(wasmBinary);
  if (expectedHash) {
    const got = await sha256hex(bytes);
    if (got !== expectedHash) throw new Error("Falcon WASM integrity check failed");
  }
  _module = await FalconFactory({ wasmBinary: bytes });
}

function mod() {
  if (!_module) throw new Error("Falcon not initialised: call initFalcon(wasmBinary) first");
  return _module;
}

/**
 * Generate a Falcon-1024 keypair from a 48-byte seed (deterministic).
 * With no seed, a random 48-byte seed is generated. The seed is returned so it
 * can be stored for recovery: falconKeygen(seed) regenerates the same keypair.
 */
export function falconKeygen(seed?: Uint8Array): { pk: Uint8Array; sk: Uint8Array; seed: Uint8Array } {
  const m = mod();
  const actualSeed = seed ?? crypto.getRandomValues(new Uint8Array(48));
  const seedPtr = m._malloc(48);
  const pkPtr = m._malloc(FALCON_PK_SIZE);
  const skPtr = m._malloc(FALCON_SK_SIZE);
  try {
    m.HEAPU8.set(actualSeed, seedPtr);
    const rc: number = m.ccall("falcon_wasm_keygen", "number",
      ["number", "number", "number"], [seedPtr, pkPtr, skPtr]);
    if (rc !== 0) throw new Error(`Falcon keygen failed (rc=${rc})`);
    return {
      pk: new Uint8Array(m.HEAPU8.buffer, pkPtr, FALCON_PK_SIZE).slice(),
      sk: new Uint8Array(m.HEAPU8.buffer, skPtr, FALCON_SK_SIZE).slice(),
      seed: actualSeed,
    };
  } finally {
    m.HEAPU8.fill(0, seedPtr, seedPtr + 48);           // wipe seed
    m.HEAPU8.fill(0, skPtr, skPtr + FALCON_SK_SIZE);   // wipe SK
    m._free(seedPtr); m._free(pkPtr); m._free(skPtr);
  }
}

/** Sign a message with Falcon-1024 (deterministic compressed signature). */
export function falconSign(sk: Uint8Array, msg: Uint8Array): Uint8Array {
  const m = mod();
  const sigMax: number = m.ccall("falcon_wasm_sig_maxsize", "number", [], []);
  const skPtr = m._malloc(FALCON_SK_SIZE);
  const msgPtr = m._malloc(msg.length);
  const sigPtr = m._malloc(sigMax);
  const sigLenPtr = m._malloc(4);
  try {
    m.HEAPU8.set(sk, skPtr);
    m.HEAPU8.set(msg, msgPtr);
    const rc: number = m.ccall("falcon_wasm_sign", "number",
      ["number", "number", "number", "number", "number"],
      [skPtr, msgPtr, msg.length, sigPtr, sigLenPtr]);
    if (rc !== 0) throw new Error(`Falcon sign failed (rc=${rc})`);
    const sigLen: number = m.getValue(sigLenPtr, "i32");
    return new Uint8Array(m.HEAPU8.buffer, sigPtr, sigLen).slice();
  } finally {
    m.HEAPU8.fill(0, skPtr, skPtr + FALCON_SK_SIZE);   // wipe SK
    m._free(skPtr); m._free(msgPtr); m._free(sigPtr); m._free(sigLenPtr);
  }
}

/** Verify a Falcon-1024 compressed signature. */
export function falconVerify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const m = mod();
  const pkPtr = m._malloc(FALCON_PK_SIZE);
  const msgPtr = m._malloc(msg.length);
  const sigPtr = m._malloc(sig.length);
  try {
    m.HEAPU8.set(pk, pkPtr);
    m.HEAPU8.set(msg, msgPtr);
    m.HEAPU8.set(sig, sigPtr);
    const rc: number = m.ccall("falcon_wasm_verify", "number",
      ["number", "number", "number", "number", "number"],
      [pkPtr, msgPtr, msg.length, sigPtr, sig.length]);
    return rc === 0;
  } finally {
    m._free(pkPtr); m._free(msgPtr); m._free(sigPtr);
  }
}
