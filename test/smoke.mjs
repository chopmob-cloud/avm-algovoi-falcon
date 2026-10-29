// SPDX-License-Identifier: Apache-2.0
// Smoke test: run `npm install && npm run build` first, then `npm test`.
// Proves the decoupled slice works outside any wallet: deterministic keygen,
// sign/verify, and Algorand address derivation.
import { readFileSync } from "node:fs";
import {
  initFalcon, falconKeygen, falconSign, falconVerify,
  deriveFalconAddress, FALCON_PK_SIZE, FALCON_SK_SIZE,
  bindAction, attest, verifyAttestation, sha256hex,
} from "../dist/index.js";

const wasmBinary = readFileSync(new URL("../wasm/falcon.wasm", import.meta.url));
await initFalcon(wasmBinary);

const seed = new Uint8Array(48).fill(7);
const a = falconKeygen(seed);
const b = falconKeygen(seed);
const deterministic = Buffer.from(a.pk).equals(Buffer.from(b.pk));

const msg = new TextEncoder().encode("hello falcon");
const sig = falconSign(a.sk, msg);
const good = falconVerify(a.pk, msg, sig);
const bad = falconVerify(a.pk, new TextEncoder().encode("tampered"), sig);

const { address } = deriveFalconAddress(a.pk);

// -- input-length guards (fail-closed / throw, no WASM heap overflow) --------
let rejectsBadPk = false, rejectsBadSk = false, rejectsBadSeed = false;
try { falconKeygen(new Uint8Array(47)); } catch { rejectsBadSeed = true; }
try { falconSign(a.sk.subarray(0, 100), msg); } catch { rejectsBadSk = true; }
rejectsBadPk = falconVerify(a.pk.subarray(0, 100), msg, sig) === false;

// -- chain-neutral attestations ----------------------------------------------
const payload = bindAction({
  chain: "base", address: "0xabc", action: "pay",
  nonce: 1, amount: 2500000, recipient: "0xdef",
});
const att = await attest(a.sk, a.pk, payload);
const verdict = await verifyAttestation(a.pk, att);
const expectedRef = "sha256:" + await sha256hex(
  new TextEncoder().encode(
    // JCS of the payload bindAction produced, keys sorted by UTF-16 code unit
    '{"action":"pay","address":"0xabc","amount":2500000,"chain":"base","nonce":1,"recipient":"0xdef","typ":"algovoi.attestation.v1"}',
  ),
);
const attOk = verdict.ok === true && verdict.ref === expectedRef;

// tamper with the payload -> must fail closed
const tampered = { ...att, payload: { ...att.payload, amount: 9999999 } };
const tamperFails = (await verifyAttestation(a.pk, tampered)).ok === false;

// verify against a different key -> must fail closed (kid mismatch)
const other = falconKeygen(new Uint8Array(48).fill(9));
const wrongKeyFails = (await verifyAttestation(other.pk, att)).ok === false;

// mutated signature -> must fail closed
const badSig = { ...att, sig: att.sig.slice(0, -2) + (att.sig.endsWith("A") ? "BB" : "AA") };
const badSigFails = (await verifyAttestation(a.pk, badSig)).ok === false;

const ok = deterministic && good && !bad
  && a.pk.length === FALCON_PK_SIZE && a.sk.length === FALCON_SK_SIZE
  && address.length === 58
  && rejectsBadSeed && rejectsBadSk && rejectsBadPk
  && attOk && tamperFails && wrongKeyFails && badSigFails;

console.log("deterministic keygen:", deterministic);
console.log("sizes pk/sk/sig:", a.pk.length, a.sk.length, sig.length);
console.log("verify good/tampered:", good, "/", bad);
console.log("address:", address);
console.log("input guards seed/sk/pk:", rejectsBadSeed, rejectsBadSk, rejectsBadPk);
console.log("attestation ok/tamper/wrongkey/badsig:", attOk, tamperFails, wrongKeyFails, badSigFails);
console.log("attestation ref:", verdict.ref);
console.log(ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
