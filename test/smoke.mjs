// SPDX-License-Identifier: Apache-2.0
// Smoke test: run `npm install && npm run build` first, then `npm test`.
// Proves the decoupled slice works outside any wallet: deterministic keygen,
// sign/verify, and Algorand address derivation.
import { readFileSync } from "node:fs";
import {
  initFalcon, falconKeygen, falconSign, falconVerify,
  deriveFalconAddress, FALCON_PK_SIZE, FALCON_SK_SIZE,
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

const ok = deterministic && good && !bad
  && a.pk.length === FALCON_PK_SIZE && a.sk.length === FALCON_SK_SIZE
  && address.length === 58;

console.log("deterministic keygen:", deterministic);
console.log("sizes pk/sk/sig:", a.pk.length, a.sk.length, sig.length);
console.log("verify good/tampered:", good, "/", bad);
console.log("address:", address);
console.log(ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
