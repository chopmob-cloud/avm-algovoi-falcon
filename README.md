# algovoi-falcon

**Falcon-1024 keys, post-quantum accounts and chain-neutral
attestations.** Keygen, deterministic sign/verify, `falcon_verify` LogicSig
address derivation for Algorand, and a chain-neutral attestation layer that binds
a post-quantum signature to an action on the settlement chain and verifies it offline. A
small standalone library with no wallet, no vault, and no host-specific code.

## Covering other chains

On-chain Falcon verification only exists where a chain has a native verifier.
Algorand has the `falcon_verify` opcode, so a Falcon public key can back a real
spendable account (a LogicSig). Most chains do not have such an opcode, and
verifying a lattice signature inside a smart contract is prohibitively expensive.
So the library offers two surfaces:

- **Native PQC accounts** (`deriveFalconAddress`, txn-group helpers): where the
  chain verifies Falcon on-chain. Algorand today; an AVM chain such as VOI is a
  drop-in once its opcode is confirmed.
- **Chain-neutral attestations** (`attest`, `verifyAttestation`): a Falcon key
  signs the RFC 8785 (JCS) canonical bytes of a payload that binds the action to a
  chain, an account and a nonce. Anchor it in a transaction note, memo, calldata
  or log. A relying party recomputes the bytes and checks the signature fully
  offline, so this is chain-neutral: the attestation verifies offline regardless of the settlement chain, with no on-chain Falcon verifier required.

```ts
import { initFalcon, falconKeygen, attest, verifyAttestation, bindAction } from "algovoi-falcon";

await initFalcon(wasmBytes);
const { pk, sk } = falconKeygen();

const payload = bindAction({ chain: "base", address: "0x...", action: "pay", nonce: 1, amount: 2500000, recipient: "0x..." });
const att = await attest(sk, pk, payload);      // { payload, alg, kid, sig }

const verdict = await verifyAttestation(pk, att);   // fail-closed
// verdict.ok === true, verdict.ref === "sha256:" + SHA-256(JCS(payload))
```

The envelope shape and JCS discipline match the keystone agent passport, so a
verified attestation is also a content-addressed keystone record (its `ref` is the
keystone reference of the payload) and composes with keystone tooling.

```ts
import { initFalcon, falconKeygen, deriveFalconAddress, falconSign, falconVerify } from "algovoi-falcon";

// 1. supply the WASM binary once (fetch/read it however your runtime does)
await initFalcon(wasmBytes);              // browser: fetch(); Node: fs.readFileSync()

// 2. generate a keypair (deterministic from a 48-byte seed; random if omitted)
const { pk, sk, seed } = falconKeygen();  // store `seed` to recover the same keypair

// 3. derive the Algorand address (a LogicSig backed by the AVM falcon_verify opcode)
const { address, program } = deriveFalconAddress(pk);

// 4. sign / verify
const sig = falconSign(sk, message);
const ok  = falconVerify(pk, message, sig);
```

For sending transactions from a Falcon account, `buildFalconTxnGroup` and
`signFalconTxnGroup` handle the LogicSig byte-budget pooling (the program is
larger than the 1000-byte limit, so it is grouped with dummy transactions).

## Runtime-agnostic loading

You provide the `falcon.wasm` bytes to `initFalcon`, so the same code runs in a
browser, a browser extension, a web worker, or Node. Pin the binary if you like
— this is the SHA-256 of the `wasm/falcon.wasm` shipped in this package:

```ts
await initFalcon(wasmBytes, "556a2f61163f786288952704210c5cc5e158a60f6103c680b852da8fbb7ef922");
```

## Notes and caveats

- **`falcon_verify` opcode dependency.** The derived address is a LogicSig that
  verifies signatures on-chain with the AVM `falcon_verify` opcode. A Falcon
  account can always receive; **spending requires the target network to support
  that opcode.** Confirm availability on your chain before relying on it.
- **Off-curve derivation.** Address derivation uses counter 0 and performs no
  off-curve search. An on-curve address would only be exploitable by solving the
  ed25519 discrete log for that point (~2^-128, i.e. breaking the curve). For
  defence-in-depth off-curve selection, add an ed25519 point-decompression check
  and advance the counter (see `deriveFalconAddress`).
- **Seed backup.** `falconKeygen` returns the 48-byte seed; store it to recover
  the account. The secret key is 2305 bytes, so a compact seed backup is
  preferable to storing the raw key.
- **Standardisation.** Falcon is the lattice scheme NIST selected for
  standardisation as FN-DSA (draft FIPS 206). The bundled binary implements
  Algorand's *deterministic* Falcon-1024 variant — the format the AVM
  `falcon_verify` opcode checks — which is not identical to the FN-DSA standard.
- **Attestation payloads.** For canonicalisation to be unambiguous, attestation
  payloads are restricted to the JSON subset of strings, booleans, null, arrays,
  objects, and **integers** (a safe-integer `number` or a `bigint`). Non-integer
  or non-finite numbers are rejected rather than guessed at, so signer and
  verifier always agree on the canonical bytes.

## The WASM binary: provenance and license

`wasm/falcon.wasm` is an Emscripten build of the Algorand Falcon-1024 C library
([github.com/algorand/falcon](https://github.com/algorand/falcon)) plus a thin
`falcon_wasm.c` wrapper that exposes a deterministic seeded keygen
(`falcon_wasm_keygen(seed, pk, sk)`). The Algorand Falcon C library is provided
under the **MIT license** (Copyright (c) 2017-2020 Falcon Project), so the binary
is redistributable, including in commercial and closed-source products, provided
the MIT copyright and permission notice ship with it (see `NOTICE`).

The TypeScript in this package and the `falcon_wasm.c` wrapper are Apache-2.0
(AlgoVoi). The binary is built only from the MIT C sources above, using the
reproducible script in `native/` (see [`native/README.md`](native/README.md)),
so you can recompile and verify it yourself.

## Build and test

```bash
npm install
npm run build      # tsc -> dist/, copies the emscripten glue
npm test           # smoke test: deterministic keygen, sign/verify, address
```

## AlgoVoi AVM evidence & interoperability suite

This repository is one of a set of AlgoVoi projects for Algorand and Voi settlement evidence and cross-chain interoperability. A bridge or relayer executes a transfer; [avm-proofpack](https://github.com/chopmob-cloud/avm-proofpack) makes the underlying chain facts independently verifiable offline; and [avm-algovoi-falcon](https://github.com/chopmob-cloud/avm-algovoi-falcon) supplies post-quantum signing for keys, accounts and attestations. The row for **this repository** is shown in **bold**.

| Repository | Role |
|---|---|
| [avm-proofpack](https://github.com/chopmob-cloud/avm-proofpack) | Portable, offline-verifiable Algorand/Voi transaction evidence anchored in State Proofs — the shared evidence core. |
| **[avm-algovoi-falcon](https://github.com/chopmob-cloud/avm-algovoi-falcon)** | Falcon-1024 post-quantum keys, Algorand `falcon_verify` LogicSig accounts and offline attestations — the identity layer. |
| [avm-voi-algo-bridge](https://github.com/chopmob-cloud/avm-voi-algo-bridge) | VOI → Algorand mainnet bridge: on-chain log validator, escrow and relayer. |
| [avm-algo-voi-bridge](https://github.com/chopmob-cloud/avm-algo-voi-bridge) | Algorand → VOI mainnet bridge (reverse direction). |
| [avm-wormhole-ntt-relayer](https://github.com/chopmob-cloud/avm-wormhole-ntt-relayer) | Wormhole NTT relayer bridging tokens between Algorand and Base. |
| [avm-hbar-bridge-relayer](https://github.com/chopmob-cloud/avm-hbar-bridge-relayer) | Treasury-model bridge relayer between Algorand and Hedera (HBAR/HTS). |

## License

Apache-2.0 for the TypeScript. See `LICENSE` and `NOTICE`. The WASM binary's
license is separate (see above).
