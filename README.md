# algovoi-falcon

**Falcon-1024 (FIPS 206) keys and Algorand post-quantum accounts.** Keygen,
deterministic sign/verify, and `falcon_verify` LogicSig address derivation, in a
small standalone library with no wallet, no vault, and no host-specific code.

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
browser, a browser extension, a web worker, or Node. Pin the binary if you like:

```ts
await initFalcon(wasmBytes, "311d79abcfca3898cce53c3b120dfe1acde0dc180716ff48dfdf159ba09650f8");
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

## The WASM binary: provenance and license

`wasm/falcon.wasm` is an Emscripten build of the Algorand Falcon-1024 C library
([github.com/algorand/falcon](https://github.com/algorand/falcon)) plus a thin
`falcon_wasm.c` wrapper that exposes a deterministic seeded keygen
(`falcon_wasm_keygen(seed, pk, sk)`). The Algorand Falcon C library is provided
under the **MIT license** (Copyright (c) 2017-2020 Falcon Project), so the binary
is redistributable, including in commercial and closed-source products, provided
the MIT copyright and permission notice ship with it (see `NOTICE`).

The TypeScript in this package and the `falcon_wasm.c` wrapper are Apache-2.0
(AlgoVoi). Note: the wasm is built with an Emscripten build script that lives in
an AGPL-licensed tooling repo, but that tooling is **not** compiled into the
binary; only the MIT C sources are. Do not redistribute that AGPL build tooling
inside a product.

## Build and test

```bash
npm install
npm run build      # tsc -> dist/, copies the emscripten glue
npm test           # smoke test: deterministic keygen, sign/verify, address
```

## License

Apache-2.0 for the TypeScript. See `LICENSE` and `NOTICE`. The WASM binary's
license is separate (see above).
