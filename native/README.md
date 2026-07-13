# Building `falcon.wasm` from source

This directory reproducibly builds `../wasm/falcon.wasm` from source, so the
binary in this package can be independently verified and rebuilt.

## What it compiles

- **`falcon/`** — the Algorand Falcon-1024 C library
  ([github.com/algorand/falcon](https://github.com/algorand/falcon)), vendored
  verbatim. MIT licensed, Copyright (c) 2017-2020 Falcon Project (see
  `falcon/LICENSE-falcon.txt`). This is the entire cryptographic core.
- **`falcon_wasm.c`** — a thin wrapper (AlgoVoi, Apache-2.0) exposing a
  deterministic seeded keygen and compressed sign/verify that match Algorand's
  AVM `falcon_verify` opcode.

Nothing else is involved. There is no AGPL-licensed tooling in this build path:
the sources above are the only inputs, and `build.sh` is our own.

## Build

```bash
# 1. install Emscripten: https://emscripten.org/docs/getting_started
# 2. from the package root:
bash native/build.sh
```

It emits `wasm/falcon.wasm` and `wasm/falcon.js` (the Emscripten glue) and prints
the binary's SHA-256. Deterministic keygen means a given seed always yields the
same keypair and address, so you can confirm a rebuilt binary matches the shipped
one behaviourally with `npm test`.

## Why rebuild

For a cryptographic dependency, a reproducible source-to-binary path is the point:
anyone can compile the wasm themselves from MIT sources and confirm it is what the
package ships, with no trust in a prebuilt blob.
