#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build wasm/falcon.wasm from source, reproducibly, with no external tooling repo.
#
# Sources (all MIT, vendored under ./falcon/): the Algorand Falcon-1024 C library
# (github.com/algorand/falcon, Copyright (c) 2017-2020 Falcon Project) plus our
# own falcon_wasm.c wrapper (Apache-2.0, AlgoVoi).
#
# Requires Emscripten (emcc) in PATH:  https://emscripten.org/docs/getting_started
# Usage:  bash native/build.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/falcon"
OUTDIR="$HERE/../wasm"
mkdir -p "$OUTDIR"

C_FILES=(
  "$SRC/codec.c" "$SRC/common.c" "$SRC/deterministic.c" "$SRC/falcon.c"
  "$SRC/fft.c" "$SRC/fpr.c" "$SRC/keygen.c" "$SRC/rng.c"
  "$SRC/shake.c" "$SRC/sign.c" "$SRC/vrfy.c"
  "$HERE/falcon_wasm.c"
)

EXPORTS='["_falcon_wasm_keygen","_falcon_wasm_sign","_falcon_wasm_verify","_falcon_wasm_pk_size","_falcon_wasm_sk_size","_falcon_wasm_sig_maxsize","_malloc","_free"]'

emcc \
  "${C_FILES[@]}" \
  -I "$SRC" \
  -o "$OUTDIR/falcon.js" \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME="FalconModule" \
  -s EXPORTED_FUNCTIONS="$EXPORTS" \
  -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","getValue","setValue","HEAPU8"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s INITIAL_MEMORY=16777216 \
  -s TOTAL_STACK=8388608 \
  -s ENVIRONMENT="web,worker,node" \
  -O2 \
  --no-entry

echo "Built:"
ls -la "$OUTDIR/falcon.js" "$OUTDIR/falcon.wasm"
echo "SHA-256 of falcon.wasm:"
sha256sum "$OUTDIR/falcon.wasm" 2>/dev/null || shasum -a 256 "$OUTDIR/falcon.wasm"
echo
echo "The emscripten glue is emitted as falcon.js. Copy its factory into"
echo "src/falcon-module-factory.js if you want to refresh the bundled glue."
