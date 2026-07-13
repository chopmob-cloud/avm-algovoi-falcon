// SPDX-License-Identifier: Apache-2.0
/**
 * algovoi-falcon: Falcon-1024 (FIPS 206) keys and Algorand post-quantum accounts.
 *
 *   import { initFalcon, falconKeygen, deriveFalconAddress } from "algovoi-falcon";
 *
 * Standalone: no wallet, no vault, no host-specific code. Supply the WASM binary
 * once with initFalcon(), then generate keys, derive Algorand addresses backed by
 * the AVM falcon_verify opcode, and sign/verify.
 */
export {
  initFalcon,
  falconKeygen,
  falconSign,
  falconVerify,
  sha256hex,
  FALCON_PK_SIZE,
  FALCON_SK_SIZE,
} from "./falcon.js";

export {
  buildFalconLogicSigProgram,
  deriveFalconAddress,
  buildFalconTxnGroup,
  signFalconTxnGroup,
  FALCON_DUMMY_TXN_COUNT,
} from "./address.js";
