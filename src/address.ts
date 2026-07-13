// SPDX-License-Identifier: Apache-2.0
/**
 * Falcon-1024 TEAL logic-sig template + Algorand address derivation.
 *
 * The program embeds the full 1793-byte Falcon public key and uses the AVM
 * `falcon_verify` opcode to verify transaction signatures on-chain. Follows the
 * Algorand Foundation's precompiled PQ logic-sig format
 * (github.com/algorandfoundation/falcon-signatures).
 *
 * Because the logic sig exceeds 1000 bytes, transactions are grouped with dummy
 * transactions to pool the byte budget (see buildFalconTxnGroup).
 */
import algosdk from "algosdk";

/**
 * Build the compiled PQ logic-sig program bytes.
 *
 *   offset | bytes           | teal opcode
 *   -------|-----------------|---------------------------
 *        0 | 0c              | #pragma version 12
 *        1 | 26 01 01 CC     | bytecblock 0xCC (counter byte)
 *        5 | 31 17           | txn TxID
 *        7 | 2d              | arg 0 (Falcon signature)
 *        8 | 80 81 0e <PK>   | pushbytes <1793-byte PK>
 *     1804 | 85              | falcon_verify
 */
export function buildFalconLogicSigProgram(pk: Uint8Array, counter = 0): Uint8Array {
  const header = new Uint8Array([
    0x0c,                   // #pragma version 12
    0x26, 0x01, 0x01, 0x00, // bytecblock 0x00
    0x31, 0x17,             // txn TxID
    0x2d,                   // arg 0
    0x80, 0x81, 0x0e,       // pushbytes varuint(1793)
  ]);
  header[4] = counter;
  const program = new Uint8Array(header.length + pk.length + 1);
  program.set(header, 0);
  program.set(pk, header.length);
  program[program.length - 1] = 0x85; // falcon_verify
  return program;
}

/**
 * Derive the Algorand address for a Falcon public key.
 *
 * The address is the logic-sig address of the program that embeds `pk`. Counter
 * 0 is used; no off-curve search is performed. An on-curve address would only be
 * exploitable by an Ed25519 keyholder able to solve the discrete log for that
 * point (~2^-128, i.e. breaking the curve). For defence-in-depth off-curve
 * selection, decode the address's 32-byte public key, reject it if it is a valid
 * ed25519 point, and advance the counter.
 */
export function deriveFalconAddress(pk: Uint8Array): { program: Uint8Array; address: string; counter: number } {
  const counter = 0;
  const program = buildFalconLogicSigProgram(pk, counter);
  const address = new algosdk.LogicSig(program).address().toString();
  return { program, address, counter };
}

/**
 * Dummy logic sig for group byte-budget pooling.
 * TEAL: #pragma version 3; txn RekeyTo; global ZeroAddress; ==  (approves any non-rekey txn).
 */
const DUMMY_PROGRAM = new Uint8Array([0x03, 0x31, 0x20, 0x32, 0x03, 0x12]);

/**
 * Number of dummy transactions needed to pool the logic-sig byte budget.
 * Falcon logic sig ~1805 B compiled + ~1237 B signature arg = ~3042 B; each txn
 * contributes 1000 B, so 3 dummies (4 x 1000 = 4000) cover it.
 */
export const FALCON_DUMMY_TXN_COUNT = 3;

/**
 * Build a grouped transaction set for a Falcon logic sig (real txn + 3 dummies).
 * The real txn's fee is bumped to cover the dummies, and a group ID is assigned
 * so the Falcon signature (over the real txn's TxID) is bound to this exact group.
 */
export function buildFalconTxnGroup(
  realTxn: algosdk.Transaction,
  suggestedParams: algosdk.SuggestedParams,
): algosdk.Transaction[] {
  const dummyLsig = new algosdk.LogicSig(DUMMY_PROGRAM);
  const dummyAddr = dummyLsig.address().toString();

  const dummies: algosdk.Transaction[] = [];
  for (let i = 0; i < FALCON_DUMMY_TXN_COUNT; i++) {
    dummies.push(algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: dummyAddr, receiver: dummyAddr, amount: 0,
      note: new Uint8Array([i]),
      suggestedParams: { ...suggestedParams, fee: BigInt(0), flatFee: true },
    }));
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const txnAny = realTxn as any;
  const baseFee = BigInt(txnAny.fee ?? suggestedParams.minFee ?? 1000);
  const extraFee = BigInt(suggestedParams.minFee ?? 1000) * BigInt(FALCON_DUMMY_TXN_COUNT);
  txnAny.fee = baseFee + extraFee;

  const group = [realTxn, ...dummies];
  const groupId = algosdk.computeGroupID(group);
  for (const txn of group) txn.group = groupId;
  return group;
}

/**
 * Assemble signed group bytes: the real txn signed by the Falcon logic sig
 * (signature over group[0].rawTxID()), the dummies by the dummy logic sig.
 */
export function signFalconTxnGroup(
  group: algosdk.Transaction[],
  program: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  if (group.length !== FALCON_DUMMY_TXN_COUNT + 1) {
    throw new Error(`Expected ${FALCON_DUMMY_TXN_COUNT + 1} transactions, got ${group.length}`);
  }
  const falconLsig = new algosdk.LogicSig(program, [signature]);
  const signedReal = algosdk.signLogicSigTransaction(group[0], falconLsig);
  const dummyLsig = new algosdk.LogicSig(DUMMY_PROGRAM);
  const signedDummies = group.slice(1).map((txn) => algosdk.signLogicSigTransaction(txn, dummyLsig));

  const totalLen = signedReal.blob.length + signedDummies.reduce((s, d) => s + d.blob.length, 0);
  const combined = new Uint8Array(totalLen);
  let offset = 0;
  combined.set(signedReal.blob, offset); offset += signedReal.blob.length;
  for (const d of signedDummies) { combined.set(d.blob, offset); offset += d.blob.length; }
  return combined;
}
