// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2017 The Decred developers
// Copyright (c) 2017 The Particl Core developers
//
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/particl/partsuite_partd/wire"
)

// Worst case script and input/output size estimates.
const (
	// redeemAtomicSwapSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script to redeem the atomic swap contract.  This
	// does not include final push for the contract itself.
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	//   - OP_DATA_32
	//   - 32 bytes secret
	//   - OP_TRUE
	redeemAtomicSwapSigScriptSize = 1 + 73 + 1 + 33 + 1 + 32 + 1

	// refundAtomicSwapSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script that refunds a P2SH atomic swap output.
	// This does not include final push for the contract itself.
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	//   - OP_FALSE
	refundAtomicSwapSigScriptSize = 1 + 73 + 1 + 33 + 1
)

const WITNESS_SCALE_FACTOR = 2

func sumOutputSerializeSizes(outputs []*wire.TxOut) (serializeSize int) {
	for _, txOut := range outputs {
		serializeSize += txOut.SerializeSize()
	}
	return serializeSize
}

func getVirtualSizeInner(sizeNoWitness int, sizeTotal int) int {
	return ((sizeNoWitness*(WITNESS_SCALE_FACTOR-1) + sizeTotal) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR
}

func getVirtualSize(tx *wire.MsgTx) int {
	return getVirtualSizeInner(tx.SerializeSizeStripped(), tx.SerializeSize())
}

// inputSize returns the size of the transaction input needed to include a
// signature script with size sigScriptSize.  It is calculated as:
//
//   - 32 bytes previous tx
//   - 4 bytes output index
//   - Compact int encoding sigScriptSize
//   - sigScriptSize bytes signature script
//   - 4 bytes sequence
func inputSize(sigScriptSize int) int {
	return 32 + 4 + wire.VarIntSerializeSize(uint64(sigScriptSize)) + sigScriptSize + 4
}

// estimateRedeemSerializeSize returns a worst case serialize size estimates for
// a transaction that redeems an atomic swap P2SH output.
func estimateRedeemSerializeSize(contract []byte, tx *wire.MsgTx) int {
	baseSize := tx.SerializeSize()
	// varintsize(height of stack) + height of stack, redeemSig, redeemPubKey, secret, b1, contract
	witnessSize := 6 + 73 + 33 + 32 + 1 + len(contract)
	return getVirtualSizeInner(baseSize, baseSize+witnessSize)
}

// estimateRefundSerializeSize returns a worst case serialize size estimates for
// a transaction that refunds an atomic swap P2SH output.
func estimateRefundSerializeSize(contract []byte, tx *wire.MsgTx) int {
	baseSize := tx.SerializeSize()
	// varintsize(height of stack) + height of stack, refundSig, refundPubKey, b0, contract
	witnessSize := 5 + 73 + 33 + 1 + len(contract)
	return getVirtualSizeInner(baseSize, baseSize+witnessSize)
}
