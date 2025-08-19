// Copyright (c) 2016 The btcsuite developers
// Copyright (c) 2016-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/btcsuite/btcd/wire"
)

const (
	// MaxCLTVScriptNum is the largest usable value for a CLTV lockTime. This
	// will actually be stored in a 5-byte ScriptNum since they have a sign bit,
	// however, it is not 2^39-1 since the spending transaction's nLocktime is
	// an unsigned 32-bit integer and it must be at least the CLTV value. This
	// establishes a maximum lock time of February 7, 2106. Any later requires
	// using a block height instead of a unix epoch time stamp.
	MaxCLTVScriptNum = 1<<32 - 1 // 0xffff_ffff a.k.a. 2^32-1

	// SecretHashSize is the byte-length of the hash of the secret key used in an
	// atomic swap.
	SecretHashSize = 32

	// SecretKeySize is the byte-length of the secret key used in an atomic swap.
	SecretKeySize = 32

	// ContractHashSize is the size of the script-hash for an atomic swap
	// contract.
	ContractHashSize = 20

	// PubKeyLength is the length of a serialized compressed public key.
	PubKeyLength = 33

	// 4 bytes version + 4 bytes locktime + 2 bytes of varints for the number of
	// transaction inputs and outputs
	MinimumBlockOverHead = 10

	// SwapContractSize is the worst case scenario size for a swap contract,
	// which is the pk-script of the non-change output of an initialization
	// transaction as used in execution of an atomic swap.
	// See ExtractSwapDetails for a breakdown of the bytes.
	SwapContractSize = 97

	// DERSigLength is the maximum length of a DER encoded signature with a
	// sighash type byte.
	DERSigLength = 73

	// RedeemSwapSigScriptSize is the worst case (largest) serialize size
	// of a transaction signature script that redeems atomic swap output contract.
	// It is calculated as:
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	//   - OP_DATA_32
	//   - 32 bytes secret key
	//   - OP_1
	//   - varint 97
	//   - 97 bytes redeem script
	RedeemSwapSigScriptSize = 1 + DERSigLength + 1 + 33 + 1 + 32 + 1 + 2 + 97

	// RefundSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script that refunds a compressed P2PKH output.
	// It is calculated as:
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	//   - OP_0
	//   - varint 97 => OP_PUSHDATA1(0x4c) + 0x61
	//   - 97 bytes contract
	RefundSigScriptSize = 1 + DERSigLength + 1 + 33 + 1 + 2 + 97

	// Overhead for a wire.TxIn. See wire.TxIn.SerializeSize.
	// hash 32 bytes + index 4 bytes + sequence 4 bytes.
	TxInOverhead = 32 + 4 + 4 // 40

	// TxOutOverhead is the overhead associated with a transaction output.
	// 8 bytes value + at least 1 byte varint script size
	TxOutOverhead = 8 + 1

	RedeemP2PKSigScriptSize = 1 + DERSigLength

	// RedeemP2PKHSigScriptSize is the worst case (largest) serialize size
	// of a transaction input script that redeems a compressed P2PKH output.
	// It is calculated as:
	//
	//   - OP_DATA_73
	//   - 72 bytes DER signature + 1 byte sighash
	//   - OP_DATA_33
	//   - 33 bytes serialized compressed pubkey
	RedeemP2PKHSigScriptSize = 1 + DERSigLength + 1 + 33 // 108

	// RedeemP2SHSigScriptSize does not include the redeem script.
	//RedeemP2SHSigScriptSize = 1 + DERSigLength + 1 + 1 + 33 + 1 // + redeem script!

	// P2PKHPkScriptSize is the size of a transaction output script that
	// pays to a compressed pubkey hash.  It is calculated as:
	//
	//   - OP_DUP
	//   - OP_HASH160
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	//   - OP_EQUALVERIFY
	//   - OP_CHECKSIG
	P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1 // 25

	// P2PKHOutputSize is the size of the serialized P2PKH output.
	P2PKHOutputSize = TxOutOverhead + P2PKHPkScriptSize // 9 + 25 = 34

	// P2SHPkScriptSize is the size of a transaction output script that
	// pays to a redeem script.  It is calculated as:
	//
	//   - OP_HASH160
	//   - OP_DATA_20
	//   - 20 bytes redeem script hash
	//   - OP_EQUAL
	P2SHPkScriptSize = 1 + 1 + 20 + 1

	// P2SHOutputSize is the size of the serialized P2SH output.
	P2SHOutputSize = TxOutOverhead + P2SHPkScriptSize // 9 + 23 = 32

	// P2WSHPkScriptSize is the size of a segwit transaction output script that
	// pays to a redeem script.  It is calculated as:
	//
	//   - OP_0
	//   - OP_DATA_32
	//   - 32 bytes redeem script hash
	P2WSHPkScriptSize = 1 + 1 + 32

	// P2WSHOutputSize is the size of the serialized P2WSH output.
	P2WSHOutputSize = TxOutOverhead + P2WSHPkScriptSize // 9 + 34 = 43

	// RedeemP2PKHInputSize is the worst case (largest) serialize size of a
	// transaction input redeeming a compressed P2PKH output.  It is
	// calculated as:
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 4 bytes sequence
	//   - 1 byte compact int encoding value 108
	//   - 108 bytes signature script
	RedeemP2PKHInputSize = TxInOverhead + 1 + RedeemP2PKHSigScriptSize // 40 + 1 + 108 = 149

	// RedeemP2WPKHInputSize is the worst case size of a transaction
	// input redeeming a P2WPKH output. This does not account for witness data,
	// which is considered at a lower weight for fee calculations. It is
	// calculated as
	//
	//   - 32 bytes previous tx
	//   - 4 bytes output index
	//   - 4 bytes sequence
	//   - 1 byte encoding empty redeem script
	//   - 0 bytes signature script
	RedeemP2WPKHInputSize = TxInOverhead + 1

	// RedeemP2WPKHInputWitnessWeight is the worst case weight of
	// a witness for spending P2WPKH and nested P2WPKH outputs. It
	// is calculated as:
	//
	//   - 1 wu compact int encoding value 2 (number of items)
	//   - 1 wu compact int encoding value 73
	//   - 72 wu DER signature + 1 wu sighash
	//   - 1 wu compact int encoding value 33
	//   - 33 wu serialized compressed pubkey
	// NOTE: witness data is not script.
	RedeemP2WPKHInputWitnessWeight = 1 + 1 + DERSigLength + 1 + 33 // 109

	// RedeemP2WPKHInputTotalSize is the worst case size of a transaction
	// input redeeming a P2WPKH output and the corresponding witness data.
	// It is calculated as:
	//
	// 41 vbytes base tx input
	// 109wu witness = 28 vbytes
	// total = 69 vbytes
	RedeemP2WPKHInputTotalSize = RedeemP2WPKHInputSize +
		(RedeemP2WPKHInputWitnessWeight+(witnessWeight-1))/witnessWeight

	// SigwitMarkerAndFlagWeight is the 2 bytes of overhead witness data
	// added to every segwit transaction.
	SegwitMarkerAndFlagWeight = 2

	// RedeemP2WSHInputWitnessWeight depends on the number of redeem script and
	// number of signatures.
	//  version + signatures + length of redeem script + redeem script
	// RedeemP2WSHInputWitnessWeight = 1 + N*DERSigLength + 1 + (redeem script bytes)

	// P2WPKHPkScriptSize is the size of a transaction output script that
	// pays to a witness pubkey hash. It is calculated as:
	//
	//   - OP_0
	//   - OP_DATA_20
	//   - 20 bytes pubkey hash
	P2WPKHPkScriptSize = 1 + 1 + 20

	// P2WPKHOutputSize is the serialize size of a transaction output with a
	// P2WPKH output script. It is calculated as:
	//
	//   - 8 bytes output value
	//   - 1 byte compact int encoding value 22
	//   - 22 bytes P2PKH output script
	P2WPKHOutputSize = TxOutOverhead + P2WPKHPkScriptSize // 31

	// MinimumTxOverhead is the size of an empty transaction.
	// 4 bytes version + 4 bytes locktime + 2 bytes of varints for the number of
	// transaction inputs and outputs
	MinimumTxOverhead = 4 + 4 + 1 + 1 // 10

	// InitTxSizeBase is the size of a standard serialized atomic swap
	// initialization transaction with one change output and no inputs. This is
	// MsgTx overhead + 1 P2PKH change output + 1 P2SH contract output. However,
	// the change output might be P2WPKH, in which case it would be smaller.
	InitTxSizeBase = MinimumTxOverhead + P2PKHOutputSize + P2SHOutputSize // 10 + 34 + 32 = 76
	// leaner with P2WPKH+P2SH outputs: 10 + 31 + 32 = 73

	// InitTxSize is InitTxBaseSize + 1 P2PKH input
	InitTxSize = InitTxSizeBase + RedeemP2PKHInputSize // 76 + 149 = 225
	// Varies greatly with some other input types, e.g nested witness (p2sh with
	// p2wpkh redeem script): 23 byte scriptSig + 108 byte (75 vbyte) witness = ~50

	// InitTxSizeBaseSegwit is the size of a standard serialized atomic swap
	// initialization transaction with one change output and no inputs. The
	// change output is assumed to be segwit. 10 + 31 + 43 = 84
	InitTxSizeBaseSegwit = MinimumTxOverhead + P2WPKHOutputSize + P2WSHOutputSize

	// InitTxSizeSegwit is InitTxSizeSegwit + 1 P2WPKH input.
	// 84 vbytes base tx
	// 41 vbytes base tx input
	// 109wu witness +  2wu segwit marker and flag = 28 vbytes
	// total = 153 vbytes
	InitTxSizeSegwit = InitTxSizeBaseSegwit + RedeemP2WPKHInputSize +
		(SegwitMarkerAndFlagWeight+RedeemP2WPKHInputWitnessWeight+(witnessWeight-1))/witnessWeight

	witnessWeight = 4 // github.com/btcsuite/btcd/blockchain.WitnessScaleFactor
)

// msgTxVBytes retuns vbytes. Call with MsgTx + the input(s) defined but no output yet
func msgTxVBytes(msgTx *wire.MsgTx) uint64 {
	baseSize := msgTx.SerializeSizeStripped()
	totalSize := msgTx.SerializeSize()
	txWeight := baseSize*(witnessWeight-1) + totalSize
	// vbytes is ceil(tx_weight/4)
	return uint64(txWeight+(witnessWeight-1)) / witnessWeight // +3 before / 4 to round up
}

// Refund worst case serial size estimates for fees - segwit
func refundTxSerialSizeEst(msgTx *wire.MsgTx) int {
	size := msgTxVBytes(msgTx)
	// include marker and flag weight.
	witnessVBytes := uint64((RefundSigScriptSize + 2 + 3) / 4)
	size += witnessVBytes + P2WPKHOutputSize
	return int(size)
}

// Redeem worst case serial size estimates for fees - segwit
func redeemTxSerialSizeEst(msgTx *wire.MsgTx) int { //241
	size := msgTxVBytes(msgTx)
	// include marker and flag weight.
	witnessVBytes := uint64((RedeemSwapSigScriptSize + 2 + 3) / 4)
	size += witnessVBytes + P2WPKHOutputSize
	return int(size)
}
