// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	rpc "github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/decred/atomicswap/cmd/btcatomicswap/adaptor"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
)

const verify = true

const secretSize = 32

const txVersion = 2

var (
	chainParams = &chaincfg.MainNetParams
)

var (
	flagset     = flag.NewFlagSet("", flag.ExitOnError)
	connectFlag = flagset.String("s", "localhost", "host[:port] of Bitcoin Core wallet RPC server")
	rpcuserFlag = flagset.String("rpcuser", "", "username for wallet RPC authentication")
	rpcpassFlag = flagset.String("rpcpass", "", "password for wallet RPC authentication")
	testnetFlag = flagset.Bool("testnet", false, "use testnet network")
	simnetFlag  = flagset.Bool("simnet", false, "use simnet network")
)

// There are two directions that the atomic swap can be performed, as the
// initiator can be on either chain.  This tool only deals with creating the
// Bitcoin transactions for these swaps.  A second tool should be used for the
// transaction on the other chain.  Any chain can be used so long as it supports
// OP_SHA256 and OP_CHECKLOCKTIMEVERIFY.
//
// Example scenerios using bitcoin as the second chain:
//
// Scenerio 1:
//   cp1 initiates (dcr)
//   cp2 participates with cp1 H(S) (btc)
//   cp1 redeems btc revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems dcr with S
//
// Scenerio 2:
//   cp1 initiates (btc)
//   cp2 participates with cp1 H(S) (dcr)
//   cp1 redeems dcr revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems btc with S

func init() {
	flagset.Usage = func() {
		fmt.Println("Usage: btcatomicswap [flags] cmd [cmd args]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  initiate <participant address> <amount>")
		fmt.Println("  participate <initiator address> <amount> <secret hash>")
		fmt.Println("  redeem <contract> <contract transaction> <secret>")
		fmt.Println("  refund <contract> <contract transaction>")
		fmt.Println("  extractsecret <redemption transaction> <secret hash>")
		fmt.Println("  auditcontract <contract> <contract transaction>")
		fmt.Println()
		fmt.Println("Private swap commands:")
		fmt.Println("  getpubkey")
		fmt.Println("  lockfunds <cp pub key> <amount> <initiator>")
		fmt.Println("  auditprivatecontract <redeem contract> <refund contract> <internal key nonce> <lock tx>")
		fmt.Println("  unsignedredemption <cp redeem contract> <cp refund contract> <cp internal key nonce> <cp tx>")
		fmt.Println("  initiateadaptor <our redeem contract> <our refund contract> <our internal key nonce> <our lock tx> <cp unsigned redeem tx>")
		fmt.Println("  verifyadaptor <cp redeem contract> <cp refund contract> <cp internal key nonce> <cp lock tx> <cp adaptor sig> <our unsigned redeem tx>")
		fmt.Println("  participateadaptor <our redeem contract> <our refund contract> <our internal key nonce> <our lock tx> <cp unsigned redeem> <cp adaptor>")
		fmt.Println("  privateredeem <cp redeem contract> <cp refund contract> <cp internal key nonce> <cp lock tx> <cp adaptor> <our unsigned redemption> <tweak>")
		fmt.Println("  extracttweak <cp redemption tx> <our adaptor sig>")
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

type command interface {
	runCommand(*rpc.Client) error
}

// offline commands don't require wallet RPC.
type offlineCommand interface {
	command
	runOfflineCommand() error
}

type initiateCmd struct {
	cp2Addr *btcutil.AddressPubKeyHash
	amount  btcutil.Amount
}

type participateCmd struct {
	cp1Addr    *btcutil.AddressPubKeyHash
	amount     btcutil.Amount
	secretHash []byte
}

type redeemCmd struct {
	contract   []byte
	contractTx *wire.MsgTx
	secret     []byte
}

type refundCmd struct {
	contract   []byte
	contractTx *wire.MsgTx
}

type extractSecretCmd struct {
	redemptionTx *wire.MsgTx
	secretHash   []byte
}

type auditContractCmd struct {
	contract   []byte
	contractTx *wire.MsgTx
}

// The following commands are for private atomic swaps:

type getPubKeyCmd struct{}

type lockFundsCmd struct {
	cpPubKey  *btcec.PublicKey
	amount    btcutil.Amount
	initiator bool
}

type unsignedRedemptionCmd struct {
	cpLockTx             *wire.MsgTx
	cpRedeemContract     []byte
	cpRefundContract     []byte
	cpTxInternalKeyNonce *secp256k1.ModNScalar
}

type initiateAdaptorCmd struct {
	ourRedeemContract     []byte
	ourRefundContract     []byte
	ourTxInternalKeyNonce *secp256k1.ModNScalar
	ourLockTx             *wire.MsgTx
	cpUnsignedRedeemTx    *wire.MsgTx
}

type verifyAdaptorCmd struct {
	cpRedeemContract     []byte
	cpRefundContract     []byte
	cpTxInternalKeyNonce *secp256k1.ModNScalar
	cpAdaptorSig         *adaptor.AdaptorSignature
	cpLockTx             *wire.MsgTx
	ourUnsignedRedeem    *wire.MsgTx
}

type participateAdaptorCmd struct {
	ourRedeemContract     []byte
	ourRefundContract     []byte
	ourTxInternalKeyNonce *secp256k1.ModNScalar
	ourLockTx             *wire.MsgTx
	cpUnsignedRedeemTx    *wire.MsgTx
	cpAdaptor             *adaptor.AdaptorSignature
}

type privateRedeemCmd struct {
	cpRedeemContract     []byte
	cpRefundContract     []byte
	cpTxInternalKeyNonce *secp256k1.ModNScalar
	cpLockTx             *wire.MsgTx
	cpAdaptor            *adaptor.AdaptorSignature
	unsignedRedemption   *wire.MsgTx
	tweak                *secp256k1.ModNScalar
}

type extractTweakCmd struct {
	cpRedeemTx *wire.MsgTx
	ourAdaptor *adaptor.AdaptorSignature
}

type auditPrivateContractCmd struct {
	redeemContract   []byte
	refundContract   []byte
	internalKeyNonce *secp256k1.ModNScalar
	lockTx           *wire.MsgTx
}

func main() {
	err, showUsage := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if showUsage {
		flagset.Usage()
	}
	if err != nil || showUsage {
		os.Exit(1)
	}
}

func checkCmdArgLength(args []string, required int) (nArgs int) {
	if len(args) < required {
		return 0
	}
	for i, arg := range args[:required] {
		if len(arg) != 1 && strings.HasPrefix(arg, "-") {
			return i
		}
	}
	return required
}

func run() (err error, showUsage bool) {
	flagset.Parse(os.Args[1:])
	args := flagset.Args()
	if len(args) == 0 {
		return nil, true
	}
	cmdArgs := 0
	switch args[0] {
	case "initiate":
		cmdArgs = 2
	case "participate":
		cmdArgs = 3
	case "redeem":
		cmdArgs = 3
	case "refund":
		cmdArgs = 2
	case "extractsecret":
		cmdArgs = 2
	case "auditcontract":
		cmdArgs = 2
	case "lockfunds":
		cmdArgs = 3
	case "unsignedredemption":
		cmdArgs = 4
	case "initiateadaptor":
		cmdArgs = 5
	case "verifyadaptor":
		cmdArgs = 6
	case "participateadaptor":
		cmdArgs = 6
	case "privateredeem":
		cmdArgs = 7
	case "getpubkey":
		cmdArgs = 0
	case "extracttweak":
		cmdArgs = 2
	case "auditprivatecontract":
		cmdArgs = 4
	default:
		return fmt.Errorf("unknown command %v", args[0]), true
	}
	nArgs := checkCmdArgLength(args[1:], cmdArgs)
	flagset.Parse(args[1+nArgs:])
	if nArgs < cmdArgs {
		return fmt.Errorf("%s: too few arguments", args[0]), true
	}
	if flagset.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flagset.Arg(0)), true
	}

	if *testnetFlag {
		chainParams = &chaincfg.TestNet3Params
	}
	if *simnetFlag {
		chainParams = &chaincfg.RegressionNetParams
	}

	var cmd command
	switch args[0] {
	case "initiate":
		cp2Addr, err := btcutil.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode participant address: %v", err), true
		}
		if !cp2Addr.IsForNet(chainParams) {
			return fmt.Errorf("participant address is not "+
				"intended for use on %v", chainParams.Name), true
		}
		cp2AddrP2PKH, ok := cp2Addr.(*btcutil.AddressPubKeyHash)
		if !ok {
			return errors.New("participant address is not P2PKH"), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount, err := btcutil.NewAmount(amountF64)
		if err != nil {
			return err, true
		}

		cmd = &initiateCmd{cp2Addr: cp2AddrP2PKH, amount: amount}
	case "participate":
		cp1Addr, err := btcutil.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode initiator address: %v", err), true
		}
		if !cp1Addr.IsForNet(chainParams) {
			return fmt.Errorf("initiator address is not "+
				"intended for use on %v", chainParams.Name), true
		}
		cp1AddrP2PKH, ok := cp1Addr.(*btcutil.AddressPubKeyHash)
		if !ok {
			return errors.New("initiator address is not P2PKH"), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount, err := btcutil.NewAmount(amountF64)
		if err != nil {
			return err, true
		}

		secretHash, err := hex.DecodeString(args[3])
		if err != nil {
			return errors.New("secret hash must be hex encoded"), true
		}
		if len(secretHash) != sha256.Size {
			return errors.New("secret hash has wrong size"), true
		}

		cmd = &participateCmd{cp1Addr: cp1AddrP2PKH, amount: amount, secretHash: secretHash}

	case "redeem":
		contract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		contractTxBytes, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}
		var contractTx wire.MsgTx
		err = contractTx.Deserialize(bytes.NewReader(contractTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}

		secret, err := hex.DecodeString(args[3])
		if err != nil {
			return fmt.Errorf("failed to decode secret: %v", err), true
		}

		cmd = &redeemCmd{contract: contract, contractTx: &contractTx, secret: secret}

	case "refund":
		contract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		contractTxBytes, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}
		var contractTx wire.MsgTx
		err = contractTx.Deserialize(bytes.NewReader(contractTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}

		cmd = &refundCmd{contract: contract, contractTx: &contractTx}

	case "extractsecret":
		redemptionTxBytes, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode redemption transaction: %v", err), true
		}
		var redemptionTx wire.MsgTx
		err = redemptionTx.Deserialize(bytes.NewReader(redemptionTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode redemption transaction: %v", err), true
		}

		secretHash, err := hex.DecodeString(args[2])
		if err != nil {
			return errors.New("secret hash must be hex encoded"), true
		}
		if len(secretHash) != sha256.Size {
			return errors.New("secret hash has wrong size"), true
		}

		cmd = &extractSecretCmd{redemptionTx: &redemptionTx, secretHash: secretHash}

	case "auditcontract":
		contract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		contractTxBytes, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}
		var contractTx wire.MsgTx
		err = contractTx.Deserialize(bytes.NewReader(contractTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}

		cmd = &auditContractCmd{contract: contract, contractTx: &contractTx}
	case "lockfunds":
		cpPubKeyBytes, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty public key: %v", err), true
		}
		if cpPubKeyBytes[0] != secp256k1.PubKeyFormatCompressedEven {
			return fmt.Errorf("counterparty public key must be even"), true
		}
		cpPubKey, err := btcec.ParsePubKey(cpPubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse counterparty public key: %v", err), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount, err := btcutil.NewAmount(amountF64)
		if err != nil {
			return err, true
		}

		isInitiator, err := strconv.ParseBool(args[3])
		if err != nil {
			return fmt.Errorf("failed to decode initiator flag: %v", err), true
		}

		cmd = &lockFundsCmd{
			cpPubKey:  cpPubKey,
			amount:    amount,
			initiator: isInitiator,
		}

	case "unsignedredemption":
		redeemContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to redeem contract: %v", err), true
		}

		refundContract, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to refund contract: %v", err), true
		}

		nonceBytes, err := hex.DecodeString(args[3])
		if err != nil {
			return err, true
		}
		internalKeyNonce := new(secp256k1.ModNScalar)
		internalKeyNonce.SetByteSlice(nonceBytes)

		txBytes, err := hex.DecodeString(args[4])
		if err != nil {
			return fmt.Errorf("failed to decode transaction: %v", err), true
		}
		var tx wire.MsgTx
		err = tx.Deserialize(bytes.NewReader(txBytes))
		if err != nil {
			return fmt.Errorf("failed to decode transaction: %v", err), true
		}

		cmd = &unsignedRedemptionCmd{
			cpLockTx:             &tx,
			cpTxInternalKeyNonce: internalKeyNonce,
			cpRedeemContract:     redeemContract,
			cpRefundContract:     refundContract,
		}
	case "initiateadaptor":
		ourRedeemContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode our redeem contract: %v", err), true
		}

		ourRefundContract, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode our refund contract: %v", err), true
		}

		nonceBytes, err := hex.DecodeString(args[3])
		if err != nil {
			return err, true
		}
		internalKeyNonce := new(secp256k1.ModNScalar)
		internalKeyNonce.SetByteSlice(nonceBytes)

		ourLockTxBytes, err := hex.DecodeString(args[4])
		if err != nil {
			return fmt.Errorf("failed to decode our lock transaction: %v", err), true
		}
		var ourLockTx wire.MsgTx
		err = ourLockTx.Deserialize(bytes.NewReader(ourLockTxBytes))
		if err != nil {
			return fmt.Errorf("failed to deserialize our lock transaction: %v", err), true
		}

		cpUnsignedRedeemTxBytes, err := hex.DecodeString(args[5])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty unsigned redeem transaction: %v", err), true
		}

		var cpUnsignedRedeemTx wire.MsgTx
		err = cpUnsignedRedeemTx.Deserialize(bytes.NewReader(cpUnsignedRedeemTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode counterparty unsigned redeem transaction: %v", err), true
		}

		cmd = &initiateAdaptorCmd{
			ourRedeemContract:     ourRedeemContract,
			ourRefundContract:     ourRefundContract,
			ourTxInternalKeyNonce: internalKeyNonce,
			ourLockTx:             &ourLockTx,
			cpUnsignedRedeemTx:    &cpUnsignedRedeemTx,
		}

	case "verifyadaptor":
		cpRedeemContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty redeem contract: %v", err), true
		}

		cpRefundContract, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty refund contract: %v", err), true
		}

		nonceBytes, err := hex.DecodeString(args[3])
		if err != nil {
			return err, true
		}
		internalKeyNonce := new(secp256k1.ModNScalar)
		internalKeyNonce.SetByteSlice(nonceBytes)

		cpLockTxBytes, err := hex.DecodeString(args[4])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty lock transaction: %v", err), true
		}

		cpAdaptorSigBytes, err := hex.DecodeString(args[5])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty adaptor signature: %v", err), true
		}
		cpAdaptorSig, err := adaptor.ParseAdaptorSignature(cpAdaptorSigBytes)
		if err != nil {
			return fmt.Errorf("failed to parse counterparty adaptor signature: %v", err), true
		}

		var cpLockTx wire.MsgTx
		err = cpLockTx.Deserialize(bytes.NewReader(cpLockTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode counterparty lock transaction: %v", err), true
		}

		ourUnsignedRedeemTxBytes, err := hex.DecodeString(args[6])
		if err != nil {
			return fmt.Errorf("failed to decode our unsigned redeem transaction: %v", err), true
		}

		var ourUnsignedRedeemTx wire.MsgTx
		err = ourUnsignedRedeemTx.Deserialize(bytes.NewReader(ourUnsignedRedeemTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode our unsigned redeem transaction: %v", err), true
		}

		cmd = &verifyAdaptorCmd{
			cpRedeemContract:     cpRedeemContract,
			cpRefundContract:     cpRefundContract,
			cpTxInternalKeyNonce: internalKeyNonce,
			cpAdaptorSig:         cpAdaptorSig,
			cpLockTx:             &cpLockTx,
			ourUnsignedRedeem:    &ourUnsignedRedeemTx,
		}
	case "participateadaptor":
		ourRedeemContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode our redeem contract: %v", err), true
		}

		ourRefundContract, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode our refund contract: %v", err), true
		}

		nonceBytes, err := hex.DecodeString(args[3])
		if err != nil {
			return err, true
		}
		internalKeyNonce := new(secp256k1.ModNScalar)
		internalKeyNonce.SetByteSlice(nonceBytes)

		ourLockTxBytes, err := hex.DecodeString(args[4])
		if err != nil {
			return fmt.Errorf("failed to decode our lock transaction: %v", err), true
		}

		var ourLockTx wire.MsgTx
		err = ourLockTx.Deserialize(bytes.NewReader(ourLockTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode our lock transaction: %v", err), true
		}

		cpUnsignedRedeemTxBytes, err := hex.DecodeString(args[5])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty unsigned redeem transaction: %v", err), true
		}

		var cpUnsignedRedeemTx wire.MsgTx
		err = cpUnsignedRedeemTx.Deserialize(bytes.NewReader(cpUnsignedRedeemTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode counterparty unsigned redeem transaction: %v", err), true
		}

		cpAdaptorSigBytes, err := hex.DecodeString(args[6])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty adaptor signature: %v", err), true
		}
		cpAdaptorSig, err := adaptor.ParseAdaptorSignature(cpAdaptorSigBytes)
		if err != nil {
			return fmt.Errorf("failed to parse counterparty adaptor signature: %v", err), true
		}

		cmd = &participateAdaptorCmd{
			ourRedeemContract:     ourRedeemContract,
			ourRefundContract:     ourRefundContract,
			ourTxInternalKeyNonce: internalKeyNonce,
			ourLockTx:             &ourLockTx,
			cpUnsignedRedeemTx:    &cpUnsignedRedeemTx,
			cpAdaptor:             cpAdaptorSig,
		}

	case "privateredeem":
		cpRedeemContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty redeem contract: %v", err), true
		}

		cpRefundContract, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty refund contract: %v", err), true
		}

		nonceBytes, err := hex.DecodeString(args[3])
		if err != nil {
			return err, true
		}
		internalKeyNonce := new(secp256k1.ModNScalar)
		internalKeyNonce.SetByteSlice(nonceBytes)

		cpLockTxBytes, err := hex.DecodeString(args[4])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty lock transaction: %v", err), true
		}

		var cpLockTx wire.MsgTx
		err = cpLockTx.Deserialize(bytes.NewReader(cpLockTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode counterparty lock transaction: %v", err), true
		}

		cpAdaptorSigBytes, err := hex.DecodeString(args[5])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty adaptor signature: %v", err), true
		}
		cpAdaptorSig, err := adaptor.ParseAdaptorSignature(cpAdaptorSigBytes)
		if err != nil {
			return fmt.Errorf("failed to parse counterparty adaptor signature: %v", err), true
		}

		unsignedRedemptionTxBytes, err := hex.DecodeString(args[6])
		if err != nil {
			return fmt.Errorf("failed to decode unsigned redemption transaction: %v", err), true
		}

		var unsignedRedemptionTx wire.MsgTx
		err = unsignedRedemptionTx.Deserialize(bytes.NewReader(unsignedRedemptionTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode unsigned redemption transaction: %v", err), true
		}

		tweakBytes, err := hex.DecodeString(args[7])
		if err != nil {
			return fmt.Errorf("failed to decode tweak: %v", err), true
		}
		var tweakBuf [32]byte
		copy(tweakBuf[:], tweakBytes)
		var tweak secp256k1.ModNScalar
		tweak.SetBytes(&tweakBuf)

		cmd = &privateRedeemCmd{
			cpRedeemContract:     cpRedeemContract,
			cpRefundContract:     cpRefundContract,
			cpTxInternalKeyNonce: internalKeyNonce,
			cpLockTx:             &cpLockTx,
			cpAdaptor:            cpAdaptorSig,
			unsignedRedemption:   &unsignedRedemptionTx,
			tweak:                &tweak,
		}
	case "getpubkey":
		cmd = &getPubKeyCmd{}
	case "extracttweak":
		cpRedeemTxBytes, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode counterparty redeem transaction: %v", err), true
		}

		var cpRedeemTx wire.MsgTx
		err = cpRedeemTx.Deserialize(bytes.NewReader(cpRedeemTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode counterparty redeem transaction: %v", err), true
		}

		ourAdaptorSigBytes, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode our adaptor signature: %v", err), true
		}
		ourAdaptorSig, err := adaptor.ParseAdaptorSignature(ourAdaptorSigBytes)
		if err != nil {
			return fmt.Errorf("failed to parse our adaptor signature: %v", err), true
		}

		cmd = &extractTweakCmd{
			cpRedeemTx: &cpRedeemTx,
			ourAdaptor: ourAdaptorSig,
		}
	case "auditprivatecontract":
		redeemContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode redeem contract: %v", err), true
		}

		refundContract, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("failed to decode refund contract: %v", err), true
		}

		nonceBytes, err := hex.DecodeString(args[3])
		if err != nil {
			return err, true
		}
		internalKeyNonce := new(secp256k1.ModNScalar)
		internalKeyNonce.SetByteSlice(nonceBytes)

		lockTxBytes, err := hex.DecodeString(args[4])
		if err != nil {
			return fmt.Errorf("failed to decode lock transaction: %v", err), true
		}

		var lockTx wire.MsgTx
		err = lockTx.Deserialize(bytes.NewReader(lockTxBytes))
		if err != nil {
			return fmt.Errorf("failed to decode lock transaction: %v", err), true
		}

		cmd = &auditPrivateContractCmd{
			redeemContract:   redeemContract,
			refundContract:   refundContract,
			internalKeyNonce: internalKeyNonce,
			lockTx:           &lockTx,
		}
	}

	// Offline commands don't need to talk to the wallet.
	if cmd, ok := cmd.(offlineCommand); ok {
		return cmd.runOfflineCommand(), false
	}

	connect, err := normalizeAddress(*connectFlag, walletPort(chainParams))
	if err != nil {
		return fmt.Errorf("wallet server address: %v", err), true
	}

	connConfig := &rpc.ConnConfig{
		Host:         connect,
		User:         *rpcuserFlag,
		Pass:         *rpcpassFlag,
		DisableTLS:   true,
		HTTPPostMode: true,
	}
	client, err := rpc.New(connConfig, nil)
	if err != nil {
		return fmt.Errorf("rpc connect: %v", err), false
	}
	defer func() {
		client.Shutdown()
		client.WaitForShutdown()
	}()

	err = cmd.runCommand(client)
	return err, false
}

func normalizeAddress(addr string, defaultPort string) (hostport string, err error) {
	host, port, origErr := net.SplitHostPort(addr)
	if origErr == nil {
		return net.JoinHostPort(host, port), nil
	}
	addr = net.JoinHostPort(addr, defaultPort)
	_, _, err = net.SplitHostPort(addr)
	if err != nil {
		return "", origErr
	}
	return addr, nil
}

func walletPort(params *chaincfg.Params) string {
	switch params {
	case &chaincfg.MainNetParams:
		return "8332"
	case &chaincfg.TestNet3Params:
		return "18332"
	default:
		return ""
	}
}

// createSig creates and returns the serialized raw signature and compressed
// pubkey for a transaction input signature.  Due to limitations of the Bitcoin
// Core RPC API, this requires dumping a private key and signing in the client,
// rather than letting the wallet sign.
func createSig(tx *wire.MsgTx, idx int, pkScript []byte, addr btcutil.Address,
	c *rpc.Client) (sig, pubkey []byte, err error) {

	wif, err := c.DumpPrivKey(addr)
	if err != nil {
		return nil, nil, err
	}
	sig, err = txscript.RawTxInSignature(tx, idx, pkScript, txscript.SigHashAll, wif.PrivKey)
	if err != nil {
		return nil, nil, err
	}
	return sig, wif.PrivKey.PubKey().SerializeCompressed(), nil
}

// fundRawTransaction calls the fundrawtransaction JSON-RPC method.  It is
// implemented manually as client support is currently missing from the
// btcd/rpcclient package.
func fundRawTransaction(c *rpc.Client, tx *wire.MsgTx, feePerKb btcutil.Amount) (fundedTx *wire.MsgTx, fee btcutil.Amount, err error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)
	param0, err := json.Marshal(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		return nil, 0, err
	}
	param1, err := json.Marshal(struct {
		FeeRate float64 `json:"feeRate"`
	}{
		FeeRate: feePerKb.ToBTC(),
	})
	if err != nil {
		return nil, 0, err
	}
	params := []json.RawMessage{param0, param1}
	rawResp, err := c.RawRequest("fundrawtransaction", params)
	if err != nil {
		return nil, 0, err
	}
	var resp struct {
		Hex       string  `json:"hex"`
		Fee       float64 `json:"fee"`
		ChangePos float64 `json:"changepos"`
	}
	err = json.Unmarshal(rawResp, &resp)
	if err != nil {
		return nil, 0, err
	}
	fundedTxBytes, err := hex.DecodeString(resp.Hex)
	if err != nil {
		return nil, 0, err
	}
	fundedTx = &wire.MsgTx{}
	err = fundedTx.Deserialize(bytes.NewReader(fundedTxBytes))
	if err != nil {
		return nil, 0, err
	}
	feeAmount, err := btcutil.NewAmount(resp.Fee)
	if err != nil {
		return nil, 0, err
	}
	return fundedTx, feeAmount, nil
}

// signRawTransaction calls the signRawTransaction JSON-RPC method.  It is
// implemented manually as client support is currently outdated from the
// btcd/rpcclient package.
func signRawTransaction(c *rpc.Client, tx *wire.MsgTx) (fundedTx *wire.MsgTx, complete bool, err error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)
	param, err := json.Marshal(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		return nil, false, err
	}
	rawResp, err := c.RawRequest("signrawtransactionwithwallet", []json.RawMessage{param})
	if err != nil {
		return nil, false, err
	}
	var resp struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	err = json.Unmarshal(rawResp, &resp)
	if err != nil {
		return nil, false, err
	}
	fundedTxBytes, err := hex.DecodeString(resp.Hex)
	if err != nil {
		return nil, false, err
	}
	fundedTx = &wire.MsgTx{}
	err = fundedTx.Deserialize(bytes.NewReader(fundedTxBytes))
	if err != nil {
		return nil, false, err
	}
	return fundedTx, resp.Complete, nil
}

// sendRawTransaction calls the signRawTransaction JSON-RPC method.  It is
// implemented manually as client support is currently outdated from the
// btcd/rpcclient package.
func sendRawTransaction(c *rpc.Client, tx *wire.MsgTx) (*chainhash.Hash, error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)

	param, err := json.Marshal(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		return nil, err
	}
	hex, err := c.RawRequest("sendrawtransaction", []json.RawMessage{param})
	if err != nil {
		return nil, err
	}
	s := string(hex)
	// we need to remove quotes from the json response
	s = s[1 : len(s)-1]
	hash, err := chainhash.NewHashFromStr(s)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

// getFeePerKb queries the wallet for the transaction relay fee/kB to use and
// the minimum mempool relay fee.  It first tries to get the user-set fee in the
// wallet.  If unset, it attempts to find an estimate using estimatefee 6.  If
// both of these fail, it falls back to mempool relay fee policy.
func getFeePerKb(c *rpc.Client) (useFee, relayFee btcutil.Amount, err error) {
	var netInfoResp struct {
		RelayFee float64 `json:"relayfee"`
	}
	var walletInfoResp struct {
		PayTxFee float64 `json:"paytxfee"`
	}
	var estimateResp struct {
		FeeRate float64 `json:"feerate"`
	}

	netInfoRawResp, err := c.RawRequest("getnetworkinfo", nil)
	if err == nil {
		err = json.Unmarshal(netInfoRawResp, &netInfoResp)
		if err != nil {
			return 0, 0, err
		}
	}
	walletInfoRawResp, err := c.RawRequest("getwalletinfo", nil)
	if err == nil {
		err = json.Unmarshal(walletInfoRawResp, &walletInfoResp)
		if err != nil {
			return 0, 0, err
		}
	}

	relayFee, err = btcutil.NewAmount(netInfoResp.RelayFee)
	if err != nil {
		return 0, 0, err
	}
	payTxFee, err := btcutil.NewAmount(walletInfoResp.PayTxFee)
	if err != nil {
		return 0, 0, err
	}

	// Use user-set wallet fee when set and not lower than the network relay
	// fee.
	if payTxFee != 0 {
		maxFee := payTxFee
		if relayFee > maxFee {
			maxFee = relayFee
		}
		return maxFee, relayFee, nil
	}

	params := []json.RawMessage{[]byte("6")}
	estimateRawResp, err := c.RawRequest("estimatesmartfee", params)
	if err != nil {
		return 0, 0, err
	}

	err = json.Unmarshal(estimateRawResp, &estimateResp)
	if err == nil && estimateResp.FeeRate > 0 {
		useFee, err = btcutil.NewAmount(estimateResp.FeeRate)
		if relayFee > useFee {
			useFee = relayFee
		}
		return useFee, relayFee, err
	}

	fmt.Println("warning: falling back to mempool relay fee policy")
	return relayFee, relayFee, nil
}

// getRawChangeAddress calls the getrawchangeaddress JSON-RPC method.  It is
// implemented manually as the rpcclient implementation always passes the
// account parameter which was removed in Bitcoin Core 0.15.
func getRawChangeAddress(c *rpc.Client) (btcutil.Address, error) {
	params := []json.RawMessage{[]byte(`"legacy"`)}
	rawResp, err := c.RawRequest("getrawchangeaddress", params)
	if err != nil {
		return nil, err
	}
	var addrStr string
	err = json.Unmarshal(rawResp, &addrStr)
	if err != nil {
		return nil, err
	}
	addr, err := btcutil.DecodeAddress(addrStr, chainParams)
	if err != nil {
		return nil, err
	}
	if !addr.IsForNet(chainParams) {
		return nil, fmt.Errorf("address %v is not intended for use on %v",
			addrStr, chainParams.Name)
	}
	if _, ok := addr.(*btcutil.AddressPubKeyHash); !ok {
		return nil, fmt.Errorf("getrawchangeaddress: address %v is not P2PKH",
			addr)
	}
	return addr, nil
}

func promptPublishTx(c *rpc.Client, tx *wire.MsgTx, name string) error {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Publish %s transaction? [y/N] ", name)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		answer = strings.TrimSpace(strings.ToLower(answer))

		switch answer {
		case "y", "yes":
		case "n", "no", "":
			return nil
		default:
			fmt.Println("please answer y or n")
			continue
		}

		txHash, err := sendRawTransaction(c, tx)
		if err != nil {
			return fmt.Errorf("sendrawtransaction: %v", err)
		}
		fmt.Printf("Published %s transaction (%v)\n", name, txHash)

		return nil
	}
}

// contractArgs specifies the common parameters used to create the initiator's
// and participant's contract.
type contractArgs struct {
	them       *btcutil.AddressPubKeyHash
	amount     btcutil.Amount
	locktime   int64
	secretHash []byte
}

// builtContract houses the details regarding a contract and the contract
// payment transaction, as well as the transaction to perform a refund.
type builtContract struct {
	contract       []byte
	contractP2SH   btcutil.Address
	contractTxHash *chainhash.Hash
	contractTx     *wire.MsgTx
	contractFee    btcutil.Amount
	refundTx       *wire.MsgTx
	refundFee      btcutil.Amount
}

// buildContract creates a contract for the parameters specified in args, using
// wallet RPC to generate an internal address to redeem the refund and to sign
// the payment to the contract transaction.
func buildContract(c *rpc.Client, args *contractArgs) (*builtContract, error) {
	refundAddr, err := getRawChangeAddress(c)
	if err != nil {
		return nil, fmt.Errorf("getrawchangeaddress: %v", err)
	}
	refundAddrH, ok := refundAddr.(interface {
		Hash160() *[ripemd160.Size]byte
	})
	if !ok {
		return nil, errors.New("unable to create hash160 from change address")
	}

	contract, err := atomicSwapContract(refundAddrH.Hash160(), args.them.Hash160(),
		args.locktime, args.secretHash)
	if err != nil {
		return nil, err
	}
	contractP2SH, err := btcutil.NewAddressScriptHash(contract, chainParams)
	if err != nil {
		return nil, err
	}
	contractP2SHPkScript, err := txscript.PayToAddrScript(contractP2SH)
	if err != nil {
		return nil, err
	}

	feePerKb, minFeePerKb, err := getFeePerKb(c)
	if err != nil {
		return nil, err
	}

	unsignedContract := wire.NewMsgTx(txVersion)
	unsignedContract.AddTxOut(wire.NewTxOut(int64(args.amount), contractP2SHPkScript))
	unsignedContract, contractFee, err := fundRawTransaction(c, unsignedContract, feePerKb)
	if err != nil {
		return nil, fmt.Errorf("fundrawtransaction: %v", err)
	}
	contractTx, complete, err := signRawTransaction(c, unsignedContract)
	if err != nil {
		return nil, fmt.Errorf("signrawtransaction: %v", err)
	}
	if !complete {
		return nil, errors.New("signrawtransaction: failed to completely sign contract transaction")
	}

	contractTxHash := contractTx.TxHash()

	refundTx, refundFee, err := buildRefund(c, contract, contractTx, feePerKb, minFeePerKb)
	if err != nil {
		return nil, err
	}

	return &builtContract{
		contract,
		contractP2SH,
		&contractTxHash,
		contractTx,
		contractFee,
		refundTx,
		refundFee,
	}, nil
}

func buildRefund(c *rpc.Client, contract []byte, contractTx *wire.MsgTx, feePerKb, minFeePerKb btcutil.Amount) (
	refundTx *wire.MsgTx, refundFee btcutil.Amount, err error) {
	contractP2SH, err := btcutil.NewAddressScriptHash(contract, chainParams)
	if err != nil {
		return nil, 0, err
	}
	contractP2SHPkScript, err := txscript.PayToAddrScript(contractP2SH)
	if err != nil {
		return nil, 0, err
	}

	contractTxHash := contractTx.TxHash()
	contractOutPoint := wire.OutPoint{Hash: contractTxHash, Index: ^uint32(0)}
	for i, o := range contractTx.TxOut {
		if bytes.Equal(o.PkScript, contractP2SHPkScript) {
			contractOutPoint.Index = uint32(i)
			break
		}
	}
	if contractOutPoint.Index == ^uint32(0) {
		return nil, 0, errors.New("contract tx does not contain a P2SH contract payment")
	}

	refundAddress, err := getRawChangeAddress(c)
	if err != nil {
		return nil, 0, fmt.Errorf("getrawchangeaddress: %v", err)
	}
	refundOutScript, err := txscript.PayToAddrScript(refundAddress)
	if err != nil {
		return nil, 0, err
	}

	pushes, err := txscript.ExtractAtomicSwapDataPushes(0, contract)
	if err != nil {
		// expected to only be called with good input
		panic(err)
	}

	refundAddr, err := btcutil.NewAddressPubKeyHash(pushes.RefundHash160[:], chainParams)
	if err != nil {
		return nil, 0, err
	}

	refundTx = wire.NewMsgTx(txVersion)
	refundTx.LockTime = uint32(pushes.LockTime)
	refundTx.AddTxOut(wire.NewTxOut(0, refundOutScript)) // amount set below
	refundSize := estimateRefundSerializeSize(contract, refundTx.TxOut)
	refundFee = txrules.FeeForSerializeSize(feePerKb, refundSize)
	refundTx.TxOut[0].Value = contractTx.TxOut[contractOutPoint.Index].Value - int64(refundFee)
	if txrules.IsDustOutput(refundTx.TxOut[0], minFeePerKb) {
		return nil, 0, fmt.Errorf("refund output value of %v is dust", btcutil.Amount(refundTx.TxOut[0].Value))
	}

	txIn := wire.NewTxIn(&contractOutPoint, nil, nil)
	txIn.Sequence = 0
	refundTx.AddTxIn(txIn)

	refundSig, refundPubKey, err := createSig(refundTx, 0, contract, refundAddr, c)
	if err != nil {
		return nil, 0, err
	}
	refundSigScript, err := refundP2SHContract(contract, refundSig, refundPubKey)
	if err != nil {
		return nil, 0, err
	}
	refundTx.TxIn[0].SignatureScript = refundSigScript

	if verify {
		prevOut := contractTx.TxOut[contractOutPoint.Index]
		a := txscript.NewCannedPrevOutputFetcher(prevOut.PkScript, prevOut.Value)
		e, err := txscript.NewEngine(contractTx.TxOut[contractOutPoint.Index].PkScript,
			refundTx, 0, txscript.StandardVerifyFlags, txscript.NewSigCache(10),
			txscript.NewTxSigHashes(refundTx, a), contractTx.TxOut[contractOutPoint.Index].Value, a)
		if err != nil {
			panic(err)
		}
		err = e.Execute()
		if err != nil {
			panic(err)
		}
	}

	return refundTx, refundFee, nil

}

type privateContractArgs struct {
	us          *btcec.PublicKey
	them        *btcec.PublicKey
	amount      btcutil.Amount
	locktime    int64
	internalKey *secp256k1.PublicKey
}

type builtPrivateContract struct {
	redeemContract []byte
	refundContract []byte
	contractTxHash *chainhash.Hash
	contractTx     *wire.MsgTx
	contractFee    btcutil.Amount
	refundTx       *wire.MsgTx
	refundFee      btcutil.Amount
}

// fakeInternalKey creates a fake internal key using a given nonce. This is required
// becuase only the redeem and refund branches in the script tree can be used to
// spend the contract output.
// The details of this can be found in BIP341:
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
func fakeInternalKey(nonce *secp256k1.ModNScalar) *secp256k1.PublicKey {
	gx := new(secp256k1.FieldVal)
	gx.SetByteSlice(secp256k1.Params().Gx.Bytes())

	gy := new(secp256k1.FieldVal)
	gy.SetByteSlice(secp256k1.Params().Gy.Bytes())

	g := secp256k1.NewPublicKey(gx, gy)
	gHash := sha256.Sum256(g.SerializeUncompressed())

	pubKey, err := secp256k1.ParsePubKey(append([]byte{secp256k1.PubKeyFormatCompressedEven}, gHash[:]...))
	if err != nil {
		panic(fmt.Sprintf("failed to create fake internal key: %v", err))
	}

	var jacobianPubKey secp256k1.JacobianPoint
	pubKey.AsJacobian(&jacobianPubKey)

	var jacobianInternalKey secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(nonce, &jacobianPubKey, &jacobianInternalKey)
	jacobianInternalKey.ToAffine()

	return secp256k1.NewPublicKey(&jacobianInternalKey.X, &jacobianInternalKey.Y)
}

func buildPrivateContract(c *rpc.Client, args *privateContractArgs) (*builtPrivateContract, error) {
	redeemScript, err := privateAtomicSwapRedeemScript(args.us, args.them)
	if err != nil {
		return nil, err
	}

	refundScript, err := privateAtomicSwapRefundScript(args.us, args.locktime)
	if err != nil {
		return nil, err
	}

	normalLeaf := txscript.NewBaseTapLeaf(redeemScript)
	refundLeaf := txscript.NewBaseTapLeaf(refundScript)
	tapScriptTree := txscript.AssembleTaprootScriptTree(normalLeaf, refundLeaf)
	tapScriptRootHash := tapScriptTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(args.internalKey, tapScriptRootHash[:])
	pkScript, err := payToTaprootScript(outputKey)
	if err != nil {
		return nil, err
	}
	refundControlBlock := tapScriptTree.LeafMerkleProofs[1].ToControlBlock(args.internalKey)

	feePerKb, _, err := getFeePerKb(c)
	if err != nil {
		return nil, err
	}
	unsignedContract := wire.NewMsgTx(txVersion)
	unsignedContract.AddTxOut(wire.NewTxOut(int64(args.amount), pkScript))
	unsignedContract, contractFee, err := fundRawTransaction(c, unsignedContract, feePerKb)
	if err != nil {
		return nil, fmt.Errorf("fundrawtransaction: %v", err)
	}

	contractTx, complete, err := signRawTransaction(c, unsignedContract)
	if err != nil {
		return nil, fmt.Errorf("signrawtransaction: %v", err)
	}
	if !complete {
		return nil, errors.New("signrawtransaction: failed to completely sign contract transaction")
	}
	contractTxHash := contractTx.TxHash()

	refundTx, refundFee, err := buildPrivateRefund(c, pkScript, refundScript, args.locktime, args.us, refundLeaf, &refundControlBlock, contractTx)
	if err != nil {
		return nil, err
	}

	return &builtPrivateContract{
		redeemScript,
		refundScript,
		&contractTxHash,
		contractTx,
		contractFee,
		refundTx,
		refundFee,
	}, nil
}

func getPrivKeyFromPubKey(c *rpc.Client, pubKey *btcec.PublicKey) (*btcec.PrivateKey, error) {
	address, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), chainParams)
	if err != nil {
		return nil, err
	}
	wif, err := c.DumpPrivKey(address)
	if err != nil {
		return nil, err
	}
	return wif.PrivKey, nil
}

func buildPrivateRefund(c *rpc.Client, pkScript, refundScript []byte, lockTime int64, pubKey *secp256k1.PublicKey,
	refundLeaf txscript.TapLeaf, controlBlock *txscript.ControlBlock, contractTx *wire.MsgTx) (*wire.MsgTx, btcutil.Amount, error) {
	contractOutPoint := wire.OutPoint{Hash: contractTx.TxHash(), Index: ^uint32(0)}
	var contractTxOut *wire.TxOut
	for i, out := range contractTx.TxOut {
		if bytes.Equal(out.PkScript, pkScript) {
			contractOutPoint.Index = uint32(i)
			contractTxOut = out
			break
		}
	}
	if contractOutPoint.Index == ^uint32(0) {
		return nil, 0, errors.New("transaction does not contain a contract output")
	}

	address, err := getNewAddress(c)
	if err != nil {
		return nil, 0, fmt.Errorf("error getting new address: %v", err)
	}
	addr, err := btcutil.DecodeAddress(address, chainParams)
	if err != nil {
		return nil, 0, err
	}
	outScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, 0, err
	}

	refundTx := wire.NewMsgTx(txVersion)
	refundTx.LockTime = uint32(lockTime)

	txIn := wire.NewTxIn(&contractOutPoint, nil, nil)
	txIn.Sequence = 0
	refundTx.AddTxIn(txIn)
	refundTx.AddTxOut(wire.NewTxOut(0, outScript))
	refundSize := estimatePrivateRefundSerializeSize(refundTx.TxOut)

	feePerKb, minFeePerKb, err := getFeePerKb(c)
	if err != nil {
		return nil, 0, err
	}
	fee := txrules.FeeForSerializeSize(feePerKb, refundSize)
	refundTx.TxOut[0].Value = contractTxOut.Value - int64(fee)
	if txrules.IsDustOutput(refundTx.TxOut[0], minFeePerKb) {
		return nil, 0, fmt.Errorf("redeem output value of %v is dust", btcutil.Amount(refundTx.TxOut[0].Value))
	}

	a := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		contractOutPoint: {
			Value:    contractTxOut.Value,
			PkScript: contractTxOut.PkScript,
		},
	})
	sigHashes := txscript.NewTxSigHashes(refundTx, a)

	privKey, err := getPrivKeyFromPubKey(c, pubKey)
	if err != nil {
		return nil, 0, err
	}
	defer privKey.Zero()

	sig, err := txscript.RawTxInTapscriptSignature(
		refundTx, sigHashes, 0, contractTxOut.Value, contractTxOut.PkScript, refundLeaf,
		txscript.SigHashDefault, privKey)
	if err != nil {
		return nil, 0, err
	}

	controlBlockB, err := controlBlock.ToBytes()
	if err != nil {
		return nil, 0, err
	}

	refundTx.TxIn[0].Witness = wire.TxWitness{sig, refundScript, controlBlockB}

	if verify {
		engine, err := txscript.NewEngine(contractTxOut.PkScript, refundTx, 0, txscript.StandardVerifyFlags,
			txscript.NewSigCache(10), sigHashes, contractTxOut.Value, a)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create verification engine for refund: %v", err)
		}
		err = engine.Execute()
		if err != nil {
			return nil, 0, fmt.Errorf("failed to execute verification engine for refund: %v", err)
		}
	}

	return refundTx, fee, nil
}

func sha256Hash(x []byte) []byte {
	h := sha256.Sum256(x)
	return h[:]
}

func calcFeePerKb(absoluteFee btcutil.Amount, serializeSize int) float64 {
	return float64(absoluteFee) / float64(serializeSize) / 1e5
}

func getNewAddress(c *rpc.Client) (string, error) {
	rawResp, err := c.RawRequest("getnewaddress", nil)
	if err != nil {
		return "", err
	}
	var addrStr string
	err = json.Unmarshal(rawResp, &addrStr)
	if err != nil {
		return "", err
	}
	addr, err := btcutil.DecodeAddress(addrStr, chainParams)
	if err != nil {
		return "", err
	}
	if !addr.IsForNet(chainParams) {
		return "", fmt.Errorf("address %v is not intended for use on %v",
			addrStr, chainParams.Name)
	}
	return addr.String(), nil
}

// getSchnorrPubKey returns a pub key that can be used for schnorr signing.
// Only pub keys with even y coordinates are supported.
func getSchnorrPubKey(c *rpc.Client) (*secp256k1.PublicKey, error) {
	var pubKeyB []byte
	for {
		rawAddrResp, err := c.RawRequest("getnewaddress", nil)
		if err != nil {
			return nil, err
		}
		type addressInfoResp struct {
			PubKey string `json:"pubkey"`
		}
		rawInfoResp, err := c.RawRequest("getaddressinfo", []json.RawMessage{rawAddrResp})
		if err != nil {
			return nil, err
		}
		infoResp := addressInfoResp{}
		err = json.Unmarshal(rawInfoResp, &infoResp)
		if err != nil {
			return nil, err
		}
		pubKeyB, err = hex.DecodeString(infoResp.PubKey)
		if err != nil {
			return nil, err
		}
		if len(pubKeyB) != 33 {
			return nil, fmt.Errorf("pubkey %x is not 33 bytes", pubKeyB)
		}
		if pubKeyB[0] == secp256k1.PubKeyFormatCompressedEven {
			break
		}
	}

	pk, err := btcec.ParsePubKey(pubKeyB)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func (cmd *initiateCmd) runCommand(c *rpc.Client) error {
	var secret [secretSize]byte
	_, err := rand.Read(secret[:])
	if err != nil {
		return err
	}
	secretHash := sha256Hash(secret[:])

	// locktime after 500,000,000 (Tue Nov  5 00:53:20 1985 UTC) is interpreted
	// as a unix time rather than a block height.
	locktime := time.Now().Add(48 * time.Hour).Unix()

	b, err := buildContract(c, &contractArgs{
		them:       cmd.cp2Addr,
		amount:     cmd.amount,
		locktime:   locktime,
		secretHash: secretHash,
	})
	if err != nil {
		return err
	}

	refundTxHash := b.refundTx.TxHash()
	contractFeePerKb := calcFeePerKb(b.contractFee, b.contractTx.SerializeSize())
	refundFeePerKb := calcFeePerKb(b.refundFee, b.refundTx.SerializeSize())

	fmt.Printf("Secret:      %x\n", secret)
	fmt.Printf("Secret hash: %x\n\n", secretHash)
	fmt.Printf("Contract fee: %v (%0.8f BTC/kB)\n", b.contractFee, contractFeePerKb)
	fmt.Printf("Refund fee:   %v (%0.8f BTC/kB)\n\n", b.refundFee, refundFeePerKb)
	fmt.Printf("Contract (%v):\n", b.contractP2SH)
	fmt.Printf("%x\n\n", b.contract)
	var contractBuf bytes.Buffer
	contractBuf.Grow(b.contractTx.SerializeSize())
	b.contractTx.Serialize(&contractBuf)
	fmt.Printf("Contract transaction (%v):\n", b.contractTxHash)
	fmt.Printf("%x\n\n", contractBuf.Bytes())
	var refundBuf bytes.Buffer
	refundBuf.Grow(b.refundTx.SerializeSize())
	b.refundTx.Serialize(&refundBuf)
	fmt.Printf("Refund transaction (%v):\n", &refundTxHash)
	fmt.Printf("%x\n\n", refundBuf.Bytes())

	return promptPublishTx(c, b.contractTx, "contract")
}

func (cmd *participateCmd) runCommand(c *rpc.Client) error {
	// locktime after 500,000,000 (Tue Nov  5 00:53:20 1985 UTC) is interpreted
	// as a unix time rather than a block height.
	locktime := time.Now().Add(24 * time.Hour).Unix()

	b, err := buildContract(c, &contractArgs{
		them:       cmd.cp1Addr,
		amount:     cmd.amount,
		locktime:   locktime,
		secretHash: cmd.secretHash,
	})
	if err != nil {
		return err
	}

	refundTxHash := b.refundTx.TxHash()
	contractFeePerKb := calcFeePerKb(b.contractFee, b.contractTx.SerializeSize())
	refundFeePerKb := calcFeePerKb(b.refundFee, b.refundTx.SerializeSize())

	fmt.Printf("Contract fee: %v (%0.8f BTC/kB)\n", b.contractFee, contractFeePerKb)
	fmt.Printf("Refund fee:   %v (%0.8f BTC/kB)\n\n", b.refundFee, refundFeePerKb)
	fmt.Printf("Contract (%v):\n", b.contractP2SH)
	fmt.Printf("%x\n\n", b.contract)
	var contractBuf bytes.Buffer
	contractBuf.Grow(b.contractTx.SerializeSize())
	b.contractTx.Serialize(&contractBuf)
	fmt.Printf("Contract transaction (%v):\n", b.contractTxHash)
	fmt.Printf("%x\n\n", contractBuf.Bytes())
	var refundBuf bytes.Buffer
	refundBuf.Grow(b.refundTx.SerializeSize())
	b.refundTx.Serialize(&refundBuf)
	fmt.Printf("Refund transaction (%v):\n", &refundTxHash)
	fmt.Printf("%x\n\n", refundBuf.Bytes())

	return promptPublishTx(c, b.contractTx, "contract")
}

func (cmd *redeemCmd) runCommand(c *rpc.Client) error {
	pushes, err := txscript.ExtractAtomicSwapDataPushes(0, cmd.contract)
	if err != nil {
		return err
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}
	recipientAddr, err := btcutil.NewAddressPubKeyHash(pushes.RecipientHash160[:],
		chainParams)
	if err != nil {
		return err
	}
	contractHash := btcutil.Hash160(cmd.contract)
	contractOut := -1
	for i, out := range cmd.contractTx.TxOut {
		sc, addrs, _, _ := txscript.ExtractPkScriptAddrs(out.PkScript, chainParams)
		if sc == txscript.ScriptHashTy &&
			bytes.Equal(addrs[0].(*btcutil.AddressScriptHash).Hash160()[:], contractHash) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain a contract output")
	}

	addr, err := getRawChangeAddress(c)
	if err != nil {
		return fmt.Errorf("getrawchangeaddress: %v", err)
	}
	outScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}

	contractTxHash := cmd.contractTx.TxHash()
	contractOutPoint := wire.OutPoint{
		Hash:  contractTxHash,
		Index: uint32(contractOut),
	}

	feePerKb, minFeePerKb, err := getFeePerKb(c)
	if err != nil {
		return err
	}

	redeemTx := wire.NewMsgTx(txVersion)
	redeemTx.LockTime = uint32(pushes.LockTime)
	redeemTx.AddTxIn(wire.NewTxIn(&contractOutPoint, nil, nil))
	redeemTx.AddTxOut(wire.NewTxOut(0, outScript)) // amount set below
	redeemSize := estimateRedeemSerializeSize(cmd.contract, redeemTx.TxOut)
	fee := txrules.FeeForSerializeSize(feePerKb, redeemSize)
	redeemTx.TxOut[0].Value = cmd.contractTx.TxOut[contractOut].Value - int64(fee)
	if txrules.IsDustOutput(redeemTx.TxOut[0], minFeePerKb) {
		return fmt.Errorf("redeem output value of %v is dust", btcutil.Amount(redeemTx.TxOut[0].Value))
	}

	redeemSig, redeemPubKey, err := createSig(redeemTx, 0, cmd.contract, recipientAddr, c)
	if err != nil {
		return err
	}
	redeemSigScript, err := redeemP2SHContract(cmd.contract, redeemSig, redeemPubKey, cmd.secret)
	if err != nil {
		return err
	}
	redeemTx.TxIn[0].SignatureScript = redeemSigScript

	redeemTxHash := redeemTx.TxHash()
	redeemFeePerKb := calcFeePerKb(fee, redeemTx.SerializeSize())

	var buf bytes.Buffer
	buf.Grow(redeemTx.SerializeSize())
	redeemTx.Serialize(&buf)
	fmt.Printf("Redeem fee: %v (%0.8f BTC/kB)\n\n", fee, redeemFeePerKb)
	fmt.Printf("Redeem transaction (%v):\n", &redeemTxHash)
	fmt.Printf("%x\n\n", buf.Bytes())

	if verify {
		prevOut := cmd.contractTx.TxOut[contractOut]
		a := txscript.NewCannedPrevOutputFetcher(prevOut.PkScript, prevOut.Value)
		e, err := txscript.NewEngine(cmd.contractTx.TxOut[contractOutPoint.Index].PkScript,
			redeemTx, 0, txscript.StandardVerifyFlags, txscript.NewSigCache(10),
			txscript.NewTxSigHashes(redeemTx, a), cmd.contractTx.TxOut[contractOut].Value, a)
		if err != nil {
			panic(err)
		}
		err = e.Execute()
		if err != nil {
			panic(err)
		}
	}

	return promptPublishTx(c, redeemTx, "redeem")
}

func (cmd *refundCmd) runCommand(c *rpc.Client) error {
	pushes, err := txscript.ExtractAtomicSwapDataPushes(0, cmd.contract)
	if err != nil {
		return err
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}

	feePerKb, minFeePerKb, err := getFeePerKb(c)
	if err != nil {
		return err
	}

	refundTx, refundFee, err := buildRefund(c, cmd.contract, cmd.contractTx, feePerKb, minFeePerKb)
	if err != nil {
		return err
	}
	refundTxHash := refundTx.TxHash()
	var buf bytes.Buffer
	buf.Grow(refundTx.SerializeSize())
	refundTx.Serialize(&buf)

	refundFeePerKb := calcFeePerKb(refundFee, refundTx.SerializeSize())

	fmt.Printf("Refund fee: %v (%0.8f BTC/kB)\n\n", refundFee, refundFeePerKb)
	fmt.Printf("Refund transaction (%v):\n", &refundTxHash)
	fmt.Printf("%x\n\n", buf.Bytes())

	return promptPublishTx(c, refundTx, "refund")
}

func (cmd *extractSecretCmd) runCommand(c *rpc.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *extractSecretCmd) runOfflineCommand() error {
	// Loop over all pushed data from all inputs, searching for one that hashes
	// to the expected hash.  By searching through all data pushes, we avoid any
	// issues that could be caused by the initiator redeeming the participant's
	// contract with some "nonstandard" or unrecognized transaction or script
	// type.
	for _, in := range cmd.redemptionTx.TxIn {
		pushes, err := txscript.PushedData(in.SignatureScript)
		if err != nil {
			return err
		}
		for _, push := range pushes {
			if bytes.Equal(sha256Hash(push), cmd.secretHash) {
				fmt.Printf("Secret: %x\n", push)
				return nil
			}
		}
	}
	return errors.New("transaction does not contain the secret")
}

func (cmd *auditContractCmd) runCommand(c *rpc.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *auditContractCmd) runOfflineCommand() error {
	contractHash160 := btcutil.Hash160(cmd.contract)
	contractOut := -1
	for i, out := range cmd.contractTx.TxOut {
		sc, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, chainParams)
		if err != nil || sc != txscript.ScriptHashTy {
			continue
		}
		if bytes.Equal(addrs[0].(*btcutil.AddressScriptHash).Hash160()[:], contractHash160) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain the contract output")
	}

	pushes, err := txscript.ExtractAtomicSwapDataPushes(0, cmd.contract)
	if err != nil {
		return err
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}
	if pushes.SecretSize != secretSize {
		return fmt.Errorf("contract specifies strange secret size %v", pushes.SecretSize)
	}

	contractAddr, err := btcutil.NewAddressScriptHash(cmd.contract, chainParams)
	if err != nil {
		return err
	}
	recipientAddr, err := btcutil.NewAddressPubKeyHash(pushes.RecipientHash160[:],
		chainParams)
	if err != nil {
		return err
	}
	refundAddr, err := btcutil.NewAddressPubKeyHash(pushes.RefundHash160[:],
		chainParams)
	if err != nil {
		return err
	}

	fmt.Printf("Contract address:        %v\n", contractAddr)
	fmt.Printf("Contract value:          %v\n", btcutil.Amount(cmd.contractTx.TxOut[contractOut].Value))
	fmt.Printf("Recipient address:       %v\n", recipientAddr)
	fmt.Printf("Author's refund address: %v\n\n", refundAddr)

	fmt.Printf("Secret hash: %x\n\n", pushes.SecretHash[:])

	if pushes.LockTime >= int64(txscript.LockTimeThreshold) {
		t := time.Unix(pushes.LockTime, 0)
		fmt.Printf("Locktime: %v\n", t.UTC())
		reachedAt := time.Until(t).Truncate(time.Second)
		if reachedAt > 0 {
			fmt.Printf("Locktime reached in %v\n", reachedAt)
		} else {
			fmt.Printf("Contract refund time lock has expired\n")
		}
	} else {
		fmt.Printf("Locktime: block %v\n", pushes.LockTime)
	}

	return nil
}

func (cmd *lockFundsCmd) runCommand(c *rpc.Client) error {
	pubKey, err := getSchnorrPubKey(c)
	if err != nil {
		return err
	}

	var lockTime int64
	if cmd.initiator {
		lockTime = time.Now().Add(48 * time.Hour).Unix()
	} else {
		lockTime = time.Now().Add(24 * time.Hour).Unix()
	}

	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return err
	}
	var internalKeyNonce secp256k1.ModNScalar
	internalKeyNonce.SetBytes(&buf)
	internalKey := fakeInternalKey(&internalKeyNonce)

	b, err := buildPrivateContract(c, &privateContractArgs{
		us:          pubKey,
		them:        cmd.cpPubKey,
		amount:      cmd.amount,
		locktime:    lockTime,
		internalKey: internalKey,
	})
	if err != nil {
		return err
	}

	var lockTxBuff bytes.Buffer
	b.contractTx.Serialize(&lockTxBuff)

	var refundBuff bytes.Buffer
	b.refundTx.Serialize(&refundBuff)

	contractFeePerKb := calcFeePerKb(b.contractFee, b.contractTx.SerializeSize())
	refundFeePerKb := calcFeePerKb(b.refundFee, b.refundTx.SerializeSize())

	fmt.Printf("\nContract fee: %v (%0.8f BTC/kB)\n", b.contractFee, contractFeePerKb)
	fmt.Printf("Refund fee:   %v (%0.8f BTC/kB)\n\n", b.refundFee, refundFeePerKb)
	fmt.Printf("Redeem swap contract:\n%x\n\n", b.redeemContract)
	fmt.Printf("Refund swap contract:\n%x\n\n", b.refundContract)
	fmt.Printf("Internal key nonce:\n%x\n\n", internalKeyNonce.Bytes())
	fmt.Printf("Lock tx (%v):\n%x\n\n", b.contractTx.TxHash(), lockTxBuff.Bytes())
	fmt.Printf("Redeem tx (%v):\n%x\n\n", b.refundTx.TxHash(), refundBuff.Bytes())

	return promptPublishTx(c, b.contractTx, "contract")
}

func (cmd *unsignedRedemptionCmd) runCommand(c *rpc.Client) error {
	address, err := getNewAddress(c)
	if err != nil {
		return fmt.Errorf("error getting new address: %v", err)
	}
	addr, err := btcutil.DecodeAddress(address, chainParams)
	if err != nil {
		return err
	}
	outScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}

	internalKey := fakeInternalKey(cmd.cpTxInternalKeyNonce)

	contractOutpoint, err := getPrivateContractOutpoint(cmd.cpLockTx, cmd.cpRedeemContract, cmd.cpRefundContract, internalKey)
	if err != nil {
		return err
	}
	contractTxOut := cmd.cpLockTx.TxOut[contractOutpoint.Index]

	redeemTx := wire.NewMsgTx(txVersion)
	redeemTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash:  contractOutpoint.Hash,
		Index: contractOutpoint.Index,
	}, nil, nil))
	redeemTx.AddTxOut(wire.NewTxOut(0, outScript))
	refundSize := estimatePrivateRedeemSerializeSize(redeemTx.TxOut)
	feePerKb, minFeePerKb, err := getFeePerKb(c)
	if err != nil {
		return err
	}

	fee := txrules.FeeForSerializeSize(feePerKb, refundSize)
	redeemTx.TxOut[0].Value = contractTxOut.Value - int64(fee)
	if txrules.IsDustOutput(redeemTx.TxOut[0], minFeePerKb) {
		return fmt.Errorf("redeem output value of %v is dust", btcutil.Amount(redeemTx.TxOut[0].Value))
	}

	var buf bytes.Buffer
	redeemTx.Serialize(&buf)

	fmt.Printf("\nRedeem fee: %v (%0.8f BTC/kB)\n\n", fee, calcFeePerKb(fee, redeemTx.SerializeSize()))
	fmt.Printf("Unsigned redemption:\n%x\n", buf.Bytes())
	return nil
}

func (cmd *initiateAdaptorCmd) runCommand(c *rpc.Client) error {
	ourPK, _, err := extractPrivateRedeemDetails(cmd.ourRedeemContract)
	if err != nil {
		return err
	}
	ourSchnorrPK, err := schnorr.ParsePubKey(ourPK)
	if err != nil {
		return err
	}

	privKey, err := getPrivKeyFromPubKey(c, ourSchnorrPK)
	if err != nil {
		return err
	}

	internalKey := fakeInternalKey(cmd.ourTxInternalKeyNonce)

	contractOutPoint, err := getPrivateContractOutpoint(cmd.ourLockTx, cmd.ourRedeemContract, cmd.ourRefundContract, internalKey)
	if err != nil {
		return err
	}
	contractTxOut := cmd.ourLockTx.TxOut[contractOutPoint.Index]

	a := txscript.NewCannedPrevOutputFetcher(contractTxOut.PkScript, contractTxOut.Value)
	sigHashes := txscript.NewTxSigHashes(cmd.cpUnsignedRedeemTx, a)

	sigB, err := txscript.RawTxInTapscriptSignature(
		cmd.cpUnsignedRedeemTx, sigHashes, 0, contractTxOut.Value, contractTxOut.PkScript,
		txscript.NewBaseTapLeaf(cmd.ourRedeemContract), txscript.SigHashDefault, privKey)
	if err != nil {
		return err
	}

	var tBuf [32]byte
	if _, err := rand.Read(tBuf[:]); err != nil {
		return err
	}
	var tweak secp256k1.ModNScalar
	tweak.SetBytes(&tBuf)

	sig, err := schnorr.ParseSignature(sigB[:64])
	if err != nil {
		return err
	}

	adaptorSig := adaptor.PrivateKeyTweakedAdaptorSig(sig, privKey.PubKey(), &tweak)

	fmt.Printf("\nAdaptor signature:\n%x\n", adaptorSig.Serialize())
	fmt.Printf("\nTweak:\n%x\n", tBuf[:])
	return nil
}

func (cmd *verifyAdaptorCmd) runCommand(c *rpc.Client) error {
	internalKey := fakeInternalKey(cmd.cpTxInternalKeyNonce)

	theirPKB, _, err := extractPrivateRedeemDetails(cmd.cpRedeemContract)
	if err != nil {
		return err
	}
	theirPK, err := schnorr.ParsePubKey(theirPKB)
	if err != nil {
		return err
	}

	contractOutPoint, err := getPrivateContractOutpoint(cmd.cpLockTx, cmd.cpRedeemContract, cmd.cpRefundContract, internalKey)
	if err != nil {
		return err
	}
	contractTxOut := cmd.cpLockTx.TxOut[contractOutPoint.Index]

	a := txscript.NewCannedPrevOutputFetcher(contractTxOut.PkScript, contractTxOut.Value)
	sigHashes := txscript.NewTxSigHashes(cmd.ourUnsignedRedeem, a)
	ourRedemptionSigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault,
		cmd.ourUnsignedRedeem, 0, a, txscript.NewBaseTapLeaf(cmd.cpRedeemContract))
	if err != nil {
		return err
	}

	if err := cmd.cpAdaptorSig.Verify(ourRedemptionSigHash, theirPK); err != nil {
		return err
	}

	fmt.Println("\nAdaptor sig is valid!")
	return nil
}

func (cmd *participateAdaptorCmd) runCommand(c *rpc.Client) error {
	ourPK, _, err := extractPrivateRedeemDetails(cmd.ourRedeemContract)
	if err != nil {
		return err
	}
	ourSchnorrPK, err := schnorr.ParsePubKey(ourPK)
	if err != nil {
		return err
	}

	privKey, err := getPrivKeyFromPubKey(c, ourSchnorrPK)
	if err != nil {
		return err
	}

	internaleKey := fakeInternalKey(cmd.ourTxInternalKeyNonce)

	contractOutPoint, err := getPrivateContractOutpoint(cmd.ourLockTx, cmd.ourRedeemContract, cmd.ourRefundContract, internaleKey)
	if err != nil {
		return err
	}
	contractTxOut := cmd.ourLockTx.TxOut[contractOutPoint.Index]

	a := txscript.NewCannedPrevOutputFetcher(contractTxOut.PkScript, contractTxOut.Value)
	sigHashes := txscript.NewTxSigHashes(cmd.cpUnsignedRedeemTx, a)
	sigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault,
		cmd.cpUnsignedRedeemTx, 0, a, txscript.NewBaseTapLeaf(cmd.ourRedeemContract))
	if err != nil {
		return err
	}

	adaptorSig, err := adaptor.PublicKeyTweakedAdaptorSig(privKey, sigHash, cmd.cpAdaptor.PublicTweak())
	if err != nil {
		return err
	}

	fmt.Printf("\nAdaptor signature: %x\n", adaptorSig.Serialize())
	return nil
}

func (cmd *privateRedeemCmd) runCommand(c *rpc.Client) error {
	_, ourPK, err := extractPrivateRedeemDetails(cmd.cpRedeemContract)
	if err != nil {
		return err
	}
	ourSchnorrPK, err := schnorr.ParsePubKey(ourPK)
	if err != nil {
		return err
	}
	privKey, err := getPrivKeyFromPubKey(c, ourSchnorrPK)
	if err != nil {
		return err
	}
	defer privKey.Zero()

	internalKey := fakeInternalKey(cmd.cpTxInternalKeyNonce)

	contractOutPoint, err := getPrivateContractOutpoint(cmd.cpLockTx, cmd.cpRedeemContract, cmd.cpRefundContract, internalKey)
	if err != nil {
		return err
	}
	contractTxOut := cmd.cpLockTx.TxOut[contractOutPoint.Index]

	redeemTx := cmd.unsignedRedemption

	a := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		*contractOutPoint: {
			Value:    contractTxOut.Value,
			PkScript: contractTxOut.PkScript,
		},
	})
	sigHashes := txscript.NewTxSigHashes(redeemTx, a)
	sigMe, err := txscript.RawTxInTapscriptSignature(
		redeemTx, sigHashes, 0, contractTxOut.Value, contractTxOut.PkScript,
		txscript.NewBaseTapLeaf(cmd.cpRedeemContract), txscript.SigHashDefault,
		privKey)
	if err != nil {
		return err
	}

	sigHash, err := txscript.CalcTapscriptSignaturehash(sigHashes, txscript.SigHashDefault, redeemTx,
		0, a, txscript.NewBaseTapLeaf(cmd.cpRedeemContract))
	if err != nil {
		return err
	}
	sigThem, err := cmd.cpAdaptor.Decrypt(cmd.tweak, sigHash)
	if err != nil {
		return err
	}
	controlBlockB, err := getRedeemControlBlock(cmd.cpRedeemContract, cmd.cpRefundContract, internalKey)
	if err != nil {
		return err
	}
	redeemTx.TxIn[0].Witness = wire.TxWitness{sigMe, sigThem.Serialize(), cmd.cpRedeemContract, controlBlockB}

	if verify {
		engine, err := txscript.NewEngine(contractTxOut.PkScript, redeemTx, 0, txscript.StandardVerifyFlags,
			txscript.NewSigCache(10), sigHashes, contractTxOut.Value, a)
		if err != nil {
			return err
		}
		err = engine.Execute()
		if err != nil {
			return err
		}
	}

	return promptPublishTx(c, redeemTx, "redeem")
}

func (cmd *extractTweakCmd) runCommand(c *rpc.Client) error {
	decryptedSig := cmd.cpRedeemTx.TxIn[0].Witness[1]
	sig, err := schnorr.ParseSignature(decryptedSig)
	if err != nil {
		return err
	}

	tweak, err := cmd.ourAdaptor.RecoverTweak(sig)
	if err != nil {
		return err
	}

	fmt.Printf("\nTweak: %x\n", tweak.Bytes())
	return nil
}

func (cmd *auditPrivateContractCmd) runCommand(c *rpc.Client) error {
	creatorPK, participantPK, err := extractPrivateRedeemDetails(cmd.redeemContract)
	if err != nil {
		return err
	}

	_, lockTime, err := extractPrivateRefundDetails(cmd.refundContract)
	if err != nil {
		return err
	}

	internalKey := fakeInternalKey(cmd.internalKeyNonce)
	outpoint, err := getPrivateContractOutpoint(cmd.lockTx, cmd.redeemContract, cmd.refundContract, internalKey)
	if err != nil {
		return err
	}
	output := cmd.lockTx.TxOut[outpoint.Index]

	fmt.Printf("\nContract value: %v\n", btcutil.Amount(output.Value))
	fmt.Printf("Creator PK: %x\n", append([]byte{02}, creatorPK...))
	fmt.Printf("Participant PK: %x\n", append([]byte{02}, participantPK...))

	if lockTime >= int64(txscript.LockTimeThreshold) {
		t := time.Unix(lockTime, 0)
		fmt.Printf("Locktime: %v\n", t.UTC())
		reachedAt := time.Until(t).Truncate(time.Second)
		if reachedAt > 0 {
			fmt.Printf("Locktime reached in %v\n", reachedAt)
		} else {
			fmt.Printf("Contract refund time lock has expired\n")
		}
	} else {
		fmt.Printf("Locktime: block %v\n", lockTime)
	}

	return nil
}

func (cmd *getPubKeyCmd) runCommand(c *rpc.Client) error {
	pubKey, err := getSchnorrPubKey(c)
	if err != nil {
		return err
	}

	fmt.Printf("%x\n", pubKey.SerializeCompressed())
	return nil
}

// atomicSwapContract returns an output script that may be redeemed by one of
// two signature scripts:
//
//	<their sig> <their pubkey> <initiator secret> 1
//
//	<my sig> <my pubkey> 0
//
// The first signature script is the normal redemption path done by the other
// party and requires the initiator's secret.  The second signature script is
// the refund path performed by us, but the refund can only be performed after
// locktime.
func atomicSwapContract(pkhMe, pkhThem *[ripemd160.Size]byte, locktime int64, secretHash []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()

	b.AddOp(txscript.OP_IF) // Normal redeem path
	{
		// Require initiator's secret to be a known length that the redeeming
		// party can audit.  This is used to prevent fraud attacks between two
		// currencies that have different maximum data sizes.
		b.AddOp(txscript.OP_SIZE)
		b.AddInt64(secretSize)
		b.AddOp(txscript.OP_EQUALVERIFY)

		// Require initiator's secret to be known to redeem the output.
		b.AddOp(txscript.OP_SHA256)
		b.AddData(secretHash)
		b.AddOp(txscript.OP_EQUALVERIFY)

		// Verify their signature is being used to redeem the output.  This
		// would normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been
		// moved outside of the branch to save a couple bytes.
		b.AddOp(txscript.OP_DUP)
		b.AddOp(txscript.OP_HASH160)
		b.AddData(pkhThem[:])
	}
	b.AddOp(txscript.OP_ELSE) // Refund path
	{
		// Verify locktime and drop it off the stack (which is not done by
		// CLTV).
		b.AddInt64(locktime)
		b.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
		b.AddOp(txscript.OP_DROP)

		// Verify our signature is being used to redeem the output.  This would
		// normally end with OP_EQUALVERIFY OP_CHECKSIG but this has been moved
		// outside of the branch to save a couple bytes.
		b.AddOp(txscript.OP_DUP)
		b.AddOp(txscript.OP_HASH160)
		b.AddData(pkhMe[:])
	}
	b.AddOp(txscript.OP_ENDIF)

	// Complete the signature check.
	b.AddOp(txscript.OP_EQUALVERIFY)
	b.AddOp(txscript.OP_CHECKSIG)

	return b.Script()
}

// privateAtomicSwapRedeemScript returns the regular (non-refund) script
// to redeem a private atomic swap. This is one of the leaves in the tapscript
// tree.
func privateAtomicSwapRedeemScript(pkMe, pkThem *secp256k1.PublicKey) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddData(schnorr.SerializePubKey(pkMe))
	b.AddOp(txscript.OP_CHECKSIGVERIFY)
	b.AddData(schnorr.SerializePubKey(pkThem))
	b.AddOp(txscript.OP_CHECKSIG)
	return b.Script()
}

// privateAtomicSwapRefundScript returns the refund script to spend a private
// atomic swap output after the locktime has been reached. This is one of the
// leaves in the tapscript tree.
func privateAtomicSwapRefundScript(pkMe *secp256k1.PublicKey, lockTime int64) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddInt64(lockTime)
	b.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
	b.AddOp(txscript.OP_DROP)
	b.AddData(schnorr.SerializePubKey(pkMe))
	b.AddOp(txscript.OP_CHECKSIG)
	script, err := b.Script()
	return script, err
}

func extractPrivateRedeemDetails(script []byte) (creator, participant []byte, err error) {
	if len(script) != 68 {
		err = fmt.Errorf("invalid swap contract length %d", len(script))
		return
	}

	if script[0] == txscript.OP_DATA_32 &&
		// creator's PK (32 bytes)
		script[33] == txscript.OP_CHECKSIGVERIFY &&
		script[34] == txscript.OP_DATA_32 &&
		// participant's PK (32 bytes)
		script[67] == txscript.OP_CHECKSIG {
		creator = make([]byte, 32)
		participant = make([]byte, 32)
		copy(creator, script[1:33])
		copy(participant, script[35:67])
	} else {
		err = fmt.Errorf("invalid swap contract")
	}

	return
}

func extractPrivateRefundDetails(script []byte) (creatorPK []byte, lockTime int64, err error) {
	tokenizer := txscript.MakeScriptTokenizer(0, script)

	// locktime (4/8 bytes)
	if !tokenizer.Next() {
		return nil, 0, fmt.Errorf("invalid refund contract")
	}
	if tokenizer.Opcode() == txscript.OP_DATA_4 {
		lockTime = int64(binary.LittleEndian.Uint32(tokenizer.Data()))
	} else if tokenizer.Opcode() == txscript.OP_DATA_8 {
		lockTime = int64(binary.LittleEndian.Uint64(tokenizer.Data()))
	} else {
		return nil, 0, fmt.Errorf("invalid refund contract")
	}

	// OP_CHECKLOCKTIMEVERIFY
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_CHECKLOCKTIMEVERIFY {
		return nil, 0, fmt.Errorf("invalid refund contract")
	}

	// OP_DROP
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_DROP {
		return nil, 0, fmt.Errorf("invalid refund contract")
	}

	// creator's PK (32 bytes)
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_DATA_32 {
		return nil, 0, fmt.Errorf("invalid refund contract")
	}
	creatorPK = make([]byte, 32)
	copy(creatorPK, tokenizer.Data())

	// OP_CHECKSIG
	if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_CHECKSIG {
		return nil, 0, fmt.Errorf("invalid refund contract")
	}

	return
}

// redeemP2SHContract returns the signature script to redeem a contract output
// using the redeemer's signature and the initiator's secret.  This function
// assumes P2SH and appends the contract as the final data push.
func redeemP2SHContract(contract, sig, pubkey, secret []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddData(sig)
	b.AddData(pubkey)
	b.AddData(secret)
	b.AddInt64(1)
	b.AddData(contract)
	return b.Script()
}

// refundP2SHContract returns the signature script to refund a contract output
// using the contract author's signature after the locktime has been reached.
// This function assumes P2SH and appends the contract as the final data push.
func refundP2SHContract(contract, sig, pubkey []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddData(sig)
	b.AddData(pubkey)
	b.AddInt64(0)
	b.AddData(contract)
	return b.Script()
}

// payToTaprootScript returns the PKScript for a pay-to-taproot output.
func payToTaprootScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}

// getRedeemControlBlock returns the control that should be used when redeeming
// a private atomic swap output.
func getRedeemControlBlock(redeemScript, refundScript []byte, internalKey *secp256k1.PublicKey) ([]byte, error) {
	normalLeaf := txscript.NewBaseTapLeaf(redeemScript)
	refundLeaf := txscript.NewBaseTapLeaf(refundScript)
	tapScriptTree := txscript.AssembleTaprootScriptTree(normalLeaf, refundLeaf)
	controlBlock := tapScriptTree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	return controlBlock.ToBytes()
}

// getPrivateContractOutpoint returns the outpoint of a private atomic swap
// contract output. If the contract output is not found in the transaction, an
// error is returned.
func getPrivateContractOutpoint(tx *wire.MsgTx, redeemScript, refundScript []byte, internalKey *secp256k1.PublicKey) (*wire.OutPoint, error) {
	normalLeaf := txscript.NewBaseTapLeaf(redeemScript)
	refundLeaf := txscript.NewBaseTapLeaf(refundScript)
	tapScriptTree := txscript.AssembleTaprootScriptTree(normalLeaf, refundLeaf)
	tapScriptRootHash := tapScriptTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, tapScriptRootHash[:])
	expectedPkScript, err := payToTaprootScript(outputKey)
	if err != nil {
		return nil, err
	}
	contractOutpoint := &wire.OutPoint{Hash: tx.TxHash(), Index: ^uint32(0)}
	for i, out := range tx.TxOut {
		if bytes.Equal(out.PkScript, expectedPkScript) {
			contractOutpoint.Index = uint32(i)
		}
	}
	if contractOutpoint.Index == ^uint32(0) {
		return nil, fmt.Errorf("contract outpoint not found")
	}
	return contractOutpoint, nil
}
