// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pb "decred.org/dcrwallet/v3/rpc/walletrpc"
	"decred.org/dcrwallet/v3/wallet/txrules"
	"github.com/decred/atomicswap/cmd/dcratomicswap/adaptor"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/decred/dcrd/dcrutil/v4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/sign"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/txscript/v4/stdscript"

	"github.com/decred/dcrd/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	isTreasuryEnabled = true
	verify            = true

	verifyFlags = txscript.ScriptDiscourageUpgradableNops |
		txscript.ScriptVerifyCleanStack |
		txscript.ScriptVerifyCheckLockTimeVerify |
		txscript.ScriptVerifyCheckSequenceVerify |
		txscript.ScriptVerifySHA256

	secretSize = 32

	feePerKb = 1e5

	scriptVersion = 0
)

var (
	chainParams = chaincfg.MainNetParams()
)

var (
	flagset        = flag.NewFlagSet("", flag.ExitOnError)
	connectFlag    = flagset.String("s", "localhost", "host[:port] of dcrwallet gRPC server")
	certFlag       = flagset.String("c", filepath.Join(dcrutil.AppDataDir("dcrwallet", false), "rpc.cert"), "dcrwallet RPC certificate path")
	clientCertFlag = flagset.String("clientcert", "", "path to client authentication certificate")
	clientKeyFlag  = flagset.String("clientkey", "", "path to client authentication key")
	testnetFlag    = flagset.Bool("testnet", false, "use testnet network")
	simnetFlag     = flagset.Bool("simnet", false, "use simnet network")
)

// There are two directions that the atomic swap can be performed, as the
// initiator can be on either chain.  This tool only deals with creating the
// Decred transactions for these swaps.  A second tool should be used for the
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
		fmt.Println("Usage: dcratomicswap [flags] cmd [cmd args]")
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
		fmt.Println("  lockfunds <counterparty address> <amount> <initiator>")
		fmt.Println("  unsignedredemption <counterparty contract> <counterparty tx>")
		fmt.Println("  initiateadaptor <our lock contract> <our lock tx> <counterparty unsigned redeem tx>")
		fmt.Println("  verifyadaptor <counterparty contract> <counterparty adaptor sig> <counterparty pub key> <our unsigned redeem tx>")
		fmt.Println("  participateadaptor <our lock contract> <our lock tx> <counterparty adaptor> <counterparty unsigned redeem>")
		fmt.Println("  privateredeem <counterparty contract> <counterparty lock tx> <counterparty adaptor> <counterparty pub key> <our unsigned redemption> <tweak>")
		fmt.Println("  extracttweak <counterparty redemption tx> <our adaptor sig>")
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

type command interface {
	runCommand(context.Context, pb.WalletServiceClient) error
}

// offline commands don't require wallet RPC.
type offlineCommand interface {
	command
	runOfflineCommand() error
}

type initiateCmd struct {
	cp2Addr *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0
	amount  dcrutil.Amount
}

type participateCmd struct {
	cp1Addr    *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0
	amount     dcrutil.Amount
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

// The following commands are used for private swaps.

type lockFundsCmd struct {
	cpAddr    *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0
	amount    dcrutil.Amount
	initiator bool
}

type unsignedRedemptionCmd struct {
	cpContract []byte
	cpLockTx   *wire.MsgTx
}

type initiateAdaptorCmd struct {
	ourContract        []byte
	ourLockTx          *wire.MsgTx
	cpUnsignedRedeemTx *wire.MsgTx
}

type verifyAdaptorCmd struct {
	cpContract        []byte
	cpAdaptorSig      *adaptor.AdaptorSignature
	cpPubKey          *secp256k1.PublicKey
	ourUnsignedRedeem *wire.MsgTx
}

type participateAdaptorCmd struct {
	ourContract          []byte
	ourLockTx            *wire.MsgTx
	cpAdaptor            *adaptor.AdaptorSignature
	cpUnsignedRedemption *wire.MsgTx
}

type privateRedeemCmd struct {
	cpContract         []byte
	cpLockTx           *wire.MsgTx
	cpAdaptor          *adaptor.AdaptorSignature
	cpPubKey           *secp256k1.PublicKey
	unsignedRedemption *wire.MsgTx
	tweak              *secp256k1.ModNScalar
}

type extractTweakCmd struct {
	cpRedeemTx *wire.MsgTx
	ourAdaptor *adaptor.AdaptorSignature
}

type auditPrivateContractCmd struct {
	cpContract []byte
	cpLockTx   *wire.MsgTx
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

func parseTx(s string) (*wire.MsgTx, error) {
	txB, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %v", err)
	}
	var tx wire.MsgTx
	err = tx.Deserialize(bytes.NewReader(txB))
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %v", err)
	}
	return &tx, nil
}

func parseAdaptorSig(s string) (*adaptor.AdaptorSignature, error) {
	sigB, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %v", err)
	}
	return adaptor.ParseAdaptorSignature(sigB)
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
	case "redeem_private":
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
	case "initiateadaptor":
		cmdArgs = 3
	case "participateadaptor":
		cmdArgs = 4
	case "unsignedredemption":
		cmdArgs = 2
	case "verifyadaptor":
		cmdArgs = 4
	case "privateredeem":
		cmdArgs = 6
	case "extracttweak":
		cmdArgs = 2
	case "auditprivatecontract":
		cmdArgs = 2
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

	if *simnetFlag {
		chainParams = chaincfg.SimNetParams()
	}

	if *testnetFlag {
		chainParams = chaincfg.TestNet3Params()
	}

	var cmd command
	switch args[0] {
	case "initiate":
		decodedAddr, err := stdaddr.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode participant address: %v", err), true
		}
		cp2Addr, ok := decodedAddr.(*stdaddr.AddressPubKeyHashEcdsaSecp256k1V0)
		if !ok {
			return errors.New("participant address is not P2PKH"), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount, err := dcrutil.NewAmount(amountF64)
		if err != nil {
			return err, true
		}

		cmd = &initiateCmd{cp2Addr: cp2Addr, amount: amount}

	case "participate":
		decodedAddr, err := stdaddr.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode initiator address: %v", err), true
		}
		cp1Addr, ok := decodedAddr.(*stdaddr.AddressPubKeyHashEcdsaSecp256k1V0)
		if !ok {
			return errors.New("initiator address is not P2PKH"), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount, err := dcrutil.NewAmount(amountF64)
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

		cmd = &participateCmd{cp1Addr: cp1Addr, amount: amount, secretHash: secretHash}

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

		// The following commands are used for private swaps

	case "lockfunds":
		decodedAddr, err := stdaddr.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode initiator address: %v", err), true
		}
		cpAddr, ok := decodedAddr.(*stdaddr.AddressPubKeyHashEcdsaSecp256k1V0)
		if !ok {
			return errors.New("initiator address is not P2PKH"), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount, err := dcrutil.NewAmount(amountF64)
		if err != nil {
			return err, true
		}

		initiator, err := strconv.ParseBool(args[3])
		if err != nil {
			return fmt.Errorf("failed to decode initiator: %v", err), true
		}

		cmd = &lockFundsCmd{
			cpAddr:    cpAddr,
			amount:    amount,
			initiator: initiator,
		}
	case "initiateadaptor":
		ourContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		ourLockTx, err := parseTx(args[2])
		if err != nil {
			return err, true
		}

		cpUnsignedRedeem, err := parseTx(args[3])
		if err != nil {
			return err, true
		}

		cmd = &initiateAdaptorCmd{
			ourContract:        ourContract,
			ourLockTx:          ourLockTx,
			cpUnsignedRedeemTx: cpUnsignedRedeem,
		}

	case "verifyadaptor":
		cpContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		cpAdaptor, err := parseAdaptorSig(args[2])
		if err != nil {
			return err, true
		}

		cpPubKeyB, err := hex.DecodeString(args[3])
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}
		cpPubKey, err := secp256k1.ParsePubKey(cpPubKeyB)
		if err != nil {
			return fmt.Errorf("parse pub key: %v", err), true
		}

		ourUnsignedRedeem, err := parseTx(args[4])
		if err != nil {
			return err, true
		}

		cmd = &verifyAdaptorCmd{
			cpContract:        cpContract,
			cpAdaptorSig:      cpAdaptor,
			cpPubKey:          cpPubKey,
			ourUnsignedRedeem: ourUnsignedRedeem,
		}
	case "participateadaptor":
		ourContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		ourLockTx, err := parseTx(args[2])
		if err != nil {
			return err, true
		}

		cpAdaptor, err := parseAdaptorSig(args[3])
		if err != nil {
			return err, true
		}

		cpUnsignedRedeem, err := parseTx(args[4])
		if err != nil {
			return err, true
		}

		cmd = &participateAdaptorCmd{
			cpAdaptor:            cpAdaptor,
			ourLockTx:            ourLockTx,
			ourContract:          ourContract,
			cpUnsignedRedemption: cpUnsignedRedeem,
		}
	case "unsignedredemption":
		cpContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		cpLockTx, err := parseTx(args[2])
		if err != nil {
			return err, true
		}

		cmd = &unsignedRedemptionCmd{
			cpContract: cpContract,
			cpLockTx:   cpLockTx,
		}

	case "privateredeem":
		cpContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		cpLockTx, err := parseTx(args[2])
		if err != nil {
			return err, true
		}

		cpAdaptor, err := parseAdaptorSig(args[3])
		if err != nil {
			return err, true
		}

		cpPubKeyB, err := hex.DecodeString(args[4])
		if err != nil {
			return err, true
		}
		cpPubKey, err := secp256k1.ParsePubKey(cpPubKeyB)
		if err != nil {
			return fmt.Errorf("parse pub key: %v", err), true
		}

		unsignedRedemption, err := parseTx(args[5])
		if err != nil {
			return err, true
		}

		tweakBytes, err := hex.DecodeString(args[6])
		if err != nil {
			return fmt.Errorf("failed to decode contract transaction: %v", err), true
		}
		var tweakBuf [32]byte
		copy(tweakBuf[:], tweakBytes)
		var tweak secp256k1.ModNScalar
		tweak.SetBytes(&tweakBuf)

		cmd = &privateRedeemCmd{
			cpContract:         cpContract,
			cpLockTx:           cpLockTx,
			cpAdaptor:          cpAdaptor,
			cpPubKey:           cpPubKey,
			tweak:              &tweak,
			unsignedRedemption: unsignedRedemption,
		}
	case "extracttweak":
		cpRedeemTx, err := parseTx(args[1])
		if err != nil {
			return err, true
		}

		ourAdaptor, err := parseAdaptorSig(args[2])
		if err != nil {
			return err, true
		}

		cmd = &extractTweakCmd{
			cpRedeemTx: cpRedeemTx,
			ourAdaptor: ourAdaptor,
		}
	case "auditprivatecontract":
		cpContract, err := hex.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("failed to decode contract: %v", err), true
		}

		cpLockTx, err := parseTx(args[2])
		if err != nil {
			return err, true
		}

		cmd = &auditPrivateContractCmd{
			cpContract: cpContract,
			cpLockTx:   cpLockTx,
		}
	}

	// Offline commands don't need to talk to the wallet.
	if cmd, ok := cmd.(offlineCommand); ok {
		return cmd.runOfflineCommand(), false
	}

	if *clientCertFlag == "" || *clientKeyFlag == "" {
		return fmt.Errorf("-clientcert and -clientkey flags are required; see -h for usage"), false
	}

	connect, err := normalizeAddress(*connectFlag, walletPort(chainParams))
	if err != nil {
		return fmt.Errorf("wallet server address: %v", err), true
	}

	keypair, err := tls.LoadX509KeyPair(*clientCertFlag, *clientKeyFlag)
	if err != nil {
		return fmt.Errorf("open client keypair: %v", err), false
	}
	tc := &tls.Config{
		Certificates:       []tls.Certificate{keypair},
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: true,
	}
	serverCAs, err := os.ReadFile(*certFlag)
	if err != nil {
		help := *certFlag == ""
		return fmt.Errorf("cannot open server certificate: %v", err), help
	}
	if !tc.RootCAs.AppendCertsFromPEM(serverCAs) {
		return fmt.Errorf("no certificates found in %q", *certFlag), false
	}
	creds := credentials.NewTLS(tc)
	conn, err := grpc.Dial(connect, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("grpc dial: %v", err), false
	}
	defer conn.Close()
	client := pb.NewWalletServiceClient(conn)

	err = cmd.runCommand(context.Background(), client)
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
	switch params.Net {
	case wire.MainNet:
		return "9111"
	case wire.TestNet3:
		return "19111"
	default:
		return ""
	}
}

func promptPassphase() ([]byte, error) {
	fmt.Printf("Passphrase: ")
	pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return pass, err
}

func promptPublishTx(ctx context.Context, c pb.WalletServiceClient, tx []byte, name string) error {
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

		r, err := c.PublishTransaction(ctx, &pb.PublishTransactionRequest{SignedTransaction: tx})
		if err != nil {
			return err
		}
		// NewHash only errors for wrong size
		txHash, _ := chainhash.NewHash(r.TransactionHash)
		fmt.Printf("Published %s transaction (%v)\n", name, txHash)
		return nil
	}
}

// contractArgs specifies the common parameters used to create the initiator's
// and participant's contract.
type contractArgs struct {
	them       *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0
	amount     dcrutil.Amount
	locktime   int64
	secretHash []byte
}

type privateContractArgs struct {
	us       *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0
	them     *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0
	amount   dcrutil.Amount
	locktime int64
}

// builtContract houses the details regarding a contract and the contract
// payment transaction, as well as the transaction to perform a refund.
type builtContract struct {
	contract       []byte
	contractP2SH   stdaddr.Address
	contractTxHash *chainhash.Hash
	contractTx     *wire.MsgTx
	contractFee    dcrutil.Amount
	refundTx       *wire.MsgTx
	refundFee      dcrutil.Amount
}

// buildContract creates a contract for the parameters specified in args, using
// wallet RPC to generate an internal address to redeem the refund and to sign
// the payment to the contract transaction.
func buildContract(ctx context.Context, c pb.WalletServiceClient, args *contractArgs,
	passphrase []byte) (*builtContract, error) {

	nar, err := c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   0, // TODO
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return nil, err
	}
	addr, err := stdaddr.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return nil, err
	}
	refundAddr, ok := addr.(*stdaddr.AddressPubKeyHashEcdsaSecp256k1V0)
	if !ok {
		return nil, fmt.Errorf("NextAddress: address %v is not P2PKH", refundAddr)
	}

	contract, err := atomicSwapContract(refundAddr.Hash160(), args.them.Hash160(),
		args.locktime, args.secretHash)
	if err != nil {
		return nil, err
	}
	contractP2SH, err := stdaddr.NewAddressScriptHash(0, contract, chainParams)
	if err != nil {
		return nil, err
	}

	scriptVersion, contractP2SHPkScript := contractP2SH.PaymentScript()
	ctr, err := c.ConstructTransaction(ctx, &pb.ConstructTransactionRequest{
		SourceAccount: 0, // TODO
		NonChangeOutputs: []*pb.ConstructTransactionRequest_Output{{
			Destination: &pb.ConstructTransactionRequest_OutputDestination{
				Script:        contractP2SHPkScript,
				ScriptVersion: uint32(scriptVersion),
			},
			Amount: int64(args.amount),
		}},
	})
	if err != nil {
		return nil, err
	}
	contractFee := dcrutil.Amount(ctr.TotalPreviousOutputAmount - ctr.TotalOutputAmount)
	str, err := c.SignTransaction(ctx, &pb.SignTransactionRequest{
		Passphrase:            passphrase,
		SerializedTransaction: ctr.UnsignedTransaction,
	})
	if err != nil {
		return nil, err
	}
	var contractTx wire.MsgTx
	err = contractTx.Deserialize(bytes.NewReader(str.Transaction))
	if err != nil {
		return nil, err
	}

	contractTxHash := contractTx.TxHash()

	refundTx, refundFee, err := buildRefund(ctx, c, contract, &contractTx,
		feePerKb, passphrase)
	if err != nil {
		return nil, err
	}

	return &builtContract{
		contract,
		contractP2SH,
		&contractTxHash,
		&contractTx,
		contractFee,
		refundTx,
		refundFee,
	}, nil
}

func buildRefund(ctx context.Context, c pb.WalletServiceClient, contract []byte, contractTx *wire.MsgTx,
	feePerKb dcrutil.Amount, passphrase []byte) (
	refundTx *wire.MsgTx, refundFee dcrutil.Amount, err error) {

	contractP2SH, err := stdaddr.NewAddressScriptHash(0, contract, chainParams)
	if err != nil {
		return nil, 0, err
	}
	_, contractP2SHPkScript := contractP2SH.PaymentScript()
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

	nar, err := c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   0, // TODO
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return nil, 0, err
	}
	refundAddress, err := stdaddr.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return nil, 0, err
	}
	_, refundOutScript := refundAddress.PaymentScript()
	pushes := stdscript.ExtractAtomicSwapDataPushesV0(contract)
	if pushes == nil {
		// expected to only be called with good input
		panic("invalid atomic swap contract")
	}

	refundAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(0, pushes.RefundHash160[:], chainParams)
	if err != nil {
		return nil, 0, err
	}

	refundTx = wire.NewMsgTx()
	refundTx.LockTime = uint32(pushes.LockTime)
	refundTx.AddTxOut(wire.NewTxOut(0, refundOutScript)) // amount set below
	refundSize := estimateRefundSerializeSize(contract, refundTx.TxOut)

	refundFee = dcrutil.Amount(feePerKb * dcrutil.Amount(refundSize) / 1000)
	refundTx.TxOut[0].Value = contractTx.TxOut[contractOutPoint.Index].Value - int64(refundFee)

	txIn := wire.NewTxIn(&contractOutPoint, 0, nil)
	txIn.Sequence = 0
	refundTx.AddTxIn(txIn)

	var buf bytes.Buffer
	buf.Grow(refundTx.SerializeSize())
	refundTx.Serialize(&buf)

	refundSig, err := c.CreateSignature(ctx, &pb.CreateSignatureRequest{
		Passphrase:            passphrase,
		Address:               refundAddr.String(),
		SerializedTransaction: buf.Bytes(),
		InputIndex:            0,
		HashType:              pb.CreateSignatureRequest_SIGHASH_ALL,
		PreviousPkScript:      contract,
	})
	if err != nil {
		return nil, 0, err
	}
	refundSigScript, err := refundP2SHContract(contract, refundSig.Signature,
		refundSig.PublicKey)
	if err != nil {
		return nil, 0, err
	}
	refundTx.TxIn[0].SignatureScript = refundSigScript

	sigCache, err := txscript.NewSigCache(10)
	if err != nil {
		return nil, 0, err
	}

	if verify {
		e, err := txscript.NewEngine(contractTx.TxOut[contractOutPoint.Index].PkScript,
			refundTx, 0, verifyFlags, scriptVersion, sigCache)
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

func buildPrivateContract(ctx context.Context, c pb.WalletServiceClient, args *privateContractArgs, passphrase []byte) (*builtContract, error) {
	contract, err := privateAtomicSwapContract(*args.us.Hash160(), *args.them.Hash160(), args.locktime)
	if err != nil {
		return nil, err
	}

	contractP2SH, err := stdaddr.NewAddressScriptHash(0, contract, chainParams)
	if err != nil {
		return nil, err
	}
	scriptVer, contractP2SHPkScript := contractP2SH.PaymentScript()
	ctr, err := c.ConstructTransaction(ctx, &pb.ConstructTransactionRequest{
		SourceAccount: 0, // TODO
		NonChangeOutputs: []*pb.ConstructTransactionRequest_Output{{
			Destination: &pb.ConstructTransactionRequest_OutputDestination{
				Script:        contractP2SHPkScript,
				ScriptVersion: uint32(scriptVer),
			},
			Amount: int64(args.amount),
		}},
	})
	if err != nil {
		return nil, err
	}

	contractFee := dcrutil.Amount(ctr.TotalPreviousOutputAmount - ctr.TotalOutputAmount)
	str, err := c.SignTransaction(ctx, &pb.SignTransactionRequest{
		Passphrase:            passphrase,
		SerializedTransaction: ctr.UnsignedTransaction,
	})
	if err != nil {
		return nil, err
	}
	var contractTx wire.MsgTx
	err = contractTx.Deserialize(bytes.NewReader(str.Transaction))
	if err != nil {
		return nil, err
	}

	refundTx, refundFee, err := buildPrivateRefund(ctx, c, contract, &contractTx, args.locktime, args.us, feePerKb, passphrase)
	if err != nil {
		return nil, err
	}

	contractTxHash := contractTx.TxHash()
	return &builtContract{
		contract,
		contractP2SH,
		&contractTxHash,
		&contractTx,
		contractFee,
		refundTx,
		refundFee,
	}, nil
}

func buildPrivateRefund(ctx context.Context, c pb.WalletServiceClient, contract []byte, contractTx *wire.MsgTx,
	locktime int64, redeemAddr *stdaddr.AddressPubKeyHashEcdsaSecp256k1V0, feePerKb dcrutil.Amount, passphrase []byte) (
	refundTx *wire.MsgTx, refundFee dcrutil.Amount, err error) {

	contractP2SH, err := stdaddr.NewAddressScriptHash(scriptVersion, contract, chainParams)
	if err != nil {
		return nil, 0, err
	}
	_, contractP2SHPkScript := contractP2SH.PaymentScript()

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

	nar, err := c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   0, // TODO
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return nil, 0, err
	}
	refundAddress, err := stdaddr.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return nil, 0, err
	}
	_, refundOutScript := refundAddress.PaymentScript()

	refundTx = wire.NewMsgTx()
	refundTx.LockTime = uint32(locktime)
	refundTx.AddTxOut(wire.NewTxOut(0, refundOutScript)) // amount set below
	refundSize := estimatePrivateRefundSerializeSize(contract, refundTx.TxOut)

	refundFee = feePerKb * dcrutil.Amount(refundSize) / 1000
	refundTx.TxOut[0].Value = contractTx.TxOut[contractOutPoint.Index].Value - int64(refundFee)

	txIn := wire.NewTxIn(&contractOutPoint, 0, nil)
	txIn.Sequence = 0
	refundTx.AddTxIn(txIn)

	var buf bytes.Buffer
	buf.Grow(refundTx.SerializeSize())
	err = refundTx.Serialize(&buf)
	if err != nil {
		return nil, 0, err
	}

	privKeyBytes, err := dumpPrivateKey(ctx, c, redeemAddr.String())
	if err != nil {
		return nil, 0, err
	}
	defer zeroBytes(privKeyBytes)
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	defer privKey.Zero()

	sigHash, err := txscript.CalcSignatureHash(contract, txscript.SigHashAll, refundTx, int(0), nil)
	if err != nil {
		return nil, 0, err
	}

	sig, err := schnorr.Sign(privKey, sigHash)
	if err != nil {
		return nil, 0, err
	}
	sigB := append(sig.Serialize(), byte(txscript.SigHashAll))
	refundSigScript, err := refundPrivateContract(contract, sigB, privKey.PubKey().SerializeCompressed())
	if err != nil {
		return nil, 0, err
	}
	refundTx.TxIn[0].SignatureScript = refundSigScript

	sigCache, err := txscript.NewSigCache(10)
	if err != nil {
		return nil, 0, err
	}

	if verify {
		e, err := txscript.NewEngine(contractTx.TxOut[contractOutPoint.Index].PkScript,
			refundTx, 0, verifyFlags, scriptVersion, sigCache)
		if err != nil {
			return nil, 0, err
		}
		err = e.Execute()
		if err != nil {
			return nil, 0, err
		}
	}

	return refundTx, refundFee, nil
}

func sha256Hash(x []byte) []byte {
	h := sha256.Sum256(x)
	return h[:]
}

func calcFeePerKb(absoluteFee dcrutil.Amount, serializeSize int) float64 {
	return float64(absoluteFee) / float64(serializeSize) / 1e5
}

func (cmd *initiateCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	var secret [secretSize]byte
	_, err := rand.Read(secret[:])
	if err != nil {
		return err
	}
	secretHash := sha256Hash(secret[:])

	// locktime after 500,000,000 (Tue Nov  5 00:53:20 1985 UTC) is interpreted
	// as a unix time rather than a block height.
	locktime := time.Now().Add(48 * time.Hour).Unix()

	passphrase, err := promptPassphase()
	if err != nil {
		return err
	}

	b, err := buildContract(ctx, c, &contractArgs{
		them:       cmd.cp2Addr,
		amount:     cmd.amount,
		locktime:   locktime,
		secretHash: secretHash,
	}, passphrase)
	if err != nil {
		return err
	}

	refundTxHash := b.refundTx.TxHash()
	contractFeePerKb := calcFeePerKb(b.contractFee, b.contractTx.SerializeSize())
	refundFeePerKb := calcFeePerKb(b.refundFee, b.refundTx.SerializeSize())

	fmt.Printf("\n")
	fmt.Printf("Secret:      %x\n", secret)
	fmt.Printf("Secret hash: %x\n\n", secretHash)
	fmt.Printf("Contract fee: %v (%0.8f DCR/kB)\n", b.contractFee, contractFeePerKb)
	fmt.Printf("Refund fee:   %v (%0.8f DCR/kB)\n\n", b.refundFee, refundFeePerKb)
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

	return promptPublishTx(ctx, c, contractBuf.Bytes(), "contract")
}

func (cmd *lockFundsCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	passphrase, err := promptPassphase()
	if err != nil {
		return err
	}

	nar, err := c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   0, // TODO
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return err
	}
	decodedAddr, err := stdaddr.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return err
	}
	ourAddr, ok := decodedAddr.(*stdaddr.AddressPubKeyHashEcdsaSecp256k1V0)
	if !ok {
		return fmt.Errorf("NextAddress: address %v is not P2PKH", decodedAddr)
	}

	var lockTime int64
	if cmd.initiator {
		lockTime = time.Now().Add(48 * time.Hour).Unix()
	} else {
		lockTime = time.Now().Add(24 * time.Hour).Unix()
	}

	b, err := buildPrivateContract(ctx, c, &privateContractArgs{
		us:       ourAddr,
		them:     cmd.cpAddr,
		amount:   cmd.amount,
		locktime: lockTime,
	}, passphrase)
	if err != nil {
		return err
	}

	contractFeePerKb := calcFeePerKb(b.contractFee, b.contractTx.SerializeSize())
	refundTxHash := b.refundTx.TxHash()
	refundFeePerKb := calcFeePerKb(b.refundFee, b.refundTx.SerializeSize())

	privateKey, err := dumpPrivateKey(ctx, c, ourAddr.String())
	if err != nil {
		return err
	}
	defer zeroBytes(privateKey)
	pubKey := secp256k1.PrivKeyFromBytes(privateKey).PubKey()

	fmt.Printf("\nContract fee: %v (%0.8f DCR/kB)\n", b.contractFee, contractFeePerKb)
	fmt.Printf("Refund fee:   %v (%0.8f DCR/kB)\n\n", b.refundFee, refundFeePerKb)
	fmt.Printf("Contract (%v):\n", b.contractP2SH)
	fmt.Printf("%x\n\n", b.contract)
	fmt.Printf("Your pub key: %x\n\n", pubKey.SerializeCompressed())
	var contractBuf bytes.Buffer
	contractBuf.Grow(b.contractTx.SerializeSize())
	b.contractTx.Serialize(&contractBuf)
	fmt.Printf("Lock transaction (%v):\n", b.contractTxHash)
	fmt.Printf("%x\n\n", contractBuf.Bytes())
	var refundBuf bytes.Buffer
	refundBuf.Grow(b.refundTx.SerializeSize())
	b.refundTx.Serialize(&refundBuf)
	fmt.Printf("Refund transaction (%v):\n", &refundTxHash)
	fmt.Printf("%x\n\n", refundBuf.Bytes())

	return promptPublishTx(ctx, c, contractBuf.Bytes(), "contract")
}

func (cmd *unsignedRedemptionCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	nar, err := c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   0, // TODO
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return err
	}
	addr, err := stdaddr.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return err
	}
	_, outScript := addr.PaymentScript()

	contractOutPoint, err := getContractOutPoint(cmd.cpLockTx, cmd.cpContract)
	if err != nil {
		return fmt.Errorf("contract transaction: %v", err)
	}

	redeemTx := wire.NewMsgTx()
	redeemTx.AddTxIn(wire.NewTxIn(contractOutPoint, 0, nil))
	redeemTx.AddTxOut(wire.NewTxOut(0, outScript)) // amount set below
	redeemSize := estimatePrivateRedeemSerializeSize(cmd.cpContract, redeemTx.TxOut)
	fee := feePerKb * dcrutil.Amount(redeemSize) / 1000
	redeemTx.TxOut[0].Value = cmd.cpLockTx.TxOut[contractOutPoint.Index].Value - int64(fee)

	var buf bytes.Buffer
	buf.Grow(redeemTx.SerializeSize())
	redeemTx.Serialize(&buf)
	redeemFeePerKb := calcFeePerKb(fee, redeemSize)

	fmt.Printf("\nRedeem Fee: %v (%0.8f DCR/kB)\n", fee, redeemFeePerKb)
	fmt.Printf("Unsigned redemption tx bytes:\n%x\n", buf.Bytes())

	return nil
}

func (cmd *initiateAdaptorCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	ourPKH, _, _, err := extractPrivateAtomicSwapDetails(cmd.ourContract)
	if err != nil {
		return err
	}
	ourAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(ourPKH[:], chainParams)
	if err != nil {
		return err
	}

	privKey, err := dumpPrivateKey(ctx, c, ourAddr.String())
	if err != nil {
		return err
	}
	defer zeroBytes(privKey)

	sigB, err := sign.RawTxInSignature(cmd.cpUnsignedRedeemTx, 0, cmd.ourContract, txscript.SigHashAll,
		privKey, dcrec.STSchnorrSecp256k1)
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
	adaptorSig := adaptor.PrivateKeyTweakedAdaptorSig(sig, secp256k1.PrivKeyFromBytes(privKey).PubKey(), &tweak)
	if err != nil {
		return err
	}

	fmt.Printf("\nAdaptor Sig:\n%x\n", adaptorSig.Serialize())
	fmt.Printf("\nTweak:\n%x\n", tBuf)

	return nil
}

func (cmd *verifyAdaptorCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	cpPKH, _, _, err := extractPrivateAtomicSwapDetails(cmd.cpContract)
	if err != nil {
		return err
	}
	expectedPKH := dcrutil.Hash160(cmd.cpPubKey.SerializeCompressed())
	if !bytes.Equal(cpPKH[:], expectedPKH) {
		return fmt.Errorf("counterparty's pubkey does not match contract")
	}

	ourRedemptionSigHash, err := txscript.CalcSignatureHash(cmd.cpContract, txscript.SigHashAll, cmd.ourUnsignedRedeem, int(0), nil)
	if err != nil {
		return err
	}
	if err := cmd.cpAdaptorSig.Verify(ourRedemptionSigHash, cmd.cpPubKey); err != nil {
		return err
	}

	fmt.Println("\nAdaptor sig is valid!")
	return nil
}

func (cmd *participateAdaptorCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	ourContractPKH, _, _, err := extractPrivateAtomicSwapDetails(cmd.ourContract)
	if err != nil {
		return err
	}
	ourContractAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(scriptVersion, ourContractPKH[:], chainParams)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.Grow(cmd.ourLockTx.SerializeSize())
	cmd.ourLockTx.Serialize(&buf)

	privKey, err := dumpPrivateKey(ctx, c, ourContractAddr.String())
	if err != nil {
		return err
	}
	defer zeroBytes(privKey)

	cpRedemptionSigHash, err := txscript.CalcSignatureHash(cmd.ourContract, txscript.SigHashAll, cmd.cpUnsignedRedemption, 0, nil)
	if err != nil {
		return err
	}

	adaptorSig, err := adaptor.PublicKeyTweakedAdaptorSig(secp256k1.PrivKeyFromBytes(privKey), cpRedemptionSigHash, cmd.cpAdaptor.PublicTweak())
	if err != nil {
		return err
	}

	fmt.Printf("\nAdaptor Sig: %x\n", adaptorSig.Serialize())

	return nil
}

func (cmd *privateRedeemCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	_, ourPKH, _, err := extractPrivateAtomicSwapDetails(cmd.cpContract)
	if err != nil {
		return err
	}
	ourAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(scriptVersion, ourPKH[:], chainParams)
	if err != nil {
		return err
	}

	hash, err := txscript.CalcSignatureHash(cmd.cpContract, txscript.SigHashAll, cmd.unsignedRedemption, 0, nil)
	if err != nil {
		return err
	}

	cpSignature, err := cmd.cpAdaptor.Decrypt(cmd.tweak, hash)
	if err != nil {
		return err
	}

	ourRedemptionSigHash, err := txscript.CalcSignatureHash(cmd.cpContract, txscript.SigHashAll, cmd.unsignedRedemption, int(0), nil)
	if err != nil {
		return err
	}

	privKeyBytes, err := dumpPrivateKey(ctx, c, ourAddr.String())
	if err != nil {
		return err
	}
	defer zeroBytes(privKeyBytes)
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	defer privKey.Zero()

	ourRedeemSig, err := schnorr.Sign(privKey, ourRedemptionSigHash)
	if err != nil {
		return err
	}

	ourSigB := append(ourRedeemSig.Serialize(), byte(txscript.SigHashAll))
	cpSigB := append(cpSignature.Serialize(), byte(txscript.SigHashAll))
	redeemContract, err := redeemPrivateContract(cmd.cpContract, privKey.PubKey().SerializeCompressed(),
		ourSigB, cmd.cpPubKey.SerializeCompressed(), cpSigB)
	if err != nil {
		return err
	}

	redeemTx := cmd.unsignedRedemption
	redeemTx.TxIn[0].SignatureScript = redeemContract

	if verify {
		op, err := getContractOutPoint(cmd.cpLockTx, cmd.cpContract)
		if err != nil {
			return err
		}
		sigCache, err := txscript.NewSigCache(10)
		if err != nil {
			return err
		}
		e, err := txscript.NewEngine(cmd.cpLockTx.TxOut[int(op.Index)].PkScript,
			redeemTx, 0, verifyFlags, scriptVersion, sigCache)
		if err != nil {
			return err
		}
		err = e.Execute()
		if err != nil {
			return err
		}
	}

	return promptPublishTx(ctx, c, serializeTx(redeemTx), "redeem")
}

func (cmd *extractTweakCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	_, _, _, sigThem, err := parseRedeemPrivateContract(cmd.cpRedeemTx.TxIn[0].SignatureScript)
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(sigThem[:64])
	if err != nil {
		return err
	}
	tweak, err := cmd.ourAdaptor.RecoverTweak(sig)
	if err != nil {
		return err
	}

	tweakBytes := tweak.Bytes()
	fmt.Printf("\nRecovered tweak:\n%x\n", tweakBytes[:])
	return nil
}

func (cmd *auditPrivateContractCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	creatorPKH, participantPKH, lockTime, err := extractPrivateAtomicSwapDetails(cmd.cpContract)
	if err != nil {
		return err
	}

	creatorAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(scriptVersion, creatorPKH[:], chainParams)
	if err != nil {
		return err
	}

	participantAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(scriptVersion, participantPKH[:], chainParams)
	if err != nil {
		return err
	}

	contractP2SH, err := stdaddr.NewAddressScriptHash(scriptVersion, cmd.cpContract, chainParams)
	if err != nil {
		return err
	}

	outpoint, err := getContractOutPoint(cmd.cpLockTx, cmd.cpContract)
	if err != nil {
		return err
	}
	output := cmd.cpLockTx.TxOut[int(outpoint.Index)]

	fmt.Printf("\nContract address: %v\n", contractP2SH.String())
	fmt.Printf("Contract value: %v\n", dcrutil.Amount(output.Value))
	fmt.Printf("Creator address: %v\n", creatorAddr.String())
	fmt.Printf("Participant address: %v\n", participantAddr.String())

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

func (cmd *participateCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	// locktime after 500,000,000 (Tue Nov  5 00:53:20 1985 UTC) is interpreted
	// as a unix time rather than a block height.
	locktime := time.Now().Add(24 * time.Hour).Unix()

	passphrase, err := promptPassphase()
	if err != nil {
		return err
	}

	b, err := buildContract(ctx, c, &contractArgs{
		them:       cmd.cp1Addr,
		amount:     cmd.amount,
		locktime:   locktime,
		secretHash: cmd.secretHash,
	}, passphrase)
	if err != nil {
		return err
	}

	refundTxHash := b.refundTx.TxHash()
	contractFeePerKb := calcFeePerKb(b.contractFee, b.contractTx.SerializeSize())
	refundFeePerKb := calcFeePerKb(b.refundFee, b.refundTx.SerializeSize())

	fmt.Printf("\n")
	fmt.Printf("Contract fee: %v (%0.8f DCR/kB)\n", b.contractFee, contractFeePerKb)
	fmt.Printf("Refund fee:   %v (%0.8f DCR/kB)\n\n", b.refundFee, refundFeePerKb)
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

	return promptPublishTx(ctx, c, contractBuf.Bytes(), "contract")
}

func (cmd *redeemCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	pushes := stdscript.ExtractAtomicSwapDataPushesV0(cmd.contract)
	if pushes == nil {
		return fmt.Errorf("invalid atomic swap script")
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}
	recipientAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(scriptVersion, pushes.RecipientHash160[:], chainParams)
	if err != nil {
		return err
	}
	contractHash := stdaddr.Hash160(cmd.contract)
	contractOut := -1
	for i, out := range cmd.contractTx.TxOut {
		scriptHash := txscript.ExtractScriptHash(out.PkScript)
		if scriptHash == nil {
			continue
		}
		if bytes.Equal(scriptHash, contractHash) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain a contract output")
	}

	nar, err := c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   0, // TODO
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return err
	}
	addr, err := stdaddr.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return err
	}
	_, outScript := addr.PaymentScript()

	contractTxHash := cmd.contractTx.TxHash()
	contractOutPoint := wire.OutPoint{
		Hash:  contractTxHash,
		Index: uint32(contractOut),
		Tree:  0,
	}

	redeemTx := wire.NewMsgTx()
	redeemTx.LockTime = uint32(pushes.LockTime)
	redeemTx.AddTxIn(wire.NewTxIn(&contractOutPoint, 0, nil))
	redeemTx.AddTxOut(wire.NewTxOut(0, outScript)) // amount set below
	redeemSize := estimateRedeemSerializeSize(cmd.contract, redeemTx.TxOut)
	fee := txrules.FeeForSerializeSize(feePerKb, redeemSize)
	redeemTx.TxOut[0].Value = cmd.contractTx.TxOut[contractOut].Value - int64(fee)
	if txrules.IsDustOutput(redeemTx.TxOut[0], feePerKb) {
		return fmt.Errorf("redeem output value of %v is dust", dcrutil.Amount(redeemTx.TxOut[0].Value))
	}

	var buf bytes.Buffer
	buf.Grow(redeemTx.SerializeSize())
	redeemTx.Serialize(&buf)

	passphrase, err := promptPassphase()
	if err != nil {
		return err
	}

	redeemSig, err := c.CreateSignature(ctx, &pb.CreateSignatureRequest{
		Passphrase:            passphrase,
		Address:               recipientAddr.String(),
		SerializedTransaction: buf.Bytes(),
		InputIndex:            0,
		HashType:              pb.CreateSignatureRequest_SIGHASH_ALL,
		PreviousPkScript:      cmd.contract,
	})
	if err != nil {
		return err
	}
	redeemSigScript, err := redeemP2SHContract(cmd.contract, redeemSig.Signature,
		redeemSig.PublicKey, cmd.secret)
	if err != nil {
		return err
	}
	redeemTx.TxIn[0].SignatureScript = redeemSigScript

	redeemTxHash := redeemTx.TxHash()
	redeemFeePerKb := calcFeePerKb(dcrutil.Amount(fee.ToCoin()), redeemTx.SerializeSize())

	buf.Reset()
	buf.Grow(redeemTx.SerializeSize())
	redeemTx.Serialize(&buf)
	fmt.Printf("\n")
	fmt.Printf("Redeem fee: %v (%0.8f DCR/kB)\n\n", fee, redeemFeePerKb)
	fmt.Printf("Redeem transaction (%v):\n", &redeemTxHash)
	fmt.Printf("%x\n\n", buf.Bytes())

	sigCache, err := txscript.NewSigCache(10)
	if err != nil {
		return err
	}

	if verify {
		e, err := txscript.NewEngine(cmd.contractTx.TxOut[contractOutPoint.Index].PkScript,
			redeemTx, 0, verifyFlags, scriptVersion, sigCache)
		if err != nil {
			panic(err)
		}
		err = e.Execute()
		if err != nil {
			panic(err)
		}
	}

	return promptPublishTx(ctx, c, buf.Bytes(), "redeem")
}

func (cmd *refundCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	pushes := stdscript.ExtractAtomicSwapDataPushesV0(cmd.contract)
	if pushes == nil {
		return fmt.Errorf("invalid atomic swap script")
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}

	passphrase, err := promptPassphase()
	if err != nil {
		return err
	}

	refundTx, refundFee, err := buildRefund(ctx, c, cmd.contract, cmd.contractTx, feePerKb, passphrase)
	if err != nil {
		return err
	}
	refundTxHash := refundTx.TxHash()
	var buf bytes.Buffer
	buf.Grow(refundTx.SerializeSize())
	refundTx.Serialize(&buf)

	refundFeePerKb := calcFeePerKb(refundFee, refundTx.SerializeSize())

	fmt.Printf("\n")
	fmt.Printf("Refund fee: %v (%0.8f DCR/kB)\n\n", refundFee, refundFeePerKb)
	fmt.Printf("Refund transaction (%v):\n", &refundTxHash)
	fmt.Printf("%x\n\n", buf.Bytes())

	return promptPublishTx(ctx, c, buf.Bytes(), "refund")
}

func (cmd *extractSecretCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	return cmd.runOfflineCommand()
}

func (cmd *extractSecretCmd) runOfflineCommand() error {
	// Loop over all pushed data from all inputs, searching for one that hashes
	// to the expected hash.  By searching through all data pushes, we avoid any
	// issues that could be caused by the initiator redeeming the participant's
	// contract with some "nonstandard" or unrecognized transaction or script
	// type.
	for _, in := range cmd.redemptionTx.TxIn {
		tokenizer := txscript.MakeScriptTokenizer(scriptVersion, in.SignatureScript)
		for tokenizer.Next() {
			data := tokenizer.Data()
			if data != nil && bytes.Equal(sha256Hash(data), cmd.secretHash) {
				fmt.Printf("Secret: %x\n", data)
				return nil
			}
		}
	}
	return errors.New("transaction does not contain the secret")
}

func (cmd *auditContractCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	return cmd.runOfflineCommand()
}

func (cmd *auditContractCmd) runOfflineCommand() error {
	contractHash160 := dcrutil.Hash160(cmd.contract)
	contractOut := -1
	for i, out := range cmd.contractTx.TxOut {
		scriptHash := txscript.ExtractScriptHash(out.PkScript)
		if scriptHash == nil {
			continue
		}
		if bytes.Equal(scriptHash, contractHash160) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain the contract output")
	}

	pushes := stdscript.ExtractAtomicSwapDataPushesV0(cmd.contract)
	if pushes == nil {
		return fmt.Errorf("invalid atomic swap script")
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}
	if pushes.SecretSize != secretSize {
		return fmt.Errorf("contract specifies strange secret size %v", pushes.SecretSize)
	}

	contractAddr, err := stdaddr.NewAddressScriptHash(scriptVersion, cmd.contract, chainParams)
	if err != nil {
		return err
	}
	recipientAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(scriptVersion, pushes.RecipientHash160[:], chainParams)
	if err != nil {
		return err
	}
	refundAddr, err := stdaddr.NewAddressPubKeyHashEcdsaSecp256k1(scriptVersion, pushes.RefundHash160[:], chainParams)
	if err != nil {
		return err
	}

	fmt.Printf("Contract address:        %v\n", contractAddr)
	fmt.Printf("Contract value:          %v\n", dcrutil.Amount(cmd.contractTx.TxOut[contractOut].Value))
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

func privateAtomicSwapContract(us, them [ripemd160.Size]byte, locktime int64) ([]byte, error) {
	b := txscript.NewScriptBuilder()

	b.AddOp(txscript.OP_IF) // Normal redeem path
	{
		b.AddOp(txscript.OP_DUP)
		b.AddOp(txscript.OP_HASH160)
		b.AddData(them[:])
		b.AddOp(txscript.OP_EQUALVERIFY)
		b.AddOp(txscript.OP_2)
		b.AddOp(txscript.OP_CHECKSIGALTVERIFY)
	}
	b.AddOp(txscript.OP_ELSE) // Refund path
	{
		b.AddInt64(locktime)
		b.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
		b.AddOp(txscript.OP_DROP)
	}
	b.AddOp(txscript.OP_ENDIF)
	b.AddOp(txscript.OP_DUP)
	b.AddOp(txscript.OP_HASH160)
	b.AddData(us[:])
	b.AddOp(txscript.OP_EQUALVERIFY)
	b.AddOp(txscript.OP_2)
	b.AddOp(txscript.OP_CHECKSIGALT)

	script, err := b.Script()
	if err != nil {
		return nil, err
	}

	return script, nil
}

func extractPrivateAtomicSwapDetails(script []byte) (creator, participant [ripemd160.Size]byte, locktime int64, err error) {
	if len(script) != 62 {
		err = fmt.Errorf("invalid swap contract: length = %v", len(script))
		return
	}

	if script[0] == txscript.OP_IF &&
		script[1] == txscript.OP_DUP &&
		script[2] == txscript.OP_HASH160 &&
		script[3] == txscript.OP_DATA_20 &&
		// creator's (20 bytes)
		script[24] == txscript.OP_EQUALVERIFY &&
		script[25] == txscript.OP_2 &&
		script[26] == txscript.OP_CHECKSIGALTVERIFY &&
		script[27] == txscript.OP_ELSE &&
		script[28] == txscript.OP_DATA_4 &&
		// lockTime (4 bytes)
		script[33] == txscript.OP_CHECKLOCKTIMEVERIFY &&
		script[34] == txscript.OP_DROP &&
		script[35] == txscript.OP_ENDIF &&
		script[36] == txscript.OP_DUP &&
		script[37] == txscript.OP_HASH160 &&
		script[38] == txscript.OP_DATA_20 &&

		// participant's pkh (20 bytes)
		script[59] == txscript.OP_EQUALVERIFY &&
		script[60] == txscript.OP_2 &&
		script[61] == txscript.OP_CHECKSIGALT {
		copy(participant[:], script[4:24])
		copy(creator[:], script[39:59])
		locktime = int64(binary.LittleEndian.Uint32(script[29:33]))
	} else {
		err = fmt.Errorf("invalid swap contract")
	}

	return
}

func redeemPrivateContract(contract, pkUs, sigUs, pkThem, sigThem []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()

	b.AddData(sigThem)
	b.AddData(pkThem)
	b.AddData(sigUs)
	b.AddData(pkUs)
	b.AddInt64(1)
	b.AddData(contract)
	return b.Script()
}

func parseRedeemPrivateContract(script []byte) (pkUs, sigUs, pkThem, sigThem []byte, err error) {
	if len(script) < redeemPrivateAtomicSwapSigScriptSize {
		err = fmt.Errorf("invalid swap redemption: length = %v", len(script))
		return
	}

	sigThem = script[1:66]
	pkThem = script[67:100]
	sigUs = script[101:167]
	pkUs = script[168:201]

	return
}

func refundPrivateContract(contract, sig, pubkey []byte) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddData(sig)
	b.AddData(pubkey)
	b.AddInt64(0)
	b.AddData(contract)
	return b.Script()
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

func dumpPrivateKey(ctx context.Context, c pb.WalletServiceClient, address string) ([]byte, error) {
	privateKey, err := c.DumpPrivateKey(ctx, &pb.DumpPrivateKeyRequest{
		Address: address,
	})
	if err != nil {
		return nil, err
	}
	defer func() { privateKey.PrivateKeyWif = "" }()

	wif, err := dcrutil.DecodeWIF(privateKey.PrivateKeyWif, chainParams.PrivateKeyID)
	if err != nil {
		return nil, err
	}

	return wif.PrivKey(), nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func getContractOutPoint(tx *wire.MsgTx, contract []byte) (*wire.OutPoint, error) {
	contractAddr, err := stdaddr.NewAddressScriptHash(scriptVersion, contract, chainParams)
	if err != nil {
		return nil, err
	}
	_, script := contractAddr.PaymentScript()
	contractTxHash := tx.TxHash()
	contractOutPoint := wire.OutPoint{Hash: contractTxHash, Index: ^uint32(0)}
	for i, o := range tx.TxOut {
		if bytes.Equal(o.PkScript, script) {
			contractOutPoint.Index = uint32(i)
			break
		}
	}
	if contractOutPoint.Index == ^uint32(0) {
		return nil, errors.New("contract tx does not contain a P2SH contract payment")
	}
	return &contractOutPoint, nil
}

func serializeTx(tx *wire.MsgTx) []byte {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)
	return buf.Bytes()
}
