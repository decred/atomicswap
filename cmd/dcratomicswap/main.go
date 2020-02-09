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
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pb "decred.org/dcrwallet/rpc/walletrpc"
	"decred.org/dcrwallet/wallet/txrules"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/txscript/v3"
	"github.com/decred/dcrd/wire"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/ssh/terminal"
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
	cp2Addr dcrutil.Address
	amount  dcrutil.Amount
}

type participateCmd struct {
	cp1Addr    dcrutil.Address
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
		chainParams = chaincfg.TestNet3Params()
	}

	var cmd command
	switch args[0] {
	case "initiate":
		cp2Addr, err := dcrutil.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode participant address: %v", err), true
		}
		_, ok := cp2Addr.(*dcrutil.AddressPubKeyHash)
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
		cp1Addr, err := dcrutil.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode initiator address: %v", err), true
		}
		_, ok := cp1Addr.(*dcrutil.AddressPubKeyHash)
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
		Certificates: []tls.Certificate{keypair},
		RootCAs:      x509.NewCertPool(),
	}
	serverCAs, err := ioutil.ReadFile(*certFlag)
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
	them       dcrutil.Address
	amount     dcrutil.Amount
	locktime   int64
	secretHash []byte
}

// builtContract houses the details regarding a contract and the contract
// payment transaction, as well as the transaction to perform a refund.
type builtContract struct {
	contract       []byte
	contractP2SH   dcrutil.Address
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
	refundAddr, err := dcrutil.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return nil, err
	}
	if _, ok := refundAddr.(*dcrutil.AddressPubKeyHash); !ok {
		return nil, fmt.Errorf("NextAddress: address %v is not P2PKH", refundAddr)
	}

	contract, err := atomicSwapContract(refundAddr.Hash160(), args.them.Hash160(),
		args.locktime, args.secretHash)
	if err != nil {
		return nil, err
	}
	contractP2SH, err := dcrutil.NewAddressScriptHash(contract, chainParams)
	if err != nil {
		return nil, err
	}
	contractP2SHPkScript, err := txscript.PayToAddrScript(contractP2SH)
	if err != nil {
		return nil, err
	}

	ctr, err := c.ConstructTransaction(ctx, &pb.ConstructTransactionRequest{
		SourceAccount: 0, // TODO
		NonChangeOutputs: []*pb.ConstructTransactionRequest_Output{{
			Destination: &pb.ConstructTransactionRequest_OutputDestination{
				Script:        contractP2SHPkScript,
				ScriptVersion: 0,
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

	contractP2SH, err := dcrutil.NewAddressScriptHash(contract, chainParams)
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

	nar, err := c.NextAddress(ctx, &pb.NextAddressRequest{
		Account:   0, // TODO
		Kind:      pb.NextAddressRequest_BIP0044_INTERNAL,
		GapPolicy: pb.NextAddressRequest_GAP_POLICY_WRAP,
	})
	if err != nil {
		return nil, 0, err
	}
	refundAddress, err := dcrutil.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return nil, 0, err
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

	refundAddr, err := dcrutil.NewAddressPubKeyHash(pushes.RefundHash160[:], chainParams,
		dcrec.STEcdsaSecp256k1)
	if err != nil {
		return nil, 0, err
	}

	refundTx = wire.NewMsgTx()
	refundTx.LockTime = uint32(pushes.LockTime)
	refundTx.AddTxOut(wire.NewTxOut(0, refundOutScript)) // amount set below
	refundSize := estimateRefundSerializeSize(contract, refundTx.TxOut)
	refundFee = txrules.FeeForSerializeSize(feePerKb, refundSize)
	refundTx.TxOut[0].Value = contractTx.TxOut[contractOutPoint.Index].Value - int64(refundFee)
	if txrules.IsDustOutput(refundTx.TxOut[0], feePerKb) {
		return nil, 0, fmt.Errorf("refund output value of %v is dust", dcrutil.Amount(refundTx.TxOut[0].Value))
	}

	txIn := wire.NewTxIn(&contractOutPoint, 0, nil)
	txIn.Sequence = 0
	refundTx.AddTxIn(txIn)

	var buf bytes.Buffer
	buf.Grow(refundTx.SerializeSize())
	refundTx.Serialize(&buf)

	refundSig, err := c.CreateSignature(ctx, &pb.CreateSignatureRequest{
		Passphrase:            passphrase,
		Address:               refundAddr.Address(),
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
	pushes, err := txscript.ExtractAtomicSwapDataPushes(
		scriptVersion, cmd.contract)
	if err != nil {
		return err
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}
	recipientAddr, err := dcrutil.NewAddressPubKeyHash(pushes.RecipientHash160[:],
		chainParams, dcrec.STEcdsaSecp256k1)
	if err != nil {
		return err
	}
	contractHash := dcrutil.Hash160(cmd.contract)
	contractOut := -1
	for i, out := range cmd.contractTx.TxOut {
		sc, addrs, _, _ := txscript.ExtractPkScriptAddrs(out.Version, out.PkScript,
			chainParams, isTreasuryEnabled)
		if sc == txscript.ScriptHashTy && bytes.Equal(addrs[0].Hash160()[:], contractHash) {
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
	addr, err := dcrutil.DecodeAddress(nar.Address, chainParams)
	if err != nil {
		return err
	}
	outScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}

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
		Address:               recipientAddr.Address(),
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
	redeemFeePerKb := calcFeePerKb(fee, redeemTx.SerializeSize())

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
	pushes, err := txscript.ExtractAtomicSwapDataPushes(
		scriptVersion, cmd.contract)
	if err != nil {
		return err
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

func (cmd *auditContractCmd) runCommand(ctx context.Context, c pb.WalletServiceClient) error {
	return cmd.runOfflineCommand()
}

func (cmd *auditContractCmd) runOfflineCommand() error {
	contractHash160 := dcrutil.Hash160(cmd.contract)
	contractOut := -1
	for i, out := range cmd.contractTx.TxOut {
		sc, addrs, _, err := txscript.ExtractPkScriptAddrs(out.Version, out.PkScript,
			chainParams, isTreasuryEnabled)
		if err != nil || sc != txscript.ScriptHashTy {
			continue
		}
		if bytes.Equal(addrs[0].(*dcrutil.AddressScriptHash).Hash160()[:], contractHash160) {
			contractOut = i
			break
		}
	}
	if contractOut == -1 {
		return errors.New("transaction does not contain the contract output")
	}

	pushes, err := txscript.ExtractAtomicSwapDataPushes(scriptVersion, cmd.contract)
	if err != nil {
		return err
	}
	if pushes == nil {
		return errors.New("contract is not an atomic swap script recognized by this tool")
	}
	if pushes.SecretSize != secretSize {
		return fmt.Errorf("contract specifies strange secret size %v", pushes.SecretSize)
	}

	contractAddr, err := dcrutil.NewAddressScriptHash(cmd.contract, chainParams)
	if err != nil {
		return err
	}
	recipientAddr, err := dcrutil.NewAddressPubKeyHash(pushes.RecipientHash160[:],
		chainParams, dcrec.STEcdsaSecp256k1)
	if err != nil {
		return err
	}
	refundAddr, err := dcrutil.NewAddressPubKeyHash(pushes.RefundHash160[:],
		chainParams, dcrec.STEcdsaSecp256k1)
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
//   <their sig> <their pubkey> <initiator secret> 1
//
//   <my sig> <my pubkey> 0
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
