// Copyright (c) 2024 The Decred developers
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

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	rpc "github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"golang.org/x/crypto/ripemd160"
)

// run script verifier
const verify = true

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
	regtestFlag = flagset.Bool("regtest", false, "use regtest network")
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
	cp2Addr *btcutil.AddressWitnessPubKeyHash
	amount  btcutil.Amount
}

type participateCmd struct {
	cp1Addr    *btcutil.AddressWitnessPubKeyHash
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
		chainParams = &chaincfg.TestNet3Params
	} else if *regtestFlag {
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
		cp2AddrP2WPKH, ok := cp2Addr.(*btcutil.AddressWitnessPubKeyHash)
		if !ok {
			return errors.New("participant address is not P2WPKH"), true
		}

		amountF64, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("failed to decode amount: %v", err), true
		}
		amount, err := btcutil.NewAmount(amountF64)
		if err != nil {
			return err, true
		}

		cmd = &initiateCmd{
			cp2Addr: cp2AddrP2WPKH,
			amount:  amount,
		}

	case "participate":
		cp1Addr, err := btcutil.DecodeAddress(args[1], chainParams)
		if err != nil {
			return fmt.Errorf("failed to decode initiator address: %v", err), true
		}
		if !cp1Addr.IsForNet(chainParams) {
			return fmt.Errorf("initiator address is not "+
				"intended for use on %v", chainParams.Name), true
		}
		cp1AddrP2WPKH, ok := cp1Addr.(*btcutil.AddressWitnessPubKeyHash)
		if !ok {
			return errors.New("initiator address is not P2WPKH"), true
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

		cmd = &participateCmd{cp1Addr: cp1AddrP2WPKH, amount: amount, secretHash: secretHash}

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
	case &chaincfg.RegressionNetParams:
		return "18443"
	default:
		return ""
	}
}

// createWitnessSig creates and returns the serialized raw signature and compressed
// pubkey for a transaction input signature.
//
// returns [sig][pubkey]
//
// Due to limitations of the Bitcoin Core RPC API, this requires dumping a private
// key and signing in the client, rather than letting the wallet sign.
func createWitnessSig(
	tx *wire.MsgTx,
	idx int,
	contractValue int64,
	contractPkScript []byte,
	sigHashes *txscript.TxSigHashes,
	addr btcutil.Address,
	c *rpc.Client) ([]byte, []byte, error) {

	wif, err := c.DumpPrivKey(addr)
	if err != nil {
		return nil, nil, err
	}
	privKey := wif.PrivKey
	defer privKey.Zero()

	sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, idx, contractValue,
		contractPkScript, txscript.SigHashAll, privKey)
	if err != nil {
		return nil, nil, err
	}

	return sig, privKey.PubKey().SerializeCompressed(), nil
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
	// The default is bech32 for recent bitcoin rpc
	rawResp, err := c.RawRequest("getrawchangeaddress", nil)
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
	if _, ok := addr.(*btcutil.AddressWitnessPubKeyHash); !ok {
		return nil, fmt.Errorf("getrawchangeaddress: address %v is not P2WPKH",
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
	them       *btcutil.AddressWitnessPubKeyHash
	amount     btcutil.Amount
	locktime   int64
	secretHash []byte
}

// builtContract houses the details regarding a contract and the contract
// payment transaction, as well as the transaction to perform a refund.
type builtContract struct {
	contract       []byte
	contractP2WSH  btcutil.Address
	contractTxHash *chainhash.Hash
	contractTx     *wire.MsgTx
	contractFee    btcutil.Amount
	refundTx       *wire.MsgTx
	refundFee      btcutil.Amount
}

// buildSegwitContract creates a contract for the parameters specified in args, using
// wallet RPC to generate an internal address to redeem the refund and to sign
// the payment to the contract transaction.
func buildSegwitContract(c *rpc.Client, args *contractArgs) (*builtContract, error) {
	refundAddr, err := getRawChangeAddress(c)
	if err != nil {
		return nil, fmt.Errorf("getrawchangeaddress: %v", err)
	}
	if _, ok := refundAddr.(interface{ Hash160() *[ripemd160.Size]byte }); !ok {
		return nil, errors.New("unable to create hash160 from change address")
	}

	contract, err := MakeContract(
		args.them,
		refundAddr,
		args.secretHash,
		args.locktime,
		true, //segwit
		chainParams)
	if err != nil {
		return nil, err
	}

	contractHash := sha256Hash(contract)
	contractP2WSH, err := btcutil.NewAddressWitnessScriptHash(contractHash, chainParams)
	if err != nil {
		return nil, err
	}
	contractP2WSHPkScript, err := txscript.PayToAddrScript(contractP2WSH)
	if err != nil {
		return nil, err
	}

	feePerKb, minFeePerKb, err := getFeePerKb(c)
	if err != nil {
		return nil, err
	}

	unsignedContractTx := wire.NewMsgTx(txVersion)
	unsignedContractTx.AddTxOut(wire.NewTxOut(int64(args.amount), contractP2WSHPkScript))
	unsignedContractTx, contractFee, err := fundRawTransaction(c, unsignedContractTx, feePerKb)
	if err != nil {
		return nil, fmt.Errorf("fundrawtransaction: %v", err)
	}
	contractTx, complete, err := signRawTransaction(c, unsignedContractTx)
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
		contractP2WSH,
		&contractTxHash,
		contractTx,
		contractFee,
		refundTx,
		refundFee,
	}, nil
}

func buildRefund(c *rpc.Client, contract []byte, contractTx *wire.MsgTx, feePerKb, minFeePerKb btcutil.Amount) (
	refundTx *wire.MsgTx, refundFee btcutil.Amount, err error) {

	contractHash := sha256Hash(contract)
	contractP2WSH, err := btcutil.NewAddressWitnessScriptHash(contractHash, chainParams)
	if err != nil {
		return nil, 0, err
	}
	contractP2WSHPkScript, err := txscript.PayToAddrScript(contractP2WSH)
	if err != nil {
		return nil, 0, err
	}

	contractTxHash := contractTx.TxHash()
	var contractValue = int64(0)
	contractOutPoint := wire.OutPoint{Hash: contractTxHash, Index: ^uint32(0)}
	for i, o := range contractTx.TxOut {
		if bytes.Equal(o.PkScript, contractP2WSHPkScript) {
			contractOutPoint.Index = uint32(i)
			contractValue = o.Value
			break
		}
	}
	if contractOutPoint.Index == ^uint32(0) {
		return nil, 0, errors.New("contract tx does not contain a P2WSH contract payment")
	}

	refundAddress, err := getRawChangeAddress(c)
	if err != nil {
		return nil, 0, fmt.Errorf("getrawchangeaddress: %v", err)
	}
	refundOutScript, err := txscript.PayToAddrScript(refundAddress)
	if err != nil {
		return nil, 0, err
	}

	sender, _, locktime, _, err := ExtractSwapDetails(
		contract,
		true, // segwit
		chainParams)
	if err != nil {
		return nil, 0, err
	}

	refundAddr, err := btcutil.NewAddressWitnessPubKeyHash(sender.ScriptAddress(), chainParams)
	if err != nil {
		return nil, 0, err
	}

	refundTx = wire.NewMsgTx(txVersion)
	refundTx.LockTime = uint32(locktime)
	// prepare single tx input
	refundTx.AddTxIn(wire.NewTxIn(&contractOutPoint, nil, nil))
	refundTx.TxIn[0].Sequence = 0
	refundTx.TxIn[0].SignatureScript = nil
	// with input but no output yet get vsize & fee
	refundSize := refundTxSerialSizeEst(refundTx)
	refundFee = txrules.FeeForSerializeSize(feePerKb, refundSize)
	// now add the single output
	refundTx.AddTxOut(wire.NewTxOut(0, refundOutScript))
	refundTx.TxOut[0].Value = contractTx.TxOut[contractOutPoint.Index].Value - int64(refundFee)
	// check dust
	if txrules.IsDustOutput(refundTx.TxOut[0], minFeePerKb) {
		return nil, 0, fmt.Errorf("refund output value of %v is dust", btcutil.Amount(refundTx.TxOut[0].Value))
	}

	// NewTxSigHashes uses the PrevOutFetcher only for detecting a taproot
	// output, so we can provide a dummy that always returns a wire.TxOut
	// with a nil pkScript that so IsPayToTaproot returns false.
	prevOutFetcher := new(txscript.CannedPrevOutputFetcher)
	sigHashes := txscript.NewTxSigHashes(refundTx, prevOutFetcher)

	sig, pubKey, err := createWitnessSig(refundTx, 0, contractValue, contract, sigHashes, refundAddr, c)
	if err != nil {
		return nil, 0, err
	}
	refundTxWitness := RefundP2WSHContract(contract, sig, pubKey)

	refundTx.TxIn[0].Witness = refundTxWitness

	if verify {
		e, err := txscript.NewEngine(
			// pubkey script
			contractTx.TxOut[contractOutPoint.Index].PkScript,
			// refund transaction
			refundTx,
			// transaction input index
			0,
			txscript.StandardVerifyFlags,
			txscript.NewSigCache(10),
			txscript.NewTxSigHashes(refundTx, prevOutFetcher),
			contractValue,
			prevOutFetcher)
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

func calcFeePerKb(absoluteFee btcutil.Amount, serializeSize int) float64 {
	return float64(absoluteFee) / float64(serializeSize) / 1e5
}

func (cmd *initiateCmd) runCommand(c *rpc.Client) error {
	var secret [SecretKeySize]byte
	_, err := rand.Read(secret[:])
	if err != nil {
		return err
	}
	secretHash := sha256Hash(secret[:])

	fmt.Printf("Secret:      %x\n", secret)
	fmt.Printf("Secret hash: %x\n\n", secretHash)

	// locktime after 500,000,000 (Tue Nov  5 00:53:20 1985 UTC) is interpreted
	// as a unix time rather than a block height.
	locktime := time.Now().Add(48 * time.Hour).Unix()
	if *regtestFlag || *testnetFlag {
		locktime = time.Now().Add(20 * time.Second).Unix()
	}

	b, err := buildSegwitContract(c, &contractArgs{
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
	fmt.Printf("Locktime: %d seconds - expires at unix time %d (%x))\n\n",
		locktime-time.Now().Unix(), locktime, locktime)
	fmt.Printf("Contract fee: %v (%0.8f BTC/kB)\n", b.contractFee, contractFeePerKb)
	fmt.Printf("Refund fee:   %v (%0.8f BTC/kB)\n\n", b.refundFee, refundFeePerKb)
	fmt.Printf("Contract (%v):\n", b.contractP2WSH)
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
	if *regtestFlag || *testnetFlag {
		locktime = time.Now().Add(20 * time.Second).Unix()
	}

	b, err := buildSegwitContract(c, &contractArgs{
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
	fmt.Printf("Locktime: %d seconds - expires at unix time %d (%x))\n\n",
		locktime-time.Now().Unix(), locktime, locktime)
	fmt.Printf("Contract (%v):\n", b.contractP2WSH)
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
	_, receiver, locktime, _, err := ExtractSwapDetails(
		cmd.contract,
		true, // segwit
		chainParams)
	if err != nil {
		return err
	}

	recipientAddr, err := btcutil.NewAddressWitnessPubKeyHash(receiver.ScriptAddress(), chainParams)
	if err != nil {
		return err
	}

	contractHash256 := sha256.Sum256(cmd.contract)
	contractOutIdx := -1
	var contractValue = int64(0)
	for i, out := range cmd.contractTx.TxOut {
		sc, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, chainParams)
		if err != nil || sc != txscript.WitnessV0ScriptHashTy { // Pay to witness script hash
			continue
		}
		if bytes.Equal(addrs[0].(*btcutil.AddressWitnessScriptHash).WitnessProgram()[:], contractHash256[:]) {
			contractOutIdx = i
			contractValue = out.Value
			break
		}
	}
	if contractOutIdx == -1 {
		return errors.New("contract transaction does not contain the contract output")
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
		Index: uint32(contractOutIdx),
	}

	feePerKb, minFeePerKb, err := getFeePerKb(c)
	if err != nil {
		return err
	}

	redeemTx := wire.NewMsgTx(txVersion)
	// prepare single tx input
	redeemTx.LockTime = uint32(locktime) //ignored?
	redeemTx.AddTxIn(wire.NewTxIn(&contractOutPoint, nil, nil))
	redeemTx.TxIn[0].SignatureScript = nil
	// with input but no output yet get vsize & fee
	redeemSize := redeemTxSerialSizeEst(redeemTx)
	fee := txrules.FeeForSerializeSize(feePerKb, redeemSize)
	// now add the single output
	redeemTx.AddTxOut(wire.NewTxOut(0, outScript))
	redeemTx.TxOut[0].Value = cmd.contractTx.TxOut[contractOutIdx].Value - int64(fee)
	// check dust
	if txrules.IsDustOutput(redeemTx.TxOut[0], minFeePerKb) {
		return fmt.Errorf("redeem output value of %v is dust", btcutil.Amount(redeemTx.TxOut[0].Value))
	}

	// NewTxSigHashes uses the PrevOutFetcher only for detecting a taproot
	// output, so we can provide a dummy that always returns a wire.TxOut
	// with a nil pkScript so that IsPayToTaproot returns false.
	prevOutFetcher := new(txscript.CannedPrevOutputFetcher)
	sigHashes := txscript.NewTxSigHashes(redeemTx, prevOutFetcher)

	sig, pubKey, err := createWitnessSig(redeemTx, 0, contractValue, cmd.contract, sigHashes, recipientAddr, c)
	if err != nil {
		return err
	}
	redeemTxWitness := RedeemP2WSHContract(cmd.contract, sig, pubKey, cmd.secret)

	redeemTx.TxIn[0].Witness = redeemTxWitness

	redeemTxHash := redeemTx.TxHash()
	redeemFeePerKb := calcFeePerKb(fee, redeemTx.SerializeSize())

	var buf bytes.Buffer
	buf.Grow(redeemTx.SerializeSize())
	redeemTx.Serialize(&buf)
	fmt.Printf("Redeem value: %v \n\n", contractValue)
	fmt.Printf("Redeem fee: %v (%0.8f BTC/kB)\n\n", fee, redeemFeePerKb)
	fmt.Printf("Redeem transaction (%v):\n", &redeemTxHash)
	fmt.Printf("%x\n\n", buf.Bytes())

	if verify {
		e, err := txscript.NewEngine(
			// pubkey script
			cmd.contractTx.TxOut[contractOutPoint.Index].PkScript,
			// refund transaction
			redeemTx,
			// transaction input index
			0,
			txscript.StandardVerifyFlags,
			txscript.NewSigCache(10),
			txscript.NewTxSigHashes(redeemTx, prevOutFetcher),
			contractValue,
			prevOutFetcher)
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
	// Loop over witness items from all inputs, searching for one that hashes to
	// the expected hash.
	// We also try to avoid any issues that could be caused by the initiator redeeming
	// the participant's contract with some "nonstandard" or unrecognized tx or script
	// type.
	for _, in := range cmd.redemptionTx.TxIn {
		// Check the witness stack
		for _, w := range in.Witness {
			// fast path
			// check items of the correct length on the witness stack
			if len(w) == SecretKeySize {
				if bytes.Equal(sha256Hash(w), cmd.secretHash) {
					fmt.Printf("Secret: %x\n", w)
					return nil
				}
			}
		}
		containsSecretKey := func(b []byte) bool {
			last := len(b) - SecretKeySize
			for i := 0; i <= last; i++ {
				s := b[i : i+SecretKeySize]
				if bytes.Equal(sha256Hash(s), cmd.secretHash) {
					fmt.Printf("Secret: %x\n", s)
					return true
				}
			}
			return false
		}
		// check inside longer items on witness stack
		for _, w := range in.Witness {
			// an item on the witness stack
			if len(w) >= SecretKeySize {
				if containsSecretKey(w) {
					return nil
				}
			}
		}
	}
	return errors.New("transaction does not contain the secret")
}

func (cmd *auditContractCmd) runCommand(c *rpc.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *auditContractCmd) runOfflineCommand() error {
	contractHash256 := sha256.Sum256(cmd.contract)
	contractOutIdx := -1
	contractValue := int64(0)
	for i, out := range cmd.contractTx.TxOut {
		sc, addrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, chainParams)
		if err != nil || sc != txscript.WitnessV0ScriptHashTy { // Pay to witness script hash
			continue
		}
		if bytes.Equal(addrs[0].(*btcutil.AddressWitnessScriptHash).WitnessProgram()[:], contractHash256[:]) {
			contractOutIdx = i
			contractValue = out.Value
			break
		}
	}
	if contractOutIdx == -1 {
		return errors.New("transaction does not contain the contract output")
	}

	sender, receiver, locktime, secretHash, err := ExtractSwapDetails(
		cmd.contract,
		true, // segwit
		chainParams)
	if err != nil {
		return err
	}

	if len(secretHash) != SecretKeySize {
		return fmt.Errorf("contract specifies strange secret size %v", len(secretHash))
	}
	contractAddr, err := btcutil.NewAddressWitnessScriptHash(contractHash256[:], chainParams)
	if err != nil {
		return err
	}
	recipientAddr, err := btcutil.NewAddressWitnessPubKeyHash(receiver.ScriptAddress(), chainParams)
	if err != nil {
		return err
	}
	refundAddr, err := btcutil.NewAddressWitnessPubKeyHash(sender.ScriptAddress(), chainParams)
	if err != nil {
		return err
	}

	fmt.Printf("Contract address:        %v\n", contractAddr.String())
	fmt.Printf("Contract value:          %v\n", btcutil.Amount(contractValue))
	fmt.Printf("Recipient address:       %v\n", recipientAddr.String())
	fmt.Printf("Author's refund address: %v\n\n", refundAddr)

	fmt.Printf("Secret hash: %x\n\n", secretHash[:])

	if locktime >= txscript.LockTimeThreshold {
		t := time.Unix(int64(locktime), 0)
		fmt.Printf("Locktime: %v\n", t.UTC())
		reachedAt := time.Until(t).Truncate(time.Second)
		if reachedAt > 0 {
			fmt.Printf("Locktime reached in %v\n", reachedAt)
		} else {
			fmt.Printf("Contract refund time lock has expired\n")
		}
	} else {
		fmt.Printf("Locktime: block %v\n", locktime)
	}

	return nil
}

// ExtractSwapDetails extacts the sender and receiver addresses, locktime and
// secret hash from a swap contract. If the provided script is not a swap contract
// an error will be returned.
func ExtractSwapDetails(pkScript []byte, segwit bool, chainParams *chaincfg.Params) (
	sender, receiver btcutil.Address, lockTime uint64, secretHash []byte, err error) {
	// A swap redemption sigScript is <pubkey> <secret> and satisfies the
	// following swap contract.
	//
	// OP_IF
	//  OP_SIZE OP_DATA_1 secretSize OP_EQUALVERIFY OP_SHA256 OP_DATA_32 secretHash OP_EQUALVERIFY OP_DUP OP_HASH160 OP_DATA20 pkHashReceiver
	//     1   +   1     +    1     +      1       +    1    +    1     +   32     +      1       +   1  +    1     +    1    +    20
	// OP_ELSE
	//  OP_DATA4 lockTime OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 OP_DATA_20 pkHashSender
	//     1    +    4   +           1          +   1   +  1   +    1     +   1      +    20
	// OP_ENDIF
	// OP_EQUALVERIFY
	// OP_CHECKSIG
	//
	// 5 bytes if-else-endif-equalverify-checksig
	// 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 1 + 1 + 1 + 20 = 62 bytes for redeem block
	// 1 + 4 + 1 + 1 + 1 + 1 + 1 + 20 = 30 bytes for refund block
	// 5 + 62 + 30 = 97 bytes
	//
	// Note that this allows for a secret size of up to 75 bytes, but the secret
	// must be 32 bytes to be considered valid.
	if len(pkScript) != SwapContractSize {
		err = fmt.Errorf("incorrect swap contract length. expected %d, got %d",
			SwapContractSize, len(pkScript))
		return
	}

	if pkScript[0] == txscript.OP_IF &&
		pkScript[1] == txscript.OP_SIZE &&
		pkScript[2] == txscript.OP_DATA_1 &&
		// secretSize (1 bytes)
		pkScript[4] == txscript.OP_EQUALVERIFY &&
		pkScript[5] == txscript.OP_SHA256 &&
		pkScript[6] == txscript.OP_DATA_32 &&
		// secretHash (32 bytes)
		pkScript[39] == txscript.OP_EQUALVERIFY &&
		pkScript[40] == txscript.OP_DUP &&
		pkScript[41] == txscript.OP_HASH160 &&
		pkScript[42] == txscript.OP_DATA_20 &&
		// receiver's pkh (20 bytes)
		pkScript[63] == txscript.OP_ELSE &&
		pkScript[64] == txscript.OP_DATA_4 &&
		// lockTime (4 bytes)
		pkScript[69] == txscript.OP_CHECKLOCKTIMEVERIFY &&
		pkScript[70] == txscript.OP_DROP &&
		pkScript[71] == txscript.OP_DUP &&
		pkScript[72] == txscript.OP_HASH160 &&
		pkScript[73] == txscript.OP_DATA_20 &&
		// sender's pkh (20 bytes)
		pkScript[94] == txscript.OP_ENDIF &&
		pkScript[95] == txscript.OP_EQUALVERIFY &&
		pkScript[96] == txscript.OP_CHECKSIG {

		if ssz := pkScript[3]; ssz != SecretKeySize {
			return nil, nil, 0, nil, fmt.Errorf("invalid secret size %d", ssz)
		}

		if segwit {
			receiver, err = btcutil.NewAddressWitnessPubKeyHash(pkScript[43:63], chainParams)
			if err != nil {
				return nil, nil, 0, nil, fmt.Errorf("error decoding address from recipient's pubkey hash")
			}

			sender, err = btcutil.NewAddressWitnessPubKeyHash(pkScript[74:94], chainParams)
			if err != nil {
				return nil, nil, 0, nil, fmt.Errorf("error decoding address from sender's pubkey hash")
			}
		} else {
			receiver, err = btcutil.NewAddressPubKeyHash(pkScript[43:63], chainParams)
			if err != nil {
				return nil, nil, 0, nil, fmt.Errorf("error decoding address from recipient's pubkey hash")
			}

			sender, err = btcutil.NewAddressPubKeyHash(pkScript[74:94], chainParams)
			if err != nil {
				return nil, nil, 0, nil, fmt.Errorf("error decoding address from sender's pubkey hash")
			}
		}

		lockTime = uint64(binary.LittleEndian.Uint32(pkScript[65:69]))
		secretHash = pkScript[7:39]

		return
	}

	err = fmt.Errorf("invalid swap contract")
	return
}

// MakeContract creates a segwit atomic swap contract. The secretHash MUST
// be computed from a secret of length SecretKeySize bytes or the resulting
// contract will be invalid.
func MakeContract(rAddr, sAddr btcutil.Address, secretHash []byte, lockTime int64, segwit bool, chainParams *chaincfg.Params) ([]byte, error) {
	if segwit {
		_, ok := rAddr.(*btcutil.AddressWitnessPubKeyHash)
		if !ok {
			return nil, fmt.Errorf("recipient address %s is not a witness-pubkey-hash address", rAddr.String())
		}
		_, ok = sAddr.(*btcutil.AddressWitnessPubKeyHash)
		if !ok {
			return nil, fmt.Errorf("sender address %s is not a witness-pubkey-hash address", sAddr.String())
		}
	} else {
		_, ok := rAddr.(*btcutil.AddressPubKeyHash)
		if !ok {
			return nil, fmt.Errorf("recipient address %s is not a pubkey-hash address", rAddr.String())
		}
		_, ok = sAddr.(*btcutil.AddressPubKeyHash)
		if !ok {
			return nil, fmt.Errorf("sender address %s is not a pubkey-hash address", sAddr.String())
		}
	}
	if len(secretHash) != SecretHashSize {
		return nil, fmt.Errorf("secret hash of length %d not supported", len(secretHash))
	}

	return txscript.NewScriptBuilder().
		AddOps([]byte{
			txscript.OP_IF,
			txscript.OP_SIZE,
		}).AddInt64(SecretKeySize).
		AddOps([]byte{
			txscript.OP_EQUALVERIFY,
			txscript.OP_SHA256,
		}).AddData(secretHash).
		AddOps([]byte{
			txscript.OP_EQUALVERIFY,
			txscript.OP_DUP,
			txscript.OP_HASH160,
		}).AddData(rAddr.ScriptAddress()).
		AddOp(txscript.OP_ELSE).
		AddInt64(lockTime).AddOps([]byte{
		txscript.OP_CHECKLOCKTIMEVERIFY,
		txscript.OP_DROP,
		txscript.OP_DUP,
		txscript.OP_HASH160,
	}).AddData(sAddr.ScriptAddress()).
		AddOps([]byte{
			txscript.OP_ENDIF,
			txscript.OP_EQUALVERIFY,
			txscript.OP_CHECKSIG,
		}).Script()
}

// RefundP2WSHContract returns the witness to refund a contract output
// using the contract author's signature after the locktime has been reached.
// This function assumes P2WSH and appends the contract as the final data push.
func RefundP2WSHContract(contract, sig, pubkey []byte) [][]byte {
	return [][]byte{
		sig,
		pubkey,
		{},
		contract,
	}
}

// RedeemP2WSHContract returns the witness script to redeem a contract output
// using the redeemer's signature and the initiator's secret.  This function
// assumes P2WSH and appends the contract as the final data push.
func RedeemP2WSHContract(contract, sig, pubkey, secret []byte) [][]byte {
	return [][]byte{
		sig,
		pubkey,
		secret,
		{0x01},
		contract,
	}
}
