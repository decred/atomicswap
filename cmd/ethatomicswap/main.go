// Copyright (c) 2018 The Decred developers and Contributors
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/decred/atomicswap/cmd/ethatomicswap/contract"
)

var (
	chainConfig = params.MainnetChainConfig
)

const (
	initiateLockPeriodInSeconds    = 48 * 60 * 60
	participateLockPeriodInSeconds = 24 * 60 * 60

	maxGasLimit = 210000
)

// TODO: find way to not require keyFile/passphrase
//       (and certainly not in the way we currently do)

var (
	flagset        = flag.NewFlagSet("", flag.ExitOnError)
	connectFlag    = flagset.String("s", "http://localhost:8545", "endpoint of Ethereum RPC server")
	contractFlag   = flagset.String("c", "", "hex-enoded address of the deployed contract")
	keyFileFlag    = flagset.String("keyfile", "", "file containing the key used for signing")
	passphraseFlag = flagset.String("passphrase", "", "passphrase used for decrypting the key")
	timeoutFlag    = flagset.Duration("t", 0, "optional timeout of any call made")
	testnetFlag    = flagset.Bool("testnet", false, "use testnet (Rinkeby) network")
)

// TODO: better error reporting:
//       now all contract-originated errors return
//       "failed to estimate gas needed: gas required exceeds allowance or always failing transaction"

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
//   cp2 participates with cp1 H(S) (eth)
//   cp1 redeems eth revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems dcr with S
//
// Scenerio 2:
//   cp1 initiates (eth)
//   cp2 participates with cp1 H(S) (dcr)
//   cp1 redeems dcr revealing S
//     - must verify H(S) in contract is hash of known secret
//   cp2 redeems eth with S

func init() {
	flagset.Usage = func() {
		fmt.Println("Usage: ethatomicswap [flags] cmd [cmd args]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  initiate <participant address> <amount>")
		fmt.Println("  participate <initiator address> <amount> <secret hash>")
		fmt.Println("  redeem <contract transaction> <secret>")
		fmt.Println("  refund <contract transaction>")
		fmt.Println("  extractsecret <redemption transaction> <secret hash>")
		fmt.Println("  auditcontract <contract transaction>")
		fmt.Println()
		fmt.Println("Extra Commands:")
		fmt.Println("  deploycontract")
		fmt.Println("  validatedeployedcontract <deploy transaction>")
		fmt.Println()
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

type command interface {
	runCommand(swapContractTransactor) error
}

// offline commands don't require wallet RPC.
type offlineCommand interface {
	command
	runOfflineCommand() error
}

type initiateCmd struct {
	cp2Addr common.Address
	amount  *big.Int // in wei
}

type participateCmd struct {
	cp1Addr    common.Address
	amount     *big.Int // in wei
	secretHash [32]byte
}

type redeemCmd struct {
	contractTx *types.Transaction
	secret     [32]byte
}

type refundCmd struct {
	contractTx *types.Transaction
}

type extractSecretCmd struct {
	redemptionTx *types.Transaction
	secretHash   [32]byte
}

type auditContractCmd struct {
	contractTx *types.Transaction
}

type deployContractCmd struct{}

type validateDeployedContractCmd struct {
	deployTx *types.Transaction
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

const (
	weiPrecision = 18
)

func parseEthAsWei(str string) (*big.Int, error) {
	initialParts := strings.SplitN(str, ".", 2)
	if len(initialParts) == 1 {
		// a round number, simply multiply and go
		i, ok := big.NewInt(0).SetString(initialParts[0], 10)
		if !ok {
			return nil, errors.New("invalid round amount")
		}
		switch i.Cmp(big.NewInt(0)) {
		case -1:
			return nil, errors.New("invalid round amount: cannot be negative")
		case 0:
			return nil, errors.New("invalid round amount: cannot be nil")
		}
		return i.Mul(i, new(big.Int).Exp(big.NewInt(10), big.NewInt(weiPrecision), nil)), nil
	}

	whole := initialParts[0]
	dac := initialParts[1]
	sn := uint(weiPrecision)
	if l := uint(len(dac)); l < sn {
		sn = l
	}
	whole += initialParts[1][:sn]
	dac = dac[sn:]
	for i := range dac {
		if dac[i] != '0' {
			return nil, errors.New("invalid or too precise amount")
		}
	}
	i, ok := big.NewInt(0).SetString(whole, 10)
	if !ok {
		return nil, errors.New("invalid amount")
	}
	switch i.Cmp(big.NewInt(0)) {
	case -1:
		return nil, errors.New("invalid round amount: cannot be negative")
	case 0:
		return nil, errors.New("invalid round amount: cannot be nil")
	}
	i.Mul(i, big.NewInt(0).Exp(
		big.NewInt(10), big.NewInt(int64(weiPrecision-sn)), nil))

	switch i.Cmp(big.NewInt(0)) {
	case -1:
		return nil, errors.New("invalid round amount: cannot be negative")
	case 0:
		return nil, errors.New("invalid round amount: cannot be nil")
	}
	return i, nil
}

func formatWeiAsEthString(w *big.Int) string {
	if w.Cmp(big.NewInt(0)) == 0 {
		return "0"
	}

	str := w.String()
	l := uint(len(str))
	if l > weiPrecision {
		idx := l - weiPrecision
		str = strings.TrimRight(str[:idx]+"."+str[idx:], "0")
		str = strings.TrimRight(str, ".")
		if len(str) == 0 {
			return "0"
		}
		return str
	}
	str = "0." + strings.Repeat("0", int(weiPrecision-l)) + str
	str = strings.TrimRight(str, "0")
	str = strings.TrimRight(str, ".")
	return str
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
		cmdArgs = 2
	case "refund":
		cmdArgs = 1
	case "extractsecret":
		cmdArgs = 2
	case "auditcontract":
		cmdArgs = 1
	case "deploycontract":
		cmdArgs = 0
	case "validatedeployedcontract":
		cmdArgs = 1
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
		chainConfig = params.RinkebyChainConfig
	}

	var cmd command
	switch args[0] {
	case "initiate":
		cp2Addr := common.HexToAddress(args[1])
		amount, err := parseEthAsWei(args[2])
		if err != nil {
			return fmt.Errorf("unexpected amount argument (%v): %v", args[2], err), true
		}
		cmd = &initiateCmd{
			cp2Addr: cp2Addr,
			amount:  amount,
		}

	case "participate":
		cp1Addr := common.HexToAddress(args[1])
		amount, err := parseEthAsWei(args[2])
		if err != nil {
			return fmt.Errorf("unexpected amount argument (%v): %v", args[2], err), true
		}
		secretHash, err := hexDecodeSha256Hash("secret hash", args[3])
		if err != nil {
			return err, true
		}
		cmd = &participateCmd{
			cp1Addr:    cp1Addr,
			amount:     amount,
			secretHash: secretHash,
		}

	case "redeem":
		contractTx, err := hexDecodeTransaction(args[1])
		if err != nil {
			return err, true
		}
		secret, err := hexDecodeSha256Hash("secret", args[2])
		if err != nil {
			return err, true
		}
		cmd = &redeemCmd{
			contractTx: contractTx,
			secret:     secret,
		}

	case "refund":
		contractTx, err := hexDecodeTransaction(args[1])
		if err != nil {
			return err, true
		}
		cmd = &refundCmd{
			contractTx: contractTx,
		}

	case "extractsecret":
		redemptionTx, err := hexDecodeTransaction(args[1])
		if err != nil {
			return err, true
		}
		secretHash, err := hexDecodeSha256Hash("secret hash", args[2])
		if err != nil {
			return err, true
		}
		cmd = &extractSecretCmd{
			redemptionTx: redemptionTx,
			secretHash:   secretHash,
		}

	case "auditcontract":
		contractTx, err := hexDecodeTransaction(args[1])
		if err != nil {
			return err, true
		}
		cmd = &auditContractCmd{
			contractTx: contractTx,
		}

	case "deploycontract":
		cmd = new(deployContractCmd)

	case "validatedeployedcontract":
		deployTx, err := hexDecodeTransaction(args[1])
		if err != nil {
			return err, true
		}
		cmd = &validateDeployedContractCmd{
			deployTx: deployTx,
		}

	default:
		panic(fmt.Sprintf("unknown command %v", args[0]))
	}

	// Offline commands don't need to talk to the wallet.
	if cmd, ok := cmd.(offlineCommand); ok {
		return cmd.runOfflineCommand(), false
	}

	client, err := dialClient()
	if err != nil {
		return fmt.Errorf("rpc connect: %v", err), false
	}
	defer client.Close()

	// create (swap) contract transactor
	contractAddr, err := getDeployedContractAddress()
	if err != nil {
		return fmt.Errorf("failed to get contract address: %v", err), false
	}
	sct, err := newSwapContractTransactor(client, contractAddr)
	if err != nil {
		return err, false
	}

	err = cmd.runCommand(sct)
	return err, false
}

func getDeployedContractAddress() (common.Address, error) {
	contractAddress := *contractFlag
	if contractAddress != "" {
		return common.HexToAddress(contractAddress), nil
	}
	switch chainConfig {
	case params.MainnetChainConfig:
		return common.Address{}, errors.New("no default contract exist yet for the main net")
	case params.RinkebyChainConfig:
		return common.HexToAddress("2661CBAa149721f7c5FAB3FA88C1EA564A683631"), nil
	}

	panic("unknown chain config for chain ID: " + chainConfig.ChainID.String())
}

func sha256Hash(x []byte) [sha256.Size]byte {
	h := sha256.Sum256(x)
	return h
}

func hexDecodeSha256Hash(name, str string) (hash [sha256.Size]byte, err error) {
	slice, err := hex.DecodeString(strings.TrimPrefix(str, "0x"))
	if err != nil {
		err = errors.New(name + " must be hex encoded")
		return
	}
	if len(slice) != sha256.Size {
		err = errors.New(name + " has wrong size")
		return
	}
	copy(hash[:], slice)
	return
}

func hexDecodeTransaction(str string) (*types.Transaction, error) {
	slice, err := hex.DecodeString(strings.TrimPrefix(str, "0x"))
	if err != nil {
		return nil, errors.New("transaction must be hex encoded")
	}
	var tx types.Transaction
	err = rlp.DecodeBytes(slice, &tx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %v", err)
	}
	return &tx, nil
}

func generateSecretHashPair() (secret, secretHash [sha256.Size]byte) {
	rand.Read(secret[:])
	secretHash = sha256Hash(secret[:])
	return
}

func newTransactOpts() (*bind.TransactOpts, error) {
	f, err := os.Open(*keyFileFlag)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %v", err)
	}
	return bind.NewTransactor(f, *passphraseFlag)
}

func promptPublishTx(name string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Publish %s transaction? [y/N] ", name)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		answer = strings.TrimSpace(strings.ToLower(answer))

		switch answer {
		case "y", "yes":
			return true, nil
		case "n", "no", "":
			return false, nil
		default:
			fmt.Println("please answer y or n")
			continue
		}
	}
}

func calcGasCost(limit uint64, c *ethclient.Client) (*big.Int, error) {
	price, err := c.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}
	return price.Mul(price, big.NewInt(int64(limit))), nil
}

func unpackContractInputParams(abi abi.ABI, tx *types.Transaction) (params struct {
	LockDuration *big.Int
	SecretHash   [sha256.Size]byte
	ToAddress    common.Address
}, err error) {
	txData := tx.Data()

	// first 4 bytes contain the id, so let's get method using that ID
	method, err := abi.MethodById(txData[:4])
	if err != nil {
		err = fmt.Errorf("failed to get method using its parsed id: %v", err)
		return
	}

	// unpack and return the params
	paramSlice := []interface{}{ // unpack as slice, so we don't enforce field names
		&params.LockDuration,
		&params.SecretHash,
		&params.ToAddress,
	}
	err = method.Inputs.Unpack(&paramSlice, txData[4:])
	if err != nil {
		err = fmt.Errorf("failed to unpack method's input params: %v", err)
	}
	return
}

func (cmd *initiateCmd) runCommand(sct swapContractTransactor) error {
	secret, secretHash := generateSecretHashPair()
	tx, err := sct.initiateTx(cmd.amount, secretHash, cmd.cp2Addr)
	if err != nil {
		return fmt.Errorf("failed to create initiate TX: %v", err)
	}

	fmt.Printf("Amount: %s Wei (%s ETH)\n\n",
		cmd.amount.String(), formatWeiAsEthString(cmd.amount))

	fmt.Printf("Secret:      %x\n", secret)
	fmt.Printf("Secret hash: %x\n\n", secretHash)

	initiateTxCost := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
	fmt.Printf("Contract fee: %s ETH\n", formatWeiAsEthString(initiateTxCost))
	refundTxCost, err := sct.maxGasCost()
	if err != nil {
		return fmt.Errorf("failed to estimate max gas cost for refund tx: %v", err)
	}
	fmt.Printf("Refund fee:   %s ETH (max)\n\n", formatWeiAsEthString(refundTxCost))

	fmt.Printf("Chain ID:         %s\n", chainConfig.ChainID.String())
	fmt.Printf("Contract Address: %x\n", sct.contractAddr)

	fmt.Printf("Contract transaction (%x):\n", tx.Hash())
	txBytes, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return fmt.Errorf("failed to encode contract TX: %v", err)
	}
	fmt.Printf("%x\n\n", txBytes)

	publish, err := promptPublishTx("contract")
	if err != nil || !publish {
		return err
	}

	err = tx.Send()
	if err != nil {
		return err
	}
	fmt.Printf("Published contract transaction (%x)\n", tx.Hash())
	return nil
}

func (cmd *participateCmd) runCommand(sct swapContractTransactor) error {
	tx, err := sct.participateTx(cmd.amount, cmd.secretHash, cmd.cp1Addr)
	if err != nil {
		return fmt.Errorf("failed to create participate TX: %v", err)
	}

	fmt.Printf("Amount: %s Wei (%s ETH)\n\n",
		cmd.amount.String(), formatWeiAsEthString(cmd.amount))

	participateTxCost := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
	fmt.Printf("Contract fee: %s ETH\n", formatWeiAsEthString(participateTxCost))
	refundTxCost, err := sct.maxGasCost()
	if err != nil {
		return fmt.Errorf("failed to estimate max gas cost for refund tx: %v", err)
	}
	fmt.Printf("Refund fee:   %s ETH (max)\n\n", formatWeiAsEthString(refundTxCost))

	fmt.Printf("Chain ID:         %s\n", chainConfig.ChainID.String())
	fmt.Printf("Contract Address: %x\n", sct.contractAddr)

	fmt.Printf("Contract transaction (%x):\n", tx.Hash())
	txBytes, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return fmt.Errorf("failed to encode contract TX: %v", err)
	}
	fmt.Printf("%x\n\n", txBytes)

	publish, err := promptPublishTx("contract")
	if err != nil || !publish {
		return err
	}

	err = tx.Send()
	if err != nil {
		return err
	}
	fmt.Printf("Published contract transaction (%x)\n", tx.Hash())
	return nil
}

func (cmd *redeemCmd) runCommand(sct swapContractTransactor) error {
	params, err := unpackContractInputParams(sct.abi, cmd.contractTx)
	if err != nil {
		return err
	}
	expectedSecretHash := sha256Hash(cmd.secret[:])
	if expectedSecretHash != params.SecretHash {
		return fmt.Errorf(
			"contract transaction contains unexpected secret hash (%x)",
			params.SecretHash)
	}
	tx, err := sct.redeemTx(params.SecretHash, cmd.secret)
	if err != nil {
		return fmt.Errorf("failed to create redeem TX: %v", err)
	}

	redeemTxCost := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
	fmt.Printf("Redeem fee: %s ETH\n\n", formatWeiAsEthString(redeemTxCost))

	fmt.Printf("Chain ID:         %s\n", chainConfig.ChainID.String())
	fmt.Printf("Contract Address: %x\n", sct.contractAddr)

	fmt.Printf("Redeem transaction (%x):\n", tx.Hash())
	txBytes, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return fmt.Errorf("failed to encode redeem TX: %v", err)
	}
	fmt.Printf("%x\n\n", txBytes)

	publish, err := promptPublishTx("redeem")
	if err != nil || !publish {
		return err
	}

	err = tx.Send()
	if err != nil {
		return err
	}
	fmt.Printf("Published redeem transaction (%x)\n", tx.Hash())
	return nil
}

func (cmd *refundCmd) runCommand(sct swapContractTransactor) error {
	params, err := unpackContractInputParams(sct.abi, cmd.contractTx)
	if err != nil {
		return err
	}
	tx, err := sct.refundTx(params.SecretHash)
	if err != nil {
		return fmt.Errorf("failed to create refund TX: %v", err)
	}

	refundTxCost := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
	fmt.Printf("Refund fee: %s ETH\n\n", formatWeiAsEthString(refundTxCost))

	fmt.Printf("Chain ID:         %s\n", chainConfig.ChainID.String())
	fmt.Printf("Contract Address: %x\n", sct.contractAddr)

	fmt.Printf("Refund transaction (%x):\n", tx.Hash())
	txBytes, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return fmt.Errorf("failed to encode refund TX: %v", err)
	}
	fmt.Printf("%x\n\n", txBytes)

	publish, err := promptPublishTx("refund")
	if err != nil || !publish {
		return err
	}

	err = tx.Send()
	if err != nil {
		return err
	}
	fmt.Printf("Published refund transaction (%x)\n", tx.Hash())
	return nil
}

func (cmd *extractSecretCmd) runCommand(swapContractTransactor) error {
	return cmd.runOfflineCommand()
}

func (cmd *extractSecretCmd) runOfflineCommand() error {
	abi, err := abi.JSON(strings.NewReader(contract.ContractABI))
	if err != nil {
		return fmt.Errorf("failed to read (smart) contract ABI: %v", err)
	}

	txData := cmd.redemptionTx.Data()

	// first 4 bytes contain the id, so let's get method using that ID
	method, err := abi.MethodById(txData[:4])
	if err != nil {
		return fmt.Errorf("failed to get method using its parsed id: %v", err)
	}
	if method.Name != "redeem" {
		return fmt.Errorf("unexpected name for unpacked method ID: %s", method.Name)
	}

	// prepare the params
	params := struct {
		Secret     [sha256.Size]byte
		SecretHash [sha256.Size]byte
	}{}

	// unpack the params
	err = method.Inputs.Unpack(&params, txData[4:])
	if err != nil {
		return fmt.Errorf("failed to unpack method's input params: %v", err)
	}

	// ensure secret hash is the same as the given one
	if cmd.secretHash != params.SecretHash {
		return fmt.Errorf("unexpected secret hash found: %x", params.SecretHash)
	}
	secretHash := sha256Hash(params.Secret[:])
	if params.SecretHash != secretHash {
		return fmt.Errorf("unexpected secret found: %x", params.Secret)
	}

	// print secret
	fmt.Printf("Secret: %x\n", params.Secret)
	return nil
}

func (cmd *auditContractCmd) runCommand(sct swapContractTransactor) error {
	// unpack input params from contract tx
	params, err := unpackContractInputParams(sct.abi, cmd.contractTx)
	if err != nil {
		return err
	}

	rpcTransaction := struct {
		tx          *types.Transaction
		BlockNumber *string
		BlockHash   *common.Hash
		From        *common.Address
	}{}

	// get transaction by hash
	contractHash := cmd.contractTx.Hash()
	err = sct.client.rpcClient.CallContext(newContext(),
		&rpcTransaction, "eth_getTransactionByHash", contractHash)
	if err != nil {
		return fmt.Errorf(
			"failed to find transaction (%x): %v", contractHash, err)
	}
	if rpcTransaction.BlockNumber == nil || *rpcTransaction.BlockNumber == "" || *rpcTransaction.BlockNumber == "0" {
		return fmt.Errorf("transaction (%x) is pending", contractHash)
	}

	// get block in order to know the timestamp of the txn
	block, err := sct.client.BlockByHash(newContext(), *rpcTransaction.BlockHash)
	if err != nil {
		return fmt.Errorf(
			"failed to find block (%x): %v", rpcTransaction.BlockHash, err)
	}

	// compute the locktime
	lockTime := time.Unix(block.Time().Int64()+params.LockDuration.Int64(), 0)

	// print contract info

	fmt.Printf("Contract address:        %x\n", cmd.contractTx.To())
	fmt.Printf("Contract value:          %s ETH\n", formatWeiAsEthString(cmd.contractTx.Value()))
	fmt.Printf("Recipient address:       %x\n", params.ToAddress)
	fmt.Printf("Author's refund address: %x\n\n", rpcTransaction.From)

	fmt.Printf("Secret hash: %x\n\n", params.SecretHash)

	// NOTE:
	// the reason we require th node for this method,
	// is because we need to be able to know the transaction's timestamp

	fmt.Printf("Locktime: %v\n", lockTime.UTC())
	reachedAt := lockTime.Sub(time.Now().UTC()).Truncate(time.Second)
	if reachedAt > 0 {
		fmt.Printf("Locktime reached in %v\n", reachedAt)
	} else {
		fmt.Printf("Contract refund time lock has expired\n")
	}
	return nil
}

func (cmd *deployContractCmd) runCommand(sct swapContractTransactor) error {
	tx, err := sct.deployTx()
	if err != nil {
		return fmt.Errorf("failed to create deploy TX: %v", err)
	}

	deployTxCost := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
	fmt.Printf("Deploy fee: %s ETH\n\n", formatWeiAsEthString(deployTxCost))

	fmt.Printf("Chain ID:         %s\n", chainConfig.ChainID.String())
	fmt.Printf("Contract Address: %x\n", sct.contractAddr)

	fmt.Printf("Deploy transaction (%x):\n", tx.Hash())
	txBytes, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return fmt.Errorf("failed to encode deploy TX: %v", err)
	}
	fmt.Printf("%x\n\n", txBytes)

	publish, err := promptPublishTx("deploy")
	if err != nil || !publish {
		return err
	}

	err = tx.Send()
	if err != nil {
		return err
	}
	fmt.Printf("Published deploy transaction (%x)\n", tx.Hash())
	return nil
}

func (cmd *validateDeployedContractCmd) runCommand(swapContractTransactor) error {
	return cmd.runOfflineCommand()
}

func (cmd *validateDeployedContractCmd) runOfflineCommand() error {
	if bytes.Compare(cmd.deployTx.Data(), contractBin) != 0 {
		return errors.New("deployed contract is invalid (make sure to use the same Solidity contract source code and Compiler version (0.4.24))")
	}
	fmt.Println("Contract is valid")
	return nil
}

// newSwapContractTransactor creates a new swapContract instance,
// see swapContractTransactor for more information
func newSwapContractTransactor(c *ethClient, contractAddr common.Address) (swapContractTransactor, error) {
	parsed, err := abi.JSON(strings.NewReader(contract.ContractABI))
	if err != nil {
		return swapContractTransactor{}, fmt.Errorf("failed to read (smart) contract ABI: %v", err)
	}
	signer, fromAddr, err := newSigner()
	if err != nil {
		return swapContractTransactor{}, fmt.Errorf("failed to create tx signer: %v", err)
	}
	return swapContractTransactor{
		abi:          parsed,
		signer:       signer,
		client:       c,
		fromAddr:     fromAddr,
		contractAddr: contractAddr,
	}, nil
}

// newSigner creates a signer func using the flag-passed
// private credentials of the sender
func newSigner() (bind.SignerFn, common.Address, error) {
	json, err := ioutil.ReadFile(*keyFileFlag)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("failed to read key file (%s): %v", *keyFileFlag, err)
	}
	key, err := keystore.DecryptKey(json, *passphraseFlag)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("failed to decrypt (JSON) file (%s): %v", *keyFileFlag, err)
	}
	privKey := key.PrivateKey
	keyAddr := crypto.PubkeyToAddress(privKey.PublicKey)
	return func(signer types.Signer, address common.Address, tx *types.Transaction) (*types.Transaction, error) {
		if address != keyAddr {
			return nil, errors.New("not authorized to sign this account")
		}
		signature, err := crypto.Sign(signer.Hash(tx).Bytes(), privKey)
		if err != nil {
			return nil, err
		}
		return tx.WithSignature(signer, signature)
	}, keyAddr, nil
}

type (
	// swapContractTransactor allows the creation of transactions for the different
	// atomic swap actions
	swapContractTransactor struct {
		abi          abi.ABI
		signer       bind.SignerFn
		client       *ethClient
		fromAddr     common.Address
		contractAddr common.Address
	}

	// swapTransaction adds send functionality to the transaction,
	// such that it can be send in an easy way
	swapTransaction struct {
		*types.Transaction
		client *ethClient
		ctx    context.Context
	}
)

func (sct *swapContractTransactor) initiateTx(amount *big.Int, secretHash [sha256.Size]byte, participant common.Address) (*swapTransaction, error) {
	return sct.newTransaction(
		amount, "initiate",
		// lock duration
		big.NewInt(initiateLockPeriodInSeconds),
		// secret hash
		secretHash,
		// participant
		participant,
	)
}

func (sct *swapContractTransactor) participateTx(amount *big.Int, secretHash [sha256.Size]byte, initiator common.Address) (*swapTransaction, error) {
	return sct.newTransaction(
		amount, "participate",
		// lock duration
		big.NewInt(participateLockPeriodInSeconds),
		// secret hash
		secretHash,
		// participant
		initiator,
	)
}

func (sct *swapContractTransactor) redeemTx(secretHash, secret [sha256.Size]byte) (*swapTransaction, error) {
	return sct.newTransaction(
		nil, "redeem",
		// secret,
		secret,
		// secret hash
		secretHash,
	)
}

func (sct *swapContractTransactor) refundTx(secretHash [sha256.Size]byte) (*swapTransaction, error) {
	return sct.newTransaction(
		nil, "refund",
		// secret hash
		secretHash,
	)
}

func (sct *swapContractTransactor) deployTx() (*swapTransaction, error) {
	return sct.newTransactionWithInput(nil, false, common.FromHex(contract.ContractBin))
}

func (sct *swapContractTransactor) maxGasCost() (*big.Int, error) {
	ctx := newContext()
	gasPrice, err := sct.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %v", err)
	}
	return gasPrice.Mul(gasPrice, big.NewInt(maxGasLimit)), nil
}

func (sct *swapContractTransactor) newTransaction(amount *big.Int, name string, params ...interface{}) (*swapTransaction, error) {
	// pack up the parameters and contract name
	input, err := sct.abi.Pack(name, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack input")
	}
	return sct.newTransactionWithInput(amount, true, input)
}

func (sct *swapContractTransactor) newTransactionWithInput(amount *big.Int, contractCall bool, input []byte) (*swapTransaction, error) {
	// define the TransactOpts for binding
	opts, err := sct.calcBaseOpts(amount)
	if err != nil {
		return nil, err
	}
	opts.GasLimit, err = sct.calcGasLimit(opts.Context, opts.Value, opts.GasPrice, contractCall, input)
	if err != nil {
		return nil, err
	}

	// create the raw transaction
	rawTx := types.NewTransaction(
		opts.Nonce.Uint64(),
		sct.contractAddr,
		opts.Value,
		opts.GasLimit,
		opts.GasPrice,
		input,
	)

	// sign the transaction and return it
	signedTx, err := opts.Signer(types.HomesteadSigner{}, opts.From, rawTx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}
	return &swapTransaction{
		Transaction: signedTx,
		client:      sct.client,
		ctx:         opts.Context,
	}, nil
}

func (sct *swapContractTransactor) calcBaseOpts(amount *big.Int) (*bind.TransactOpts, error) {
	ctx := newContext()
	nonce, err := sct.client.PendingNonceAt(ctx, sct.fromAddr)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to retrieve account (%x) nonce: %v",
			sct.fromAddr, err)
	}
	gasPrice, err := sct.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %v", err)
	}
	if amount == nil {
		amount = new(big.Int)
	}
	return &bind.TransactOpts{
		From:     sct.fromAddr,
		Nonce:    new(big.Int).SetUint64(nonce),
		Signer:   sct.signer,
		Value:    amount,
		GasPrice: gasPrice,
		Context:  ctx,
	}, nil
}

func (sct *swapContractTransactor) calcGasLimit(ctx context.Context, amount, gasPrice *big.Int, contractCall bool, input []byte) (uint64, error) {
	if contractCall {
		if code, err := sct.client.PendingCodeAt(ctx, sct.contractAddr); err != nil {
			return 0, fmt.Errorf("failed to estimate gas needed: %v", err)
		} else if len(code) == 0 {
			return 0, fmt.Errorf("failed to estimate gas needed: %v", bind.ErrNoCode)
		}
	}
	// If the contract surely has code (or code is not needed), estimate the transaction
	msg := ethereum.CallMsg{
		From:  sct.fromAddr,
		Value: amount,
		Data:  input,
	}
	if contractCall {
		msg.To = &sct.contractAddr
	}
	gasLimit, err := sct.client.EstimateGas(ctx, msg)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas needed: %v", err)
	}
	if contractCall && gasLimit > maxGasLimit {
		return 0, fmt.Errorf("%d exceeds the hardcoded code-call gas limit of %d", gasLimit, maxGasLimit)
	}
	return gasLimit, nil
}

func (st *swapTransaction) Send() error {
	err := st.client.SendTransaction(st.ctx, st.Transaction)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}
	return nil
}

func dialClient() (*ethClient, error) {
	c, err := rpc.DialContext(context.Background(), *connectFlag)
	if err != nil {
		return nil, err
	}
	return &ethClient{
		Client:    ethclient.NewClient(c),
		rpcClient: c,
	}, nil
}

type ethClient struct {
	*ethclient.Client
	rpcClient *rpc.Client
}

func newContext() context.Context {
	if *timeoutFlag == 0 {
		return context.Background()
	}
	ctx, _ := context.WithTimeout(context.Background(), *timeoutFlag)
	return ctx
}

var (
	contractBin = func() []byte {
		b, err := hex.DecodeString(contract.ContractBin)
		if err != nil {
			panic("invalid binary contract: " + err.Error())
		}
		return b
	}()
)
