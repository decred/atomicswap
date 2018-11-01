# AtomicSwap Smart Contract for the EVM

In this directory you can find the smart contract, written in Solidity,
to be used together with the `ethatomicswap` tool.

## WARNING

This contract has only recently been developed, and has not received any external audits yet. Please use common sense when doing anything that deals with real money! We take no responsibility for any security problem you might experience while using this contract.

## Test

You can test the AtomicSwap smart contract,
found as [/cmd/ethatomicswap/solidity/contracts/AtomicSwap.sol](/cmd/ethatomicswap/solidity/contracts/AtomicSwap.sol) using a single command. It has however following prerequisites:

* Install NodeJS (10.5.0), which bundles _npm_ as well;
* Install truffle: `npm install -g truffle`;

Optionally you can also install and run
Ganache ( <https://truffleframework.com/ganache>).

Once you have fulfilled all prerequisites listed above,
you can run the unit tests provided with the AtomicSwap contract, using:

```
truffle test
```

## Deploy

// TODO
