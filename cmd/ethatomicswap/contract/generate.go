// Copyright (c) 2018 BetterToken BVBA
// Use of this source code is governed by an MIT
// license that can be found at https://github.com/rivine/rivine/blob/master/LICENSE.

package contract

// prerequisite: install ethereum devtools
//
//   go get -u github.com/ethereum/go-ethereum
//   cd $GOPATH/src/github.com/ethereum/go-ethereum/
//   make
//   make devtools

//go:generate sh -c "solc --abi src/contracts/AtomicSwap.sol | awk '/JSON ABI/{x=1;next}x' > AtomicSwap.abi"
//go:generate sh -c "solc --bin src/contracts/AtomicSwap.sol | awk '/Binary:/{x=1;next}x' > AtomicSwap.bin"
//go:generate abigen --bin=AtomicSwap.bin --abi=AtomicSwap.abi --pkg=contract --out=atomicswap.go
