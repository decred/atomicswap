package contract

// prerequisite: install ethereum devtools
//
//   go get -u github.com/ethereum/go-ethereum
//   cd $GOPATH/src/github.com/ethereum/go-ethereum/
//   make
//   make devtools
//

//go:generate sh -c "solc --abi src/contracts/AtomicSwap.sol | awk '/JSON ABI/{x=1;next}x' > AtomicSwap.abi"
//go:generate abigen --abi=AtomicSwap.abi --pkg=contract --out=atomicswap.go
