module github.com/decred/atomicswap/cmd/ltcatomicswap

require (
	github.com/Roasbeef/btcutil v0.0.0-20180406014609-dfb640c57141 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/golangcrypto v0.0.0-20150304025918-53f62d9b43e8 // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/ltcsuite/ltcd v0.0.0-20181017022805-01737289d815
	github.com/ltcsuite/ltcutil v0.0.0-20170825230323-a88d7dfb1c02
	github.com/ltcsuite/ltcwallet v0.0.0-20170424230739-689fccd15fdf
	github.com/roasbeef/btcd v0.0.0-20180418012700-a03db407e40d // indirect
	github.com/roasbeef/btcutil v0.0.0-20180406014609-dfb640c57141 // indirect
	golang.org/x/crypto v0.0.0-20181030102418-4d3f4d9ffa16
)

replace (
	github.com/ltcsuite/ltcd => github.com/jrick/btcd v0.0.0-20180219142856-941d1c922dfd
	github.com/ltcsuite/ltcutil => github.com/jrick/btcutil v0.0.0-20170913155058-8e0fd08dd902
	github.com/ltcsuite/ltcwallet => github.com/jrick/btcwallet v0.0.0-20170912202655-d2214fcebbf4
)
