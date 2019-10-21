**NOTICE Mar 1 2018:** The atomic swap contract has been updated to specify the
secret sizes to prevent fraudulent swaps between two cryptocurrencies with
different maximum data sizes.  Old contracts will not be usable by the new tools
and vice-versa.  Please rebuild all tools before conducting new atomic swaps.

# Decred-compatible cross-chain atomic swapping

This repository contains utilities to manually perform cross-chain atomic swaps
between various supported pairs of cryptocurrencies.  At the moment, support
exists for the following coins and wallets:

* Bitcoin ([Bitcoin Core](https://github.com/bitcoin/bitcoin))
* Bitcoin Cash ([Bitcoin ABC](https://github.com/Bitcoin-ABC/bitcoin-abc), [Bitcoin Unlimited](https://github.com/BitcoinUnlimited/BitcoinUnlimited), [Bitcoin XT](https://github.com/bitcoinxt/bitcoinxt))
* Decred ([dcrwallet](https://github.com/decred/dcrwallet))
* Litecoin ([Litecoin Core](https://github.com/litecoin-project/litecoin))
* Monacoin ([Monacoin Core](https://github.com/monacoinproject/monacoin))
* Particl ([Particl Core](https://github.com/particl/particl-core))
* Qtum ([Qtum Core](https://github.com/qtumproject/qtum))
* Vertcoin ([Vertcoin Core](https://github.com/vertcoin/vertcoin))
* Viacoin ([Viacoin Core](https://github.com/viacoin/viacoin))
* Zcoin ([Zcoin Core](https://github.com/zcoinofficial/zcoin))

External support exists for the following coins and wallets:

* ThreeFold Token ([ThreeFold Chain](https://github.com/threefoldfoundation/tfchain))

Pull requests implementing support for additional cryptocurrencies and wallets
are encouraged.  See [GitHub project
1](https://github.com/decred/atomicswap/projects/1) for the status of coins
being considered.  Implementing support for a new cryptocurrency provides atomic
swap compatibility between all current and future supported coins.

These tools do not operate solely on-chain.  A side-channel is required between
each party performing the swap in order to exchange additional data.  This
side-channel could be as simple as a text chat and copying data.  Until a more
streamlined implementation of the side channel exists, such as the Lightning
Network, these tools suffice as a proof-of-concept for cross-chain atomic swaps
and a way for early adopters to try out the technology.

Due to the requirements of manually exchanging data and creating, sending, and
watching for the relevant transactions, it is highly recommended to read this
README in its entirety before attempting to use these tools.  The sections
below explain the principles on which the tools operate, the instructions for
how to use them safely, and an example swap between Decred and Bitcoin.

## Build instructions

Requires [Go 1.11](https://golang.org/dl/) or later

- Clone atomicswap somewhere outside `$GOPATH`:
  ```
  $ git clone https://github.com/decred/atomicswap && cd atomicswap
  ```

- To install a single tool:
  ```
  $ cd cmd/dcratomicswap && go install
  ```

## Theory

A cross-chain swap is a trade between two users of different cryptocurrencies.
For example, one party may send Decred to a second party's Decred address, while
the second party would send Bitcoin to the first party's Bitcoin address.
However, as the blockchains are unrelated and transactions can not be reversed,
this provides no protection against one of the parties never honoring their end
of the trade.  One common solution to this problem is to introduce a
mutually-trusted third party for escrow.  An atomic cross-chain swap solves this
problem without the need for a third party.

Atomic swaps involve each party paying into a contract transaction, one contract
for each blockchain.  The contracts contain an output that is spendable by
either party, but the rules required for redemption are different for each party
involved.

One party (called counterparty 1 or the initiator) generates a secret and pays
the intended trade amount into a contract transaction.  The contract output can
be redeemed by the second party (called counterparty 2 or the participant) as
long as the secret is known.  If a period of time (typically 48 hours) expires
after the contract transaction has been mined but has not been redeemed by the
participant, the contract output can be refunded back to the initiator's wallet.

For simplicity, we assume the initiator wishes to trade Bitcoin for Decred with
the participant.  The initiator can also trade Decred for Bitcoin and the steps
will be the same, but with each step performed on the other blockchain.

The participant is unable to spend from the initiator's Bitcoin contract at this
point because the secret is unknown by them.  If the initiator revealed their
secret at this point, the participant could spend from the contract without ever
honoring their end of the trade.

The participant creates a similar contract transaction to the initiator's but on
the Decred blockchain and pays the intended Decred amount into the contract.
However, for the initiator to redeem the output, their own secret must be
revealed.  For the participant to create their contract, the initiator must
reveal not the secret, but a cryptographic hash of the secret to the
participant.  The participant's contract can also be refunded by the
participant, but only after half the period of time that the initiator is
required to wait before their contract can be refunded (typically 24 hours).

With each side paying into a contract on each blockchain, and each party unable
to perform their refund until the allotted time expires, the initiator redeems
the participant's Decred contract, thereby revealing the secret to the
participant.  The secret is then extracted from the initiator's redeeming Decred
transaction providing the participant with the ability to redeem the initiator's
Bitcoin contract.

This procedure is atomic (with timeout) as it gives each party at least 24 hours
to redeem their coins on the other blockchain before a refund can be performed.

The image below provides a visual of the steps each party performs and the
transfer of data between each party.

<img src="workflow.svg" width="100%" height=650 />

## Command line

Separate command line utilities are provided to handle the transactions required
to perform a cross-chain atomic swap for each supported blockchain.  For a swap
between Bitcoin and Decred, the two utilities `btcatomicswap` and
`dcratomicswap` are used.  Both tools must be used by both parties performing
the swap.

Different tools may require different flags to use them with the supported
wallet.  For example, `btcatomicswap` includes flags for the RPC username and
password while `dcratomicswap` does not.  Running a tool without any parameters
will show the full usage help.

All of the tools support the same six commands.  These commands are:

```
Commands:
  initiate <participant address> <amount>
  participate <initiator address> <amount> <secret hash>
  redeem <contract> <contract transaction> <secret>
  refund <contract> <contract transaction>
  extractsecret <redemption transaction> <secret hash>
  auditcontract <contract> <contract transaction>
```

**`initiate <participant address> <amount>`**

The `initiate` command is performed by the initiator to create the first
contract.  The contract is created with a locktime of 48 hours in the future.
This command returns the secret, the secret hash, the contract script, the
contract transaction, and a refund transaction that can be sent after 48 hours
if necessary.

Running this command will prompt for whether to publish the contract
transaction.  If everything looks correct, the transaction should be published.
The refund transaction should be saved in case a refund is required to be made
later.

For dcratomicswap, this step prompts for the wallet passphrase.  For the
btcatomicswap and ltcatomicswap tools the wallet must already be unlocked.

**`participate <initiator address> <amount> <secret hash>`**

The `participate` command is performed by the participant to create a contract
on the second blockchain.  It operates similarly to `initiate` but requires
using the secret hash from the initiator's contract and creates the contract
with a locktime of 24 hours.

Running this command will prompt for whether to publish the contract
transaction.  If everything looks correct, the transaction should be published.
The refund transaction should be saved in case a refund is required to be made
later.

For dcratomicswap, this step prompts for the wallet passphrase.  For the
btcatomicswap and ltcatomicswap tools the wallet must already be unlocked.

**`redeem <contract> <contract transaction> <secret>`**

The `redeem` command is performed by both parties to redeem coins paid into the
contract created by the other party.  Redeeming requires the secret and must be
performed by the initiator first.  Once the initiator's redemption has been
published, the secret may be extracted from the transaction and the participant
may also redeem their coins.

Running this command will prompt for whether to publish the redemption
transaction. If everything looks correct, the transaction should be published.

For dcratomicswap, this step prompts for the wallet passphrase.  For the
btcatomicswap and ltcatomicswap tools the wallet must already be unlocked.

**`refund <contract> <contract transaction>`**

The `refund` command is used to create and send a refund of a contract
transaction.  While the refund transaction is created and displayed during
contract creation in the initiate and participate steps, the refund can also be
created after the fact in case there was any issue sending the transaction (e.g.
the contract transaction was malleated or the refund fee is now too low).

Running this command will prompt for whether to publish the redemption
transaction. If everything looks correct, the transaction should be published.

**`extractsecret <redemption transaction> <secret hash>`**

The `extractsecret` command is used by the participant to extract the secret
from the initiator's redemption transaction.  With the secret known, the
participant may claim the coins paid into the initiator's contract.

The secret hash is a required parameter so that "nonstandard" redemption
transactions won't confuse the tool and the secret can still be discovered.

**`auditcontract <contract> <contract transaction>`**

The `auditcontract` command inspects a contract script and parses out the
addresses that may claim the output, the locktime, and the secret hash.  It also
validates that the contract transaction pays to the contract and reports the
contract output amount.  Each party should audit the contract provided by the
other to verify that their address is the recipient address, the output value is
correct, and that the locktime is sensible.

## Example

The first step is for both parties to exchange addresses on both blockchains. If
party A (the initiator) wishes to trade Bitcoin for Decred, party B (the
participant) must provide their Bitcoin address and the initiator must provide
the participant their Decred address.

_Party A runs:_
```
$ dcrctl --testnet --wallet getnewaddress
TsfWDVTAcsLaHUhHnLLKkGnZuJz2vkmM6Vr
```

_Party B runs:_
```
$ bitcoin-cli -testnet getnewaddress "comment" "legacy"
n31og5QGuS28dmHpDH6PQD5wmVQ2K2spAG
```

*Note:* It is normal for neither of these addresses to show any activity on
block explorers.  They are only used in nonstandard scripts that the block
explorers do not recognize.

A initiates the process by using `btcatomicswap` to pay 1.0 BTC into the Bitcoin
contract using B's Bitcoin address, sending the contract transaction, and
sharing the secret hash (*not* the secret), contract, and contract transaction
with B.  The refund transaction can not be sent until the locktime expires, but
should be saved in case a refund is necessary.

_Party A runs:_
```
$ ./btcatomicswap --testnet --rpcuser=user --rpcpass=AtomicSwap1234 initiate mkTqX7oLvzxjLFjsfpeRtLkKsyDwsekNDJ 0.0009
warning: falling back to mempool relay fee policy
Secret:      901c0c51c24d129265f25fc7af367a52a7906ce93d8105372c338232a49062fd
Secret hash: 91ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd2

Contract fee: 0.00000166 BTC (0.00000672 BTC/kB)
Refund fee:   0.00000297 BTC (0.00001021 BTC/kB)

Contract (2N6Tn86gmckeQH4caubCoJF7DkGZuX7F8PP):
6382012088a82091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a9143641b9cac269f3f85b7c521f563dfc5eb49228a96704ba1b335db17576a914685ec9625a6084b9a287d7023857534a54e089516888ac

Contract transaction (9e47b18deb57cf0f53fa615d360ded1cd6f28aed560056e6f1771741e01c7db5):
020000000001018e4a97368348a4561c5644a4263232d7c6d251489ea055631a04ab60f00afe7b0000000017160014f4e813007dd822942bc84a593e29ba81fa9b818cfeffffff02905f01000000000017a91490f97392e65b9395a55b574b1b448e155380ea4d876a2600000000000017a91498cf0bc7b56953b3cfb7b3c7270bff8c09247d4c870247304402205d10647e2eff1898d94adbb89a5e0aee15f1e1bea56a047e114ef5b8cb6a8dc202203240bf57659d75bdf5e446b1a71371a4747b3a7ecc532e9cd3a8306a473492a7012102b8a75060633a360d13a17e01e2f3c0e25e8e905806485cdcc097bf58b18bada900000000

Refund transaction (1ae7c98ab417ba0de6cb677533df01ac65bb6389bd6eee4cab3f342a64a3f126):
0200000001b57d1ce0411777f1e6560056ed8af2d61ced0d365d61fa530fcf57eb8db1479e00000000ce473044022023df603da2c1f0a07ca0d54bff7d49bf8aac0145deaa44d3c6e301cff55dd8dc02206270f8df5aaf051b6489e87c86d1b6643ecea5e65e81b5918aa374ea9c6a8e5b012102df0cfe61b1a028cbca0c126477294a07cfde153b5ac89b2b0aba1d0fc584e8f9004c616382012088a82091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a9143641b9cac269f3f85b7c521f563dfc5eb49228a96704ba1b335db17576a914685ec9625a6084b9a287d7023857534a54e089516888ac0000000001675e0100000000001976a9143b76a395ecd840b3903119f52e43521d5013825c88acba1b335d

Publish contract transaction? [y/N] y
Published contract transaction ("9e47b18deb57cf0f53fa615d360ded1cd6f28aed560056e6f1771741e01c7db5")
```

Once A has initialized the swap, B must audit the contract and contract
transaction to verify:

1. The recipient address was the BTC address that was provided to A
2. The contract value is the expected amount of BTC to receive
3. The locktime was set to 48 hours in the future

_Party B runs:_
```
$ ./btcatomicswap --testnet auditcontract 6382012088a82091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a9143641b9cac269f3f85b7c521f563dfc5eb49228a96704ba1b335db17576a914685ec9625a6084b9a287d7023857534a54e089516888ac 020000000001018e4a97368348a4561c5644a4263232d7c6d251489ea055631a04ab60f00afe7b0000000017160014f4e813007dd822942bc84a593e29ba81fa9b818cfeffffff02905f01000000000017a91490f97392e65b9395a55b574b1b448e155380ea4d876a2600000000000017a91498cf0bc7b56953b3cfb7b3c7270bff8c09247d4c870247304402205d10647e2eff1898d94adbb89a5e0aee15f1e1bea56a047e114ef5b8cb6a8dc202203240bf57659d75bdf5e446b1a71371a4747b3a7ecc532e9cd3a8306a473492a7012102b8a75060633a360d13a17e01e2f3c0e25e8e905806485cdcc097bf58b18bada900000000
Contract address:        2N6Tn86gmckeQH4caubCoJF7DkGZuX7F8PP
Contract value:          0.0009 BTC
Recipient address:       mkTqX7oLvzxjLFjsfpeRtLkKsyDwsekNDJ
Author's refund address: mq2p7txzWjjhaSqpcQaQwugCbbEUQk2mbQ

Secret hash: 91ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd2

Locktime: 2019-07-20 13:48:42 +0000 UTC
Locktime reached in 47h54m42s
```

Auditing the contract also reveals the hash of the secret, which is needed for
the next step.

Once B trusts the contract, they may participate in the cross-chain atomic swap
by paying the intended Decred amount (1.0 in this example) into a Decred
contract using the same secret hash.  The contract transaction may be published
at this point.  The refund transaction can not be sent until the locktime
expires, but should be saved in case a refund is necessary.

_Party B runs:_
```
$ ./dcratomicswap --testnet participate Tsjz12Auk15DCXiseXZTwAnk16dPKrfwNKs 0.5 91ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd2
Passphrase: 

Contract fee: 0.0000251 DCR (0.00010080 DCR/kB)
Refund fee:   0.000317 DCR (0.00100635 DCR/kB)

Contract (TctyvA4mDrTUANTKoaCmxu3K5e86RREiCPC):
6382012088c02091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a914d00355ba3824bf8361e4d6e17d9583cc4aef1c07670459cc315db17576a914eb1b8b80600edcaebe186cbcbd028ae77cafd51f6888ac

Contract transaction (5615b8804a5a55c8c2f980b234632ed34c4cacd059fa5049c050106a9ce7c829):
01000000018a0de13d9d1b64e9b90299d60a27cd0b2bfe7d21e699d3d05803a309554bebac0000000000ffffffff023dac532d0200000000001976a914c9cceaa10fb5311db1837d91f731784380fcb40488ac80f0fa0200000000000017a914eb7af990b1a30518bf5001a9cd44f101ab180e7e870000000000000000018ba64e300200000000000000ffffffff6a47304402207a84361dedad66a0183fb18b2b6a20df66aaf8691464ff15e47905e77e759cf102205254e5d7217b58afdd61382cf8cef4a0dfc87b8b567fa349a7a831e5325391cf01210285d70911132d1e59a18944fde6e37462e895d4b52f3cabed1396328292c3ab1c

Refund transaction (a95dbe50f41b492b2051a1bead9f0b577d8ed99bd5ab72d9a3f23847d04bc6e9):
010000000129c8e79c6a1050c04950fa59d0ac4c4cd32e6334b280f9c2c8555a4a80b8155601000000000000000001ac74fa020000000000001976a914363dc8adb0786bf38b10916a56d4c690640c1eac88ac59cc315d0000000001000000000000000000000000ffffffffce4730440220725470675bd54c4a9756c1fc0b6417a91943f0bbea8f9c5286e5cc1153cc2acd02207b12b2714549aef9d35b0b268f1917222f842fd23a0bafa96914b378ac285f1701210389ec97a79b17f6dd48fbd7e7bfe19fb9609b363b0e18b65bcde26e53046478b2004c616382012088c02091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a914d00355ba3824bf8361e4d6e17d9583cc4aef1c07670459cc315db17576a914eb1b8b80600edcaebe186cbcbd028ae77cafd51f6888ac

Publish contract transaction? [y/N] y
Published contract transaction (5615b8804a5a55c8c2f980b234632ed34c4cacd059fa5049c050106a9ce7c829)
```

B now informs A that the Decred contract transaction has been created and
published, and provides the contract details to A.

Just as B needed to audit A's contract before locking their coins in a contract,
A must do the same with B's contract before withdrawing from the contract.  A
audits the contract and contract transaction to verify:

1. The recipient address was the DCR address that was provided to B
2. The contract value is the expected amount of DCR to receive
3. The locktime was set to 24 hours in the future
4. The secret hash matches the value previously known

_Party A runs:_
```
$ ./dcratomicswap --testnet auditcontract 6382012088c02091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a914d00355ba3824bf8361e4d6e17d9583cc4aef1c07670459cc315db17576a914eb1b8b80600edcaebe186cbcbd028ae77cafd51f6888ac 01000000018a0de13d9d1b64e9b90299d60a27cd0b2bfe7d21e699d3d05803a309554bebac0000000000ffffffff023dac532d0200000000001976a914c9cceaa10fb5311db1837d91f731784380fcb40488ac80f0fa0200000000000017a914eb7af990b1a30518bf5001a9cd44f101ab180e7e870000000000000000018ba64e300200000000000000ffffffff6a47304402207a84361dedad66a0183fb18b2b6a20df66aaf8691464ff15e47905e77e759cf102205254e5d7217b58afdd61382cf8cef4a0dfc87b8b567fa349a7a831e5325391cf01210285d70911132d1e59a18944fde6e37462e895d4b52f3cabed1396328292c3ab1c
Contract address:        TctyvA4mDrTUANTKoaCmxu3K5e86RREiCPC
Contract value:          0.5 DCR
Recipient address:       Tsjz12Auk15DCXiseXZTwAnk16dPKrfwNKs
Author's refund address: TsnTGGVg5LoRV3tynLPshrXVNNVXF6mTZHi

Secret hash: 91ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd2

Locktime: 2019-07-19 13:57:45 +0000 UTC
Locktime reached in 23h52m45s
```

Now that both parties have paid into their respective contracts, A may withdraw
from the Decred contract.  This step involves publishing a transaction which
reveals the secret to B, allowing B to withdraw from the Bitcoin contract.

_Party A runs:_
```
$ ./dcratomicswap --testnet redeem 6382012088c02091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a914d00355ba3824bf8361e4d6e17d9583cc4aef1c07670459cc315db17576a914eb1b8b80600edcaebe186cbcbd028ae77cafd51f6888ac 01000000018a0de13d9d1b64e9b90299d60a27cd0b2bfe7d21e699d3d05803a309554bebac0000000000ffffffff023dac532d0200000000001976a914c9cceaa10fb5311db1837d91f731784380fcb40488ac80f0fa0200000000000017a914eb7af990b1a30518bf5001a9cd44f101ab180e7e870000000000000000018ba64e300200000000000000ffffffff6a47304402207a84361dedad66a0183fb18b2b6a20df66aaf8691464ff15e47905e77e759cf102205254e5d7217b58afdd61382cf8cef4a0dfc87b8b567fa349a7a831e5325391cf01210285d70911132d1e59a18944fde6e37462e895d4b52f3cabed1396328292c3ab1c 901c0c51c24d129265f25fc7af367a52a7906ce93d8105372c338232a49062fd
Passphrase: 

Redeem fee: 0.00035 DCR (0.00100575 DCR/kB)

Redeem transaction (e4d8e8a3e00935c44e38d5e839045d1cb6f42593dc8df784014e306c571fd67f):
010000000129c8e79c6a1050c04950fa59d0ac4c4cd32e6334b280f9c2c8555a4a80b815560100000000ffffffff01c867fa020000000000001976a914363dc8adb0786bf38b10916a56d4c690640c1eac88ac59cc315d0000000001000000000000000000000000ffffffffef47304402205781a15053e967653b755cb31b4583ee8fbe23933e28e827a30196b7464c66f7022021287de9db57aaa7c7f800e16c33aae23bc5f9e1f52cc118b4d8207529d3938d0121028e1d1ad6e9bd99cdba8407e7ecde9ce66ff3b1c7dc01814e50f94ac69a9be9c420901c0c51c24d129265f25fc7af367a52a7906ce93d8105372c338232a49062fd514c616382012088c02091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a914d00355ba3824bf8361e4d6e17d9583cc4aef1c07670459cc315db17576a914eb1b8b80600edcaebe186cbcbd028ae77cafd51f6888ac

Publish redeem transaction? [y/N] y
Published redeem transaction (e4d8e8a3e00935c44e38d5e839045d1cb6f42593dc8df784014e306c571fd67f)
```

Now that A has withdrawn from the Decred contract and revealed the secret, B
must extract the secret from this redemption transaction.  B may watch a block
explorer to see when the Decred contract output was spent and look up the
redeeming transaction.

_Party B runs:_
```
$ ./dcratomicswap --testnet extractsecret 010000000129c8e79c6a1050c04950fa59d0ac4c4cd32e6334b280f9c2c8555a4a80b815560100000000ffffffff01c867fa020000000000001976a914363dc8adb0786bf38b10916a56d4c690640c1eac88ac59cc315d0000000001000000000000000000000000ffffffffef47304402205781a15053e967653b755cb31b4583ee8fbe23933e28e827a30196b7464c66f7022021287de9db57aaa7c7f800e16c33aae23bc5f9e1f52cc118b4d8207529d3938d0121028e1d1ad6e9bd99cdba8407e7ecde9ce66ff3b1c7dc01814e50f94ac69a9be9c420901c0c51c24d129265f25fc7af367a52a7906ce93d8105372c338232a49062fd514c616382012088c02091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a914d00355ba3824bf8361e4d6e17d9583cc4aef1c07670459cc315db17576a914eb1b8b80600edcaebe186cbcbd028ae77cafd51f6888ac 91ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd2
Secret: 901c0c51c24d129265f25fc7af367a52a7906ce93d8105372c338232a49062fd
```

With the secret known, B may redeem from A's Bitcoin contract.

_Party B runs:_
```
$ ./btcatomicswap --testnet --rpcuser=user --rpcpass=AtomicSwap1234 redeem 6382012088a82091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a9143641b9cac269f3f85b7c521f563dfc5eb49228a96704ba1b335db17576a914685ec9625a6084b9a287d7023857534a54e089516888ac 020000000001018e4a97368348a4561c5644a4263232d7c6d251489ea055631a04ab60f00afe7b0000000017160014f4e813007dd822942bc84a593e29ba81fa9b818cfeffffff02905f01000000000017a91490f97392e65b9395a55b574b1b448e155380ea4d876a2600000000000017a91498cf0bc7b56953b3cfb7b3c7270bff8c09247d4c870247304402205d10647e2eff1898d94adbb89a5e0aee15f1e1bea56a047e114ef5b8cb6a8dc202203240bf57659d75bdf5e446b1a71371a4747b3a7ecc532e9cd3a8306a473492a7012102b8a75060633a360d13a17e01e2f3c0e25e8e905806485cdcc097bf58b18bada900000000 901c0c51c24d129265f25fc7af367a52a7906ce93d8105372c338232a49062fd
Redeem fee: 0.0000033 BTC (0.00001019 BTC/kB)

Redeem transaction (ba5818e498abacb99dd57493412d69722fe2dfc324af0d9ad1c28c120f4536d5):
0200000001b57d1ce0411777f1e6560056ed8af2d61ced0d365d61fa530fcf57eb8db1479e00000000ef473044022002cba28f2f9803abbbbcbb71790ed3290d999c6845c2f9a391eb0a82ac30483e02202314afc132e2a4847b106a725bd5f5d8e11a6eaedf97ac57b2ad97922fbcb65101210223c6fe322a154ea5246d7c588e42e212ef6c15ad9a2cc204bf9b3fcb97e6026820901c0c51c24d129265f25fc7af367a52a7906ce93d8105372c338232a49062fd514c616382012088a82091ab5f9e63c000fa3a0f761d10267437229631cc3c50ba3861aea3172f8dedd28876a9143641b9cac269f3f85b7c521f563dfc5eb49228a96704ba1b335db17576a914685ec9625a6084b9a287d7023857534a54e089516888acffffffff01465e0100000000001976a914a75882cf5daebe1652665d338d03691cedfede7288acba1b335d

Publish redeem transaction? [y/N] y
Published redeem transaction ("ba5818e498abacb99dd57493412d69722fe2dfc324af0d9ad1c28c120f4536d5")
```

The cross-chain atomic swap is now completed and successful.  This example was
performed on the public Bitcoin and Decred testnet blockchains.  For reference,
here are the four transactions involved:

| Description | Transaction |
| - | - |
| Bitcoin contract created by A | [9e47b18deb57cf0f53fa615d360ded1cd6f28aed560056e6f1771741e01c7db5](https://www.blockstream.info/testnet/tx/9e47b18deb57cf0f53fa615d360ded1cd6f28aed560056e6f1771741e01c7db5) |
| Decred contract created by B | [5615b8804a5a55c8c2f980b234632ed34c4cacd059fa5049c050106a9ce7c829](https://testnet.decred.org/tx/5615b8804a5a55c8c2f980b234632ed34c4cacd059fa5049c050106a9ce7c829) |
| A's Decred redemption | [e4d8e8a3e00935c44e38d5e839045d1cb6f42593dc8df784014e306c571fd67f](https://testnet.decred.org/tx/e4d8e8a3e00935c44e38d5e839045d1cb6f42593dc8df784014e306c571fd67f) |
| B's Bitcoin redemption | [ba5818e498abacb99dd57493412d69722fe2dfc324af0d9ad1c28c120f4536d5](https://www.blockstream.info/testnet/tx/c49e6fd0057b601dbb8856ad7b3fcb45df626696772f6901482b08df0333e5a0) |

If at any point either party attempts to fraud (e.g. creating an invalid
contract, not revealing the secret and refunding, etc.) both parties have the
ability to issue the refund transaction created in the initiate/participate step
and refund the contract.

## Discovering raw transactions

Several steps require working with a raw transaction published by the other
party.  While the transactions can sometimes be looked up from a local node
using the `getrawtransaction` JSON-RPC, this method can be unreliable since the
set of queryable transactions depends on the current UTXO set or may require a
transaction index to be enabled.

Another method of discovering these transactions is to use a public blockchain
explorer.  Not all explorers expose this info through the main user interface so
the API endpoints may need to be used instead.

For Insight-based block explorers, such as the Bitcoin block explorer on
[test-]insight.bitpay.com, the Litecoin block explorer on
{insight,testnet}.litecore.io, and the Decred block explorer on
{mainnet,testnet}.decred.org, the API endpoint `/api/rawtx/<txhash>` can be used
to return a JSON object containing the raw transaction.  For example, here are
links to the four raw transactions published in the example:

| Description | Link to raw transaction |
| - | - |
| Bitcoin contract created by A | https://test-insight.bitpay.com/api/rawtx/9e47b18deb57cf0f53fa615d360ded1cd6f28aed560056e6f1771741e01c7db5 |
| Decred contract created by B | https://testnet.decred.org/api/tx/decoded/5615b8804a5a55c8c2f980b234632ed34c4cacd059fa5049c050106a9ce7c829?indent=true |
| A's Decred redemption | https://testnet.decred.org/api/tx/decoded/e4d8e8a3e00935c44e38d5e839045d1cb6f42593dc8df784014e306c571fd67f?indent=true |
| B's Bitcoin redemption | https://test-insight.bitpay.com/api/rawtx/ba5818e498abacb99dd57493412d69722fe2dfc324af0d9ad1c28c120f4536d5 |

## First mainnet DCR-LTC atomic swap

| Description | Link to raw transaction |
| - | - |
| Decred contract created by A | [fdd72f5841414a9c8b4a188a98a4d484df98f84e1c120e1ed59a66e51e8ae90c](https://mainnet.decred.org/tx/fdd72f5841414a9c8b4a188a98a4d484df98f84e1c120e1ed59a66e51e8ae90c) |
| Litecoin contract created by B | [550d1b2851f6f104e380aa3c2810ac272f8b6918140547c9717a78b1f4ff3469](https://insight.litecore.io/tx/550d1b2851f6f104e380aa3c2810ac272f8b6918140547c9717a78b1f4ff3469) |
| A's Litecoin redemption | [6c27cffab8a86f1b3be1ebe7acfbbbdcb82542c5cfe7880fcca60eab36747037](https://insight.litecore.io/tx/6c27cffab8a86f1b3be1ebe7acfbbbdcb82542c5cfe7880fcca60eab36747037) |
| B's Decred redemption | [49245425967b7e39c1eb27d261c7fe972675cccacff19ae9cc21f434ccddd986](https://mainnet.decred.org/tx/49245425967b7e39c1eb27d261c7fe972675cccacff19ae9cc21f434ccddd986) |
## License

These tools are licensed under the [copyfree](http://copyfree.org) ISC License.
