**Atomic Swap Project Architecture**

![Alt text](./AtomicSwapProjectArchitectureZcoin.png?raw=true "Project Structure")

So zxcatomicswap in the decred/atomicswap project references
- zcoinofficial/xzcd
- zcoinofficial/xzcwallet
- zcoinofficial/xzcutil

These are referenced for all associated projects by the dependency tool in the
 decred/atomic swap package
- Gopkg.toml
- Gopkg.lock

TO BUILD & RUN THE TOOLS CLONE THE **github.com/decred/atomicswap** repo, __not__ this one

THE xzcd, xzcutil, xzcwallet code will be 'pulled in' from zcoinofficial

Please also refer to `The main README.md`

devwarrior.sec@gmail.com

