var AtomicSwap = artifacts.require("AtomicSwap");

module.exports = function(deployer) {
  // deployment steps
  deployer.deploy(AtomicSwap);
};