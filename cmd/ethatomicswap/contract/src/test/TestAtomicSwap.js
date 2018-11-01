// Copyright (c) 2018 BetterToken BVBA
// Use of this source code is governed by an MIT
// license that can be found at https://github.com/rivine/rivine/blob/master/LICENSE.

const AtomicSwap = artifacts.require("AtomicSwap");

contract("AtomicSwap tests", accounts => {
    let tryCatch = require("./exceptions.js").tryCatch;
    let errTypes = require("./exceptions.js").errTypes;
    let utils = require("./utils.js");

    // Solidity Enums aren't exported,
    // a manual integer mapping is therefore required
    const [kindInitiator, kindParticipant] = [0, 1];
    const [stateEmpty, stateFilled, stateRedeemed, stateRefunded] = [0, 1, 2, 3];

    // contractAccount is used only to deploy the contracts,
    // firstAccount and secondAccount are used for valid and invalid transfers,
    // and thridAccount and fourthAccount are used only for invalid transfers
    const [contractAccount, firstAccount, secondAccount, thirdAccount, fourthAccount] = accounts;

    // atomicSwap gets assigned, before each unit test,
    // the instance of a newly deployed AtomicSwap smart contract
    let atomicSwap;  

    // define constant hash+secretHash
    const secret = "0x64f1ddd4cc83a3aaf37a7f290ec922dc764de023acdd11bf76c24378b086a017";
    const secretHash = "0xd4ebb2bf3e7898c18f6fe07d8eb8e7084e0bae52ae44a42ca6cdba240f58549f";
    // wrong hash+secretHash
    const wrongSecretHash = "0xe3b25a963d024e7788d97ae1030bdb279731edb190f25d4aa5d38c400e08634e";
    const wrongSecret = "0x686f661e0c2f7678d2751db8662cc56cb9b6a7bdfd0524f0a841006c244cfc37";
    // empty secret
    const emptySecret = "0x0000000000000000000000000000000000000000000000000000000000000000";

    beforeEach(async () => {
        atomicSwap = await AtomicSwap.new();

        console.log("balance of accounts before test:")
        console.log("  * balance of account #1: " + web3.eth.getBalance(firstAccount).toString());
        console.log("  * balance of account #2: " + web3.eth.getBalance(secondAccount).toString());
        console.log("  * balance of account #3: " + web3.eth.getBalance(thirdAccount).toString());
        console.log("  * balance of account #4: " + web3.eth.getBalance(fourthAccount).toString());
    });

    afterEach(async () => {
        console.log("balance of accounts after test:")
        console.log("  * balance of account #1: " + web3.eth.getBalance(firstAccount).toString());
        console.log("  * balance of account #2: " + web3.eth.getBalance(secondAccount).toString());
        console.log("  * balance of account #3: " + web3.eth.getBalance(thirdAccount).toString());
        console.log("  * balance of account #4: " + web3.eth.getBalance(fourthAccount).toString());
    });

    it("should be able to redeem a participation contract", async () => {
        const contractAmount = web3.toBigNumber(web3.toWei('0.01', 'ether'));
        const refundTime = 60;
        
        let initTimestamp;

        // store initial balance of our accounts,
        // so that we can check if the locked value
        // transfers indeed between accounts 
        let balanceFirstAccount = web3.eth.getBalance(firstAccount);
        let balanceSecondAccount = web3.eth.getBalance(secondAccount);
        let expectedBalanceFirstAccount = balanceFirstAccount;
        let expectedBalanceSecondAccount = balanceSecondAccount;

        // ensure our contract does not exist yet
        var [,,,,,,,,contractState] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractState, stateEmpty, "state should equal Empty");

        // sanity balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // create participation contract
        await atomicSwap.participate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Participated", "Expected Participated event");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "Value should equal contractAmount");
                assert.equal(firstLog.args.secretHash, secretHash, "SecretHash should be as expected");
                assert.equal(firstLog.args.refundTime, refundTime, "RefundTime should be as expected");
                assert.equal(firstLog.args.initiator, secondAccount, "Initiator should equal secondAccount");
                assert.equal(firstLog.args.participant, firstAccount, "Participant should equal firstAccount");
                initTimestamp = firstLog.args.initTimestamp.toNumber();
            });
        
        // update balance and check it again
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount.negated());
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");
        
        // assert all contract details
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, emptySecret, "secret should still be nil");
        assert.equal(contractInitiator, secondAccount, "initiator should equal secondAccount");
        assert.equal(contractParticipant, firstAccount, "participant should equal firstAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindParticipant, "kind should equal Participant");
        assert.equal(contractState, stateFilled, "state should equal Filled");
        
        // creating another contract using the same secretHash should fail
        await tryCatch(atomicSwap.participate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}), errTypes.revert);
        // even when using different accounts
        await tryCatch(atomicSwap.participate(refundTime, secretHash, fourthAccount,
            {from: thirdAccount, value: contractAmount, gasPrice: 0}), errTypes.revert);
        // and even when trying to create an initiation contract, instead of an participation contract
        await tryCatch(atomicSwap.initiate(refundTime, secretHash, fourthAccount,
            {from: thirdAccount, value: contractAmount, gasPrice: 0}), errTypes.revert);
        
        // only the initiator can refund a contract
        await tryCatch(atomicSwap.refund(secretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: thirdAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: fourthAccount, gasPrice: 0}), errTypes.revert);

        // but even the initiator cannot refund, given the refundTime has not yet been reached
        await tryCatch(atomicSwap.refund(secretHash,
            {from: firstAccount, gasPrice: 0}), errTypes.revert);

        // only the the participant can redeem a contract
        await tryCatch(atomicSwap.redeem(secret, secretHash,
            {from: firstAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.redeem(secret, secretHash,
            {from: thirdAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.redeem(secret, secretHash,
            {from: fourthAccount, gasPrice: 0}), errTypes.revert);

        // the participant has to give however give the correct secret hash
        await tryCatch(atomicSwap.redeem(secret, wrongSecretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        // and the correct secret
        await tryCatch(atomicSwap.redeem(wrongSecret, secretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        // in fact, the secretHash has to be the correct one and the secretHash has to equal sha256(secret)
        await tryCatch(atomicSwap.redeem(wrongSecret, wrongSecretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);

        // redeem the participation contract as the the participant
        await atomicSwap.redeem(secret, secretHash, {from: secondAccount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Redeemed", "Expected Redeemed event");
                assert.isAtLeast(firstLog.args.redeemTime.toNumber(), initTimestamp,
                    "redeem time " + firstLog.args.redeemTime +
                    " should be atleast equal to the init timestamp " +
                    initTimestamp.toString());
                assert.equal(firstLog.args.secretHash, secretHash, "secretHash should be as expected");
                assert.equal(firstLog.args.secret, secret, "secret should be as expected");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "value should equal contractAmount");
                assert.equal(firstLog.args.redeemer, secondAccount, "redeemer should equal secondAccount");
            });
        
        // ensure balance updates of second account
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        expectedBalanceSecondAccount = expectedBalanceSecondAccount.add(contractAmount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should have decreased by txn cost, " +
            "and should have received contract amount");

        // assert state has now been updated,
        // and that our contract still exists
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, secret, "secret should no longer be nil and instead be as expected");
        assert.equal(contractInitiator, secondAccount, "initiator should equal secondAccount");
        assert.equal(contractParticipant, firstAccount, "participant should equal firstAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindParticipant, "kind should equal Participant");
        assert.equal(contractState, stateRedeemed, "state should equal Redeemed");

        // last balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");
    });

    it("should be able to redeem a participation contract even when refunding is already possible", async () => {
        const contractAmount = web3.toBigNumber(web3.toWei('0.01', 'ether'));
        const refundTime = 1;
        
        let initTimestamp;

        // store initial balance of our accounts,
        // so that we can check if the locked value
        // transfers indeed between accounts 
        let balanceFirstAccount = web3.eth.getBalance(firstAccount);
        let balanceSecondAccount = web3.eth.getBalance(secondAccount);
        let expectedBalanceFirstAccount = balanceFirstAccount;
        let expectedBalanceSecondAccount = balanceSecondAccount;

        // ensure our contract does not exist yet
        var [,,,,,,,,contractState] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractState, stateEmpty, "state should equal Empty");

        // sanity balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // create participation contract
        await atomicSwap.participate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Participated", "Expected Participated event");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "Value should equal contractAmount");
                assert.equal(firstLog.args.secretHash, secretHash, "SecretHash should be as expected");
                assert.equal(firstLog.args.refundTime, refundTime, "RefundTime should be as expected");
                assert.equal(firstLog.args.initiator, secondAccount, "Initiator should equal secondAccount");
                assert.equal(firstLog.args.participant, firstAccount, "Participant should equal firstAccount");
                initTimestamp = firstLog.args.initTimestamp.toNumber();
            });
        
        // update balance and check it again
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount.negated());
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // sleep so that the refund-period gets reached
        await utils.sleep(refundTime * 2000);

        // redeem the participation contract as the the participant
        await atomicSwap.redeem(secret, secretHash, {from: secondAccount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Redeemed", "Expected Redeemed event");
                assert.isAtLeast(firstLog.args.redeemTime.toNumber(), initTimestamp,
                    "redeem time " + firstLog.args.redeemTime +
                    " should be atleast equal to the init timestamp " +
                    initTimestamp.toString());
                assert.equal(firstLog.args.secretHash, secretHash, "secretHash should be as expected");
                assert.equal(firstLog.args.secret, secret, "secret should be as expected");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "value should equal contractAmount");
                assert.equal(firstLog.args.redeemer, secondAccount, "redeemer should equal secondAccount");
            });
        
        // ensure balance updates of second account
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        expectedBalanceSecondAccount = expectedBalanceSecondAccount.add(contractAmount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should have decreased by txn cost, " +
            "and should have received contract amount");

        // assert state and that our contract still exists
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, secret, "secret should no longer be nil and instead be as expected");
        assert.equal(contractInitiator, secondAccount, "initiator should equal secondAccount");
        assert.equal(contractParticipant, firstAccount, "participant should equal firstAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindParticipant, "kind should equal Participant");
        assert.equal(contractState, stateRedeemed, "state should equal Redeemed");

        // last balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");
    });

    it("should be able to redeem an initiation contract", async () => {
        const contractAmount = web3.toBigNumber(web3.toWei('0.01', 'ether'));
        const refundTime = 60;

        let initTimestamp;

        // store initial balance of our accounts,
        // so that we can check if the locked value
        // transfers indeed between accounts 
        let balanceFirstAccount = web3.eth.getBalance(firstAccount);
        let balanceSecondAccount = web3.eth.getBalance(secondAccount);
        let expectedBalanceFirstAccount = balanceFirstAccount;
        let expectedBalanceSecondAccount = balanceSecondAccount;

        // ensure our contract does not exist yet
        var [,,,,,,,,contractState] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractState, stateEmpty, "state should equal Empty");

        // sanity balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // create initiation contract
        await atomicSwap.initiate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Initiated", "Expected Initiated event");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "Value should equal contractAmount");
                assert.equal(firstLog.args.secretHash, secretHash, "SecretHash should be as expected");
                assert.equal(firstLog.args.refundTime, refundTime, "RefundTime should be as expected");
                assert.equal(firstLog.args.participant, secondAccount, "Participant should equal secondAccount");
                assert.equal(firstLog.args.initiator, firstAccount, "Initiator should equal firstAccount");
                initTimestamp = firstLog.args.initTimestamp.toNumber();
            });

        // update balance and check it again
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount.negated());
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // assert all contract details
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, emptySecret, "secret should still be nil");
        assert.equal(contractInitiator, firstAccount, "initiator should equal firstAccount");
        assert.equal(contractParticipant, secondAccount, "participant should equal secondAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindInitiator, "kind should equal Initiator");
        assert.equal(contractState, stateFilled, "state should equal Filled");
        
        // creating another contract using the same secretHash should fail
        await tryCatch(atomicSwap.initiate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}), errTypes.revert);
        // even when using different accounts
        await tryCatch(atomicSwap.initiate(refundTime, secretHash, fourthAccount,
            {from: thirdAccount, value: contractAmount, gasPrice: 0}), errTypes.revert);
        // and even when trying to create a participation contract, instead of an initiation contract
        await tryCatch(atomicSwap.participate(refundTime, secretHash, fourthAccount,
            {from: thirdAccount, value: contractAmount, gasPrice: 0}), errTypes.revert);
        
        // only the participant can refund a contract
        await tryCatch(atomicSwap.refund(secretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: thirdAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: fourthAccount, gasPrice: 0}), errTypes.revert);

        // but even the participant cannot refund, given the refundTime has not yet been reached
        await tryCatch(atomicSwap.refund(secretHash,
            {from: firstAccount, gasPrice: 0}), errTypes.revert);

        // only the the initiator can redeem a contract
        await tryCatch(atomicSwap.redeem(secret, secretHash,
            {from: firstAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.redeem(secret, secretHash,
            {from: thirdAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.redeem(secret, secretHash,
            {from: fourthAccount, gasPrice: 0}), errTypes.revert);

        // the initiator has to give however give the correct secret hash
        await tryCatch(atomicSwap.redeem(secret, wrongSecretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        // and the correct secret
        await tryCatch(atomicSwap.redeem(wrongSecret, secretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        // in fact, the secretHash has to be the correct one and the secretHash has to equal sha256(secret)
        await tryCatch(atomicSwap.redeem(wrongSecret, wrongSecretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        
        // redeem the initiation contract
        await atomicSwap.redeem(secret, secretHash, {from: secondAccount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Redeemed", "Expected Redeemed event");
                assert.isAtLeast(firstLog.args.redeemTime.toNumber(), initTimestamp,
                    "redeem time " + firstLog.args.redeemTime +
                    " should be atleast equal to the init timestamp " +
                    initTimestamp.toString());
                assert.equal(firstLog.args.secretHash, secretHash, "secretHash should be as expected");
                assert.equal(firstLog.args.secret, secret, "secret should be as expected");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "value should equal contractAmount");
                assert.equal(firstLog.args.redeemer, secondAccount, "redeemer should equal secondAccount");
            });

        // ensure balance updates of second account
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        expectedBalanceSecondAccount = expectedBalanceSecondAccount.add(contractAmount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should have decreased by txn cost, " +
            "and should have received contract amount");

        // assert state has now been updated,
        // and that our contract still exists
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, secret, "secret should no longer be nil and instead be as expected");
        assert.equal(contractInitiator, firstAccount, "initiator should equal firstAccount");
        assert.equal(contractParticipant, secondAccount, "participant should equal secondAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindInitiator, "kind should equal Initiator");
        assert.equal(contractState, stateRedeemed, "state should equal Redeemed");

        // last balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");
    });

    it("should be able to redeem an initiation contract even when refunding is already possible", async () => {
        const contractAmount = web3.toBigNumber(web3.toWei('0.01', 'ether'));
        const refundTime = 1;

        let initTimestamp;

        // store initial balance of our accounts,
        // so that we can check if the locked value
        // transfers indeed between accounts 
        let balanceFirstAccount = web3.eth.getBalance(firstAccount);
        let balanceSecondAccount = web3.eth.getBalance(secondAccount);
        let expectedBalanceFirstAccount = balanceFirstAccount;
        let expectedBalanceSecondAccount = balanceSecondAccount;

        // ensure our contract does not exist yet
        var [,,,,,,,,contractState] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractState, stateEmpty, "state should equal Empty");

        // sanity balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // create initiation contract
        await atomicSwap.initiate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Initiated", "Expected Initiated event");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "Value should equal contractAmount");
                assert.equal(firstLog.args.secretHash, secretHash, "SecretHash should be as expected");
                assert.equal(firstLog.args.refundTime, refundTime, "RefundTime should be as expected");
                assert.equal(firstLog.args.participant, secondAccount, "Participant should equal secondAccount");
                assert.equal(firstLog.args.initiator, firstAccount, "Initiator should equal firstAccount");
                initTimestamp = firstLog.args.initTimestamp.toNumber();
            });

        // update balance and check it again
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount.negated());
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // sleep so that the refund-period gets reached
        await utils.sleep(refundTime * 2000);
        
        // redeem the initiation contract
        await atomicSwap.redeem(secret, secretHash, {from: secondAccount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Redeemed", "Expected Redeemed event");
                assert.isAtLeast(firstLog.args.redeemTime.toNumber(), initTimestamp,
                    "redeem time " + firstLog.args.redeemTime +
                    " should be atleast equal to the init timestamp " +
                    initTimestamp.toString());
                assert.equal(firstLog.args.secretHash, secretHash, "secretHash should be as expected");
                assert.equal(firstLog.args.secret, secret, "secret should be as expected");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "value should equal contractAmount");
                assert.equal(firstLog.args.redeemer, secondAccount, "redeemer should equal secondAccount");
            });

        // ensure balance updates of second account
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        expectedBalanceSecondAccount = expectedBalanceSecondAccount.add(contractAmount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should have decreased by txn cost, " +
            "and should have received contract amount");

        // assert state and that our contract still exists
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, secret, "secret should no longer be nil and instead be as expected");
        assert.equal(contractInitiator, firstAccount, "initiator should equal firstAccount");
        assert.equal(contractParticipant, secondAccount, "participant should equal secondAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindInitiator, "kind should equal Initiator");
        assert.equal(contractState, stateRedeemed, "state should equal Redeemed");

        // last balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");
    });

    it("should be able to refund a participation contract", async () => {
        const contractAmount = web3.toBigNumber(web3.toWei('0.01', 'ether'));
        const refundTime = 1;
        
        let initTimestamp;

        // store initial balance of our accounts,
        // so that we can check if the locked value
        // transfers indeed between accounts 
        let balanceFirstAccount = web3.eth.getBalance(firstAccount);
        let balanceSecondAccount = web3.eth.getBalance(secondAccount);
        let expectedBalanceFirstAccount = balanceFirstAccount;
        let expectedBalanceSecondAccount = balanceSecondAccount;

        // ensure our contract does not exist yet
        var [,,,,,,,,contractState] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractState, stateEmpty, "state should equal Empty");

        // sanity balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // create participation contract
        await atomicSwap.participate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Participated", "Expected Participated event");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "Value should equal contractAmount");
                assert.equal(firstLog.args.secretHash, secretHash, "SecretHash should be as expected");
                assert.equal(firstLog.args.refundTime, refundTime, "RefundTime should be as expected");
                assert.equal(firstLog.args.initiator, secondAccount, "Initiator should equal secondAccount");
                assert.equal(firstLog.args.participant, firstAccount, "Participant should equal firstAccount");
                initTimestamp = firstLog.args.initTimestamp.toNumber();
            });

        // update balance and check it again
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount.negated());
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // assert all contract details
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, emptySecret, "secret should still be nil");
        assert.equal(contractInitiator, secondAccount, "initiator should equal secondAccount");
        assert.equal(contractParticipant, firstAccount, "participant should equal firstAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindParticipant, "kind should equal Participant");
        assert.equal(contractState, stateFilled, "state should equal Filled");
        
        await utils.sleep(refundTime * 2000);
        
        // only the participant can refund a contract
        await tryCatch(atomicSwap.refund(secretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: thirdAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: fourthAccount, gasPrice: 0}), errTypes.revert);
    
        atomicSwap.refund(secretHash, {from: firstAccount, gasPrice: 0}).then(result => {
            const firstLog = result.logs[0];
            assert.equal(firstLog.event, "Refunded", "Expected Refunded event");
            assert.isAtLeast(firstLog.args.refundTime.toNumber(), initTimestamp,
                "refund time " + firstLog.args.refundTime +
                " should be atleast equal to the init timestamp " +
                initTimestamp.toString());
                assert.equal(firstLog.args.secretHash, secretHash, "secretHash should be as expected");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "value should equal contractAmount");
                assert.equal(firstLog.args.refunder, firstAccount, "refunder should equal firstAccount");
        });

        await utils.sleep(1000); // refund balance updates seem to take longer for some reason

        // ensure balance updates of first account
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should have decreased by txn cost, " +
            "and should have received contract amount back");

        // assert state has now been updated,
        // and that our contract still exists
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, emptySecret, "secret should still be nil");
        assert.equal(contractInitiator, secondAccount, "initiator should equal secondAccount");
        assert.equal(contractParticipant, firstAccount, "participant should equal firstAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindParticipant, "kind should equal Participant");
        assert.equal(contractState, stateRefunded, "state should equal Refunded");

        // last balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");
    });

    it("should be able to refund an initiation contract", async () => {
        const contractAmount = web3.toBigNumber(web3.toWei('0.01', 'ether'));
        const refundTime = 1;
        
        let initTimestamp;

        // store initial balance of our accounts,
        // so that we can check if the locked value
        // transfers indeed between accounts 
        let balanceFirstAccount = web3.eth.getBalance(firstAccount);
        let balanceSecondAccount = web3.eth.getBalance(secondAccount);
        let expectedBalanceFirstAccount = balanceFirstAccount;
        let expectedBalanceSecondAccount = balanceSecondAccount;

        // ensure our contract does not exist yet
        var [,,,,,,,,contractState] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractState, stateEmpty, "state should equal Empty");

        // sanity balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

        // create initiation contract
        await atomicSwap.initiate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}).
            then(result => {
                const firstLog = result.logs[0];
                assert.equal(firstLog.event, "Initiated", "Expected Initiated event");
                assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "Value should equal contractAmount");
                assert.equal(firstLog.args.secretHash, secretHash, "SecretHash should be as expected");
                assert.equal(firstLog.args.refundTime, refundTime, "RefundTime should be as expected");
                assert.equal(firstLog.args.initiator, firstAccount, "Initiator should equal secondAccount");
                assert.equal(firstLog.args.participant, secondAccount, "Participant should equal firstAccount");
                initTimestamp = firstLog.args.initTimestamp.toNumber();
            });
        
        // update balance and check it again
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount.negated());
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");

       // assert all contract details
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, emptySecret, "secret should still be nil");
        assert.equal(contractInitiator, firstAccount, "initiator should equal firstAccount");
        assert.equal(contractParticipant, secondAccount, "participant should equal secondAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindInitiator, "kind should equal Initiator");
        assert.equal(contractState, stateFilled, "state should equal Filled");
        
        await utils.sleep(refundTime * 2000);
        
        // only the initiator can refund a contract
        await tryCatch(atomicSwap.refund(secretHash,
            {from: secondAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: thirdAccount, gasPrice: 0}), errTypes.revert);
        await tryCatch(atomicSwap.refund(secretHash,
            {from: fourthAccount, gasPrice: 0}), errTypes.revert);
        atomicSwap.refund(secretHash, {from: firstAccount, gasPrice: 0}).then(result => {
            const firstLog = result.logs[0];
            assert.equal(firstLog.event, "Refunded", "Expected Refunded event");
            assert.isAtLeast(firstLog.args.refundTime.toNumber(), initTimestamp,
                "refund time " + firstLog.args.refundTime +
                " should be atleast equal to the init timestamp " +
                initTimestamp.toString());
            assert.equal(firstLog.args.secretHash, secretHash, "secretHash should be as expected");
            assert.equal(firstLog.args.value.toString(), contractAmount.toString(), "value should equal contractAmount");
            assert.equal(firstLog.args.refunder, firstAccount, "refunder should equal firstAccount");
        });

        await utils.sleep(1000); // refund balance updates seem to take longer for some reason

        // ensure balance updates of first account
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        expectedBalanceFirstAccount = expectedBalanceFirstAccount.add(contractAmount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should have decreased by txn cost, " +
            "and should have received contract amount back");

        // assert state has now been updated,
        // and that our contract still exists
        var [
            contractTime,
            contractRefundTime,
            contractSecretHash,
            contractSecret,
            contractInitiator,
            contractParticipant,
            contractValue,
            contractKind,
            contractState,
        ] = await atomicSwap.swaps(secretHash, {gasPrice: 0});
        assert.equal(contractSecretHash, secretHash, "secretHash should be as expected");
        assert.equal(contractSecret, emptySecret, "secret should still be nil");
        assert.equal(contractInitiator, firstAccount, "initiator should equal firstAccount");
        assert.equal(contractParticipant, secondAccount, "participant should equal secondAccount");
        assert.equal(contractValue.toString(), contractAmount.toString(), "value should equal contractAmount");
        assert.equal(contractKind, kindInitiator, "kind should equal Initiator");
        assert.equal(contractState, stateRefunded, "state should equal Refunded");

        // last balance check
        balanceFirstAccount = web3.eth.getBalance(firstAccount);
        assert.equal(balanceFirstAccount.toString(), expectedBalanceFirstAccount.toString(),
            "balance of first account should be as expected");
        balanceSecondAccount = web3.eth.getBalance(secondAccount);
        assert.equal(balanceSecondAccount.toString(), expectedBalanceSecondAccount.toString(),
            "balance of second account should be as expected");
    });

    it("shouldn't be possible to create a contract with no value", async () => {
        const refundTime = 60;

        await tryCatch(atomicSwap.participate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: 0, gasPrice: 0}), errTypes.revert)
        await tryCatch(atomicSwap.initiate(refundTime, secretHash, secondAccount,
            {from: firstAccount, value: 0, gasPrice: 0}), errTypes.revert)
    });

    it("shouldn't be possible to create a contract with no refundTime", async () => {
        const contractAmount = web3.toBigNumber(web3.toWei('0.01', 'ether'));

        await tryCatch(atomicSwap.participate(0, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}), errTypes.revert)
        await tryCatch(atomicSwap.initiate(0, secretHash, secondAccount,
            {from: firstAccount, value: contractAmount, gasPrice: 0}), errTypes.revert)
    });
});
