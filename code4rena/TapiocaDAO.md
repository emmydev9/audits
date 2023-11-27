# Tapioca DAO
The code under review can be found in [2023-07-tapioca](https://github.com/code-423n4/2023-07-tapioca-findings/).

## Findings Summary

| ID | Description | Severity |
| - | - | - |
| [M-01](#m-01-a-malicious-user-could-set-the-allowable-slippage-in-withdrawallmarketfees-to-zero-and-sandwich-all-market-fees) | A malicious user could set the allowable slippage in withdrawAllMarketFees to zero and sandwich all market fees. | Medium |
| [H-01](#h-01-dangerous-delegatecall-to-arbitrary-address)| Dangerous delegatecall to arbitrary address. | High |
| [H-02](#h-02-reentrancy-on-flashloan-allows-bypassing-maxflashloan-limit) | Reentrancy on flashloan allows bypassing maxFlashLoan limit. | High |

## M-01 A malicious user could set the allowable slippage in withdrawAllMarketFees to zero and sandwich all market fees.

## Vulnerability Details
Penrose.withdrawAllMarketFees allows anyone to call the function but the swapData_ passed is not validated.
This is problematic because a malicious user can set the minAssetAmount of swapData_ to zero while sandwiching the swap within the swappers.
We can see that swapData_ is not validated
```solidity
function withdrawAllMarketFees(
        IMarket[] calldata markets_,
        ISwapper[] calldata swappers_,
        IPenrose.SwapData[] calldata swapData_
    ) public notPaused {//@audit swapData is not validated
        require(
            markets_.length == swappers_.length &&
                swappers_.length == swapData_.length,
            "Penrose: length mismatch"
        );
        require(address(swappers_[0]) != address(0), "Penrose: zero address");
        require(address(markets_[0]) != address(0), "Penrose: zero address");

        _withdrawAllProtocolFees(swappers_, swapData_, markets_);

        emit ProtocolWithdrawal(markets_, block.timestamp);
    }
```
## Proof of Concept
but the value set within the calldata is used as a slippage amount in _depositFeesToYieldBox.
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/2286f80f928f41c8bc189d0657d74ba83286c668/contracts/Penrose.sol#L500

```solidity
function _depositFeesToYieldBox(
        IMarket market,
        ISwapper swapper,
        IPenrose.SwapData calldata dexData
    ) private {
        require(swappers[swapper], "Penrose: Invalid swapper");
        require(isMarketRegistered[address(market)], "Penrose: Invalid market");

        uint256 feeShares = market.refreshPenroseFees(feeTo);
        if (feeShares == 0) return;

        uint256 assetId = market.assetId();
        uint256 amount = 0;
        if (assetId != wethAssetId) {
            yieldBox.transfer(
                address(this),
                address(swapper),
                assetId,
                feeShares
            );

            ISwapper.SwapData memory swapData = swapper.buildSwapData(
                assetId,
                wethAssetId,
                0,
                feeShares,
                true,
                true
            );
            (amount, ) = swapper.swap(
                swapData,
                dexData.minAssetAmount,//@audit this slippage value is passed directly from the caller.
                feeTo,
                ""
            );
        } else {
            yieldBox.transfer(address(this), feeTo, assetId, feeShares);
        }

        emit LogYieldBoxFeesDeposit(feeShares, amount);
    }
```
here is the callflow withdrawAllMarketFees -> _withdrawAllProtocolFees -> _depositFeesToYieldBox.
You can see in _depositFeesToYieldBox the dexData.minAssetAmount is the amount passed directly from the call to Penrose.withdrawAllMarketFees. this implies that the caller of this function controls the allowable slippage.
A malicious user could pass zero as the slippage amount and sandwich the swap which results to loss to the protocol since the amountOut from the swap could be zero.

## Recommendation
The easier solution would be to allow only trusted parties to call withdrawAllMarketFees by adding access control to withdrawAllMarketFees.


## H-01 Dangerous delegatecall to arbitrary address.
## vulnerability detail
Delegatecall to arbitrary address could lead destruction or draining of module contracts.

## Proof of Concept

Modules are chuck of code to perform specific task, these contracts splits the protocols functionalities in small parts.
but within these modules delegatecall are made to any arbitrary address passed to the functions, this could be dangerous because it uses delegatecall that preserves the context of the caller.
For Instance,
USDOLeverageModule.leverageUp makes a delegateCall to any address passed as a module argument to the function.
Since this function is public anyone can call this function with a malicious address which implements leverageUpInternal.selector with either a selfdestruct or drains the token held within the module.
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/master/contracts/usd0/modules/USDOLeverageModule.sol#L169
```solidity
function leverageUp(
        address module,//@audit arbitrary address could be passed.
        uint16 _srcChainId,
        bytes memory _srcAddress,
        uint64 _nonce,
        bytes memory _payload
    ) public {
       ...SNIP

        (bool success, bytes memory reason) = module.delegatecall(//@audit dangerous delegateCall!
            abi.encodeWithSelector(
                this.leverageUpInternal.selector,
                amount,
                swapData,
                externalData,
                lzData,
                leverageFor
            )
        );

        ...SNIP
    }
```
modules are essential within the protocol if a module is drained or self-destructed this could lead to complete half of essential components with the protocol.
Within singularity.liquidate we can see the usage of these modules.
```
    function liquidate(
        address[] calldata users,
        uint256[] calldata maxBorrowParts,
        ISwapper swapper,
        bytes calldata collateralToAssetSwapData,
        bytes calldata usdoToBorrowedSwapData
    ) external {
        _executeModule(
            Module.Liquidation,
            abi.encodeWithSelector(
                SGLLiquidation.liquidate.selector,
                users,
                maxBorrowParts,
                swapper,
                collateralToAssetSwapData,
                usdoToBorrowedSwapData
            )
        );
    }
```
this is how _extractModule is implemented within Singularity._extractModule:

```solidity
function _extractModule(Module _module) private view returns (address) {
        address module;
        if (_module == Module.Borrow) {
            module = address(borrowModule);//@audit returns the address of the deployed module contract
        } else if (_module == Module.Collateral) {
            module = address(collateralModule);
        } else if (_module == Module.Liquidation) {
            module = address(liquidationModule);
        } else if (_module == Module.Leverage) {
            module = address(leverageModule);
        }
        if (module == address(0)) {
            revert("SGL: module not set");
        }

        return module;//@audit returns the address of the deployed module contract
    }
```
we can see that singularity also depends on the address of deployed modules to perform its operations if the module contracts are self destructed or drained this creates a huge loss to the overall protocol and could lead to a complete half of the overall protocol.
Other Instances:
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/master/contracts/usd0/modules/USDOMarketModule.sol#L168
https://github.com/Tapioca-DAO/tapioca-bar-audit/blob/master/contracts/usd0/modules/USDOOptionsModule.sol#L174

## Recommendation
Instead of using the address passed to the function, could use address(this).delegatecall instead. or
module address passed to these functions should be validated and checked against module contracts deployed within the appropriate chain.


## [H-02] Reentrancy on flashloan allows bypassing maxFlashLoan limit.
## vulnerability details
Malicious users could have access to more tokens than intended by the protocol.

## Proof of Concept
A malicious user can bypass the maxFlashMint by utilizing reentrancy.
In USDO.flashLoan:
```solidity
function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external override notPaused returns (bool) {//@audit susceptible to reentrancy
        require(token == address(this), "USDO: token not valid");
        require(maxFlashLoan(token) >= amount, "USDO: amount too big");
        require(amount > 0, "USDO: amount not valid");
        uint256 fee = flashFee(token, amount);
        _mint(address(receiver), amount);

        require(
            receiver.onFlashLoan(msg.sender, token, amount, fee, data) ==
                FLASH_MINT_CALLBACK_SUCCESS,
            "USDO: failed"
        );//@audit callback

        uint256 _allowance = allowance(address(receiver), address(this));
        require(_allowance >= (amount + fee), "USDO: repay not approved");
        _approve(address(receiver), address(this), _allowance - (amount + fee));
        _burn(address(receiver), amount + fee);
        return true;
    }
```
A malicious receiver could reenter the callback to mint additional amount of token, the user would only have to burn the tokens at the end of their transaction. This defeats the purpose of maxFlashMint.

## Recommendation
Add nonReentrant modifier from openzepplin to flashloan
