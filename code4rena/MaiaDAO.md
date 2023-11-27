# Maia DAO

The code under review can be found in [2023-05-maia](https://github.com/code-423n4/2023-05-maia).

## Findings Summary

| ID | Description | Severity |
| - | - | - |
| [H-01](#h-01-removeBribeFlywheel-does-not-remove-assets-from-MultiRewardsDepot) | removeBribeFlywheel does not remove assets from MultiRewardsDepot | High |
| [H-02](#h-02-_normalizeDecimals-and-_denormalizeDecimals-implementation-are-wrongly-interchanged) | _normalizeDecimals and _denormalizeDecimals implementation are wrongly interchanged | High |
| [H-03](#h-03-precision-differences-when-performing-calculations-can-cause-major-issues-in-Ulysses-Omnichain) | Precision differences when performing calculations can cause major issues in Ulysses Omnichain | High |
| [H-04](#h-04-accumulatedFees-should-be-unwrapped-before-sweeping) | accumulatedFees should be unwrapped before sweeping. | High |

## H-01 removeBribeFlywheel does not remove assets from MultiRewardsDepot

## Vulnerability details
Flywheel could be gamed to still accrue rewards on the subsequent epochs even when removed or inactive.

## Proof of Concept
In BaseV2Gauge.sol#addBribeFlywheel when adding bribeflywheel the function calls multiRewardsDepot.addAsset(flyWheelRewards, bribeFlywheel.rewardToken())
https://github.com/code-423n4/2023-05-maia/blob/main/src/gauges/BaseV2Gauge.sol#L128
```solidity
function addBribeFlywheel(FlywheelCore bribeFlywheel) external onlyOwner {
        /// @dev Can't add existing flywheel (active or not)
        if (added[bribeFlywheel]) revert FlywheelAlreadyAdded();

        address flyWheelRewards = address(bribeFlywheel.flywheelRewards());
        FlywheelBribeRewards(flyWheelRewards).setRewardsDepot(multiRewardsDepot);

        multiRewardsDepot.addAsset(flyWheelRewards, bribeFlywheel.rewardToken());//@audit <= added here
        bribeFlywheels.push(bribeFlywheel);
        isActive[bribeFlywheel] = true;
        added[bribeFlywheel] = true;

        emit AddedBribeFlywheel(bribeFlywheel);
    }
```
This adds the bribeFlywheel as a rewardContract in MultiRewardsDepot to enable the flywheel accrue rewards from the depot
https://github.com/code-423n4/2023-05-maia/blob/main/src/rewards/depots/MultiRewardsDepot.sol#L47
```solidity
function addAsset(address rewardsContract, address asset) external onlyOwner {
        if (_isAsset[asset] || _isRewardsContract[rewardsContract]) revert ErrorAddingAsset();
        _isAsset[asset] = true;
        _isRewardsContract[rewardsContract] = true;
        _assets[rewardsContract] = asset;

        emit AssetAdded(rewardsContract, asset);
    }
```
but when removing bribeflywheel the removeBribeFlywheel function does not call MultiRewardsDepot.sol#removeAsset this allows users to call accrue from the flywheel with the strategy and accrue rewards even when the flywheel is removed in subsequent epochs.
https://github.com/code-423n4/2023-05-maia/blob/main/src/rewards/depots/MultiRewardsDepot.sol#L57
```solidity
function removeAsset(address rewardsContract) external onlyOwner {
        if (!_isRewardsContract[rewardsContract]) revert ErrorRemovingAsset();

        emit AssetRemoved(rewardsContract, _assets[rewardsContract]);

        delete _isAsset[_assets[rewardsContract]];
        delete _isRewardsContract[rewardsContract];
        delete _assets[rewardsContract];
    }
```
https://github.com/code-423n4/2023-05-maia/blob/main/src/gauges/BaseV2Gauge.sol#L144
```solidity
function removeBribeFlywheel(FlywheelCore bribeFlywheel) external onlyOwner {//@audit <== not removed here
        /// @dev Can only remove active flywheels
        if (!isActive[bribeFlywheel]) revert FlywheelNotActive();

        /// @dev This is permanent; can't be re-added
        delete isActive[bribeFlywheel];

        emit RemoveBribeFlywheel(bribeFlywheel);
    }
```
## Recommendation
Add multiRewardsDepot.removeAsset(flyWheelRewards) to BaseV2Gauge.sol#removeBribeFlywheel and set BaseV2Gauge.sol#removeBribeFlywheel behind a timelock before the next epoch to allow users who haven't claimed to claim before removal.

## H-02 _normalizeDecimals and _denormalizeDecimals implementation are wrongly interchanged

## Vulnerability details
This creates discrepancies within contracts using these functions which could lead to lost of funds to users or the protocol.

## Proof of Concept
denormalizeDecimals is meant to denormalizes an input from 18 decimal places to it's native decimals but it's implementation wrongly does the opposite.
https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/BranchPort.sol#L388
```solidity
/**
     * @notice Internal function that denormalizes an input from 18 decimal places.
     * @param _amount amount of tokens
     * @param _decimals number of decimal places
     */
    function _denormalizeDecimals(uint256 _amount, uint8 _decimals) internal pure returns (uint256) {
        return _decimals == 18 ? _amount : _amount * 1 ether / (10 ** _decimals);
    }
```
while normalizeDecimals is meant to normalizes an input to 18 decimal places but it's implementation does the opposite.
https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/BranchBridgeAgent.sol#L1340
```solidity
/**
     * @notice Internal function that normalizes an input to 18 decimal places.
     * @param _amount amount of tokens
     * @param _decimals number of decimal places
     */
    function _normalizeDecimals(uint256 _amount, uint8 _decimals) internal pure returns (uint256) {
        return _decimals == 18 ? _amount : _amount * (10 ** _decimals) / 1 ether;
    }
```

This creates discrepancies within contracts using these functions which could lead to lost of funds to users or the protocol.
for instance _denormalizeDecimals is used in BranchPort.sol to bridge out funds.
```solidity
function bridgeOut(
        address _depositor,
        address _localAddress,
        address _underlyingAddress,
        uint256 _amount,
        uint256 _deposit
    ) external virtual requiresBridgeAgent {
        if (_amount - _deposit > 0) {
            _localAddress.safeTransferFrom(_depositor, address(this), _amount - _deposit);
            ERC20hTokenBranch(_localAddress).burn(_amount - _deposit);
        }
        if (_deposit > 0) {
            _underlyingAddress.safeTransferFrom(
                _depositor, address(this), _denormalizeDecimals(_deposit, ERC20(_underlyingAddress).decimals())//@audit
            );
        }
    }
```
but instead of _denormalizing the decimal to the underlying assets decimal it rather normalizes it to 18 decimals which implies that if the underlying asset decimal is less than 18 it would be overstated and more tokens would be bridge out to the user than intended.

## Recommendation
Correct the implementation of `_denormalizeDecimals` and `normalizeDecimals` by swapping both implementation.

## H-03 Precision differences when performing calculations can cause major issues in Ulysses Omnichain

## Vulnerability details
Precision differences when performing calculations can cause major issues in Ulysses Omnichain.

## Proof of Concept
From the contest description:

> Ulysses AMM (Ulysses Pools and Ulysses Tokens) only supports tokens with 18 decimals, but Ulysses Omnichain accounting supports tokens with any decimals and converts them to 18 decimals.

But some instances in Ulysses Omnichain fails to convert/normalize such tokens.
Within Ulysses Omnichain calculations are done with tokens which might have different precision/decimals, this could lead to issues like transferring fewer or more tokens to users or reverts in some cases.
for instances:
https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/RootBridgeAgent.sol#L442
```solidity
function _updateStateOnBridgeOut(
        address _sender,
        address _globalAddress,
        address _localAddress,
        address _underlyingAddress,
        uint256 _amount,
        uint256 _deposit,
        uint24 _toChain
    ) internal {
        if (_amount - _deposit > 0) {//@audit _deposit should be normalized first
            //Move output hTokens from Root to Branch
            if (_localAddress == address(0)) revert UnrecognizedLocalAddress();
            _globalAddress.safeTransferFrom(_sender, localPortAddress, _amount - _deposit);//@audit _deposit should be normalized 
        }

        if (_deposit > 0) {
            //Verify there is enough balance to clear native tokens if needed
            if (_underlyingAddress == address(0)) revert UnrecognizedUnderlyingAddress();
            if (IERC20hTokenRoot(_globalAddress).getTokenBalance(_toChain) < _deposit) {//@audit should be normalized first
                revert InsufficientBalanceForSettlement();
            }
            IPort(localPortAddress).burn(_sender, _globalAddress, _deposit, _toChain);
        }
    }
```
This function takes two value input amount and _deposit from the Natspec comment amount is from the htoken which is known to be 18 decimals but _deposit can be any underlying token with different precision, these difference could cause multiple issues within these contracts.

## Recommendation
Precision of both token should be consistent before performing operations on them.
normalize the _deposit parameter before usage.

## H-04 accumulatedFees should be unwrapped before sweeping

## Vulnerability details
All _accumulatedFees would be stuck in the wrappedNativeToken contract.

## Proof of Concept
DAO attempts to sweep accumulatedFees paid in transactions but fails to unwrap before sweeping.
https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/RootBridgeAgent.sol#L1259
```solidity
function sweep() external {
        if (msg.sender != daoAddress) revert NotDao();
        uint256 _accumulatedFees = accumulatedFees - 1;
        accumulatedFees = 1;
        SafeTransferLib.safeTransferETH(daoAddress, _accumulatedFees);
    }
```

gas fees are wrapped to gasToken when paid by users then any excess deposited gas fees are recorded in the accumulatedFees but when trying to sweep this excess, it fails to unwrap this amount before attempting to sweep.
This implies that when trying to sweep the amount _accumulatedFees, the contracts does not have that amount rather if the ether held in the contracts is upto the value _accumulatedFees then sweep would be successful else it reverts.
all _accumulatedFees would be stuck in the wrappedNativeToken contract.

## Recommendation
Unwrap `_accumulatedFees` before transferring eth to DAO


