# Moonwell

The code under review can be found in [2023-07-moonwell](https://github.com/code-423n4/2023-07-moonwell).

## Findings Summary

| ID | Description | Severity |
| - | - | - |
| [M-01](#m-01-reserve-could-exceed-cash-in-utilization-rate-computation) | Reserve could exceed cash in utilization rate computation | Medium |
| [M-02](#m-02-calls-to-_executeProposal-would-reverts-as-external-functions-are-not-marked-payable) | Calls to _executeProposal would reverts as external functions are not marked payable | Medium |
| [M-03](#m-03-check-the-price-against-reasonable-limits) | Check the price against reasonable limits | Medium |

## Reserve could exceed cash in utilization rate computation

## Vulnerability details
The WhitePaperInterestRateModel.utilizationRate and JumpRateModel.utilizationRate function can return value above 1 and not between 0, 1e18.

## Proof of Concept
In WhitePaperInterestRateModel.utilizationRate and JumpRateModel.utilizationRate function, cash and borrows and reserves values gets used to calculate utilization rate between between [0, 1e18]. reserves is currently unused but it will be used in the future.
https://github.com/code-423n4/2023-07-moonwell/blob/main/src/core/IRModels/WhitePaperInterestRateModel.sol#L51
https://github.com/code-423n4/2023-07-moonwell/blob/main/src/core/IRModels/JumpRateModel.sol#L68
```solidity
function utilizationRate(uint cash, uint borrows, uint reserves) public pure returns (uint) {
        // Utilization rate is 0 when there are no borrows
        if (borrows == 0) {
            return 0;
        }

        return borrows.mul(1e18).div(cash.add(borrows).sub(reserves));
    }
```
If Borrow value is 0, then function will return 0. but in this function the scenario where the value of reserves exceeds cash is not handled. the system does not guarantee that reserves never exceeds cash. the reserves grow automatically over time, so it might be difficult to avoid this entirely.

If reserves > cash and cash + borrows - reserves > 0, the formula for utilizationRate above gives a utilization rate above 1.
## Recommendation
Make the utilization rate computation return 1 if reserves > cash.

## Calls to target with non-zero value would always revert.

## Vulnerability details
Calls to target with non-zero value would always revert.

## Proof of Concept
Some external functions within TemporalGovernor uses _executeProposal to execute proposals but these external functions are not marked payable and contract does not implement recieve payable fallback.
https://github.com/code-423n4/2023-07-moonwell/blob/main/src/core/Governance/TemporalGovernor.sol#L400
For instance:

 function executeProposal(bytes memory VAA) public whenNotPaused {
        _executeProposal(VAA, false);
    }
In _executeProposal:
https://github.com/code-423n4/2023-07-moonwell/blob/main/src/core/Governance/TemporalGovernor.sol#L400

```solidity
 function _executeProposal(bytes memory VAA, bool overrideDelay) private {
        
	...SNIP

        _sanityCheckPayload(targets, values, calldatas);

        for (uint256 i = 0; i < targets.length; i++) {
            address target = targets[i];
            uint256 value = values[i];
            bytes memory data = calldatas[i];

            // Go make our call, and if it is not successful revert with the error bubbling up
            (bool success, bytes memory returnData) = target.call{value: value}(//@audit if value is non zero this call would revert.
                data
            );

            /// revert on failure with error message if any
            require(success, string(returnData));

            emit ExecutedTransaction(target, value, data);
        }
    }
```

You can see that _executeProposal makes low level call to the target with value. if value is non-zero the call would revert since the contract have no ETH, since the external function is not marked payable and the contract does not implement receive payable.
Another Instance:
https://github.com/code-423n4/2023-07-moonwell/blob/main/src/core/Governance/TemporalGovernor.sol#L266

## Recommendation
Add payable to the external functions calling _executeProposal or implement receive payable external so contract can recieve ETH.


## Check the price against reasonable limits

## Vulnerability details
wrong price could be returned in the event of a market crash.

## Proof of Concept
From chainlink:

> The data feed aggregator includes both minAnswer and maxAnswer values. These variables prevent the aggregator from updating the latestAnswer outside the agreed range of acceptable values, but they do not stop your application from reading the most recent answer.

> Configure your application to detect when the reported answer is close to reaching minAnswer or maxAnswer and issue an alert so you can respond to a potential market event. Separately, configure your application to detect and respond to extreme price volatility or prices that are outside of your acceptable limits.

Chainlink oracles have a min and max price that they return. If the price goes below the minimum price the oracle will not return the correct price but only the min price. Same goes for the other extremity.
Both ChainlinkCompositeOracle.getPriceAndDecimals and ChainlinkOracle.getChainlinkPrice does not check if price within the correct range:
https://github.com/code-423n4/2023-07-moonwell/blob/main/src/core/Oracles/ChainlinkOracle.sol#L97
```solidity
function getChainlinkPrice(
        AggregatorV3Interface feed
    ) internal view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = AggregatorV3Interface(feed)
            .latestRoundData();
        require(answer > 0, "Chainlink price cannot be lower than 0");
        require(updatedAt != 0, "Round is in incompleted state");

        ...SNIP
    }
```
wrong price may be returned in the event of a market crash.

## Recommendation
Check the latest answer against reasonable limits and/or revert in case you get a bad price

 ```solidity
 require(answer >= minAnswer && answer <= maxAnswer, "invalid price");
 ```