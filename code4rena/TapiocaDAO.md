# Tapioca DAO
The code under review can be found in [2023-07-tapioca](https://github.com/code-423n4/2023-07-tapioca-findings/).

## Findings Summary

| ID | Description | Severity |
| - | - | - |
| [M-01](#m-01-prevent-users-from-sending-more-eth-than-the-premium-price-in-buyoption) | Prevent users from sending more ETH than the premium price in `buyOption()` | Medium |
| [M-02](#m-02-missing-upper-limit-definition-in-setfee) | Missing upper limit definition in `setFee()` | Medium |
| [M-03](#m-03-vaults-created-with-fee-on-transfer-tokens-will-always-fail) | Vaults created with fee-on-transfer tokens will always fail | Medium |
| [M-04](#m-04-recommend-using-safetransferfrom-instead-of-transferfrom-for-nfts) | Recommend using `safeTransferFrom()` instead of `transferFrom()` for NFTs | Medium |