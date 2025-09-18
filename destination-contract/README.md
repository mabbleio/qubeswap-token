# QST Destination Chain Contract

QubeSwapToken Destination Chain Contract 
for Bridges Use.

QST is a multi-chain token

## Key Features

Mint/Burn Mechanism: The bridge will mint tokens on the destination chain when deposits occur on the source chain (and burn when withdrawing).<br>

Role-Based Access Control: Only the bridge contract (or a designated "minter" role) should be able to mint/burn. <br>

Initial Supply: The MAX_SUPPLY should be enforced, but minting should be allowed up to this cap. <br>

Security: Ensure no reentrancy or unauthorized minting. <br>

Compatibility: Align with common bridge patterns (e.g., LayerZero, Axelar, or custom bridge logic). <br>


## Bridge Integration Notes

Deploy the Token:

Deploy QubeSwapTokenDT on the destination chain.

Call grantBridgeRole(bridgeAddress) to authorize the bridge contract.


#### Bridge Contract Logic:

The bridge should call mint(to, amount) on deposits (source → destination).

The bridge should call burn(from, amount) on withdrawals (destination → source).




#### Security Considerations:

Only the bridge should have BRIDGE_ROLE (or MINTER_ROLE).

Use nonReentrant to prevent reentrancy in mint/burn.

Validate MAX_SUPPLY to prevent inflation.




