// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title QubeTimelock - v1.1
/// @title QubeTimelock
/// @notice Custom timelock controller extending OpenZeppelin's implementation
contract QubeTimelock is TimelockController {
    string public constant NAME = "QubeTimelock";

    /**
     * @dev Constructor
     * @param minDelay Minimum delay for operations in seconds
     * @param proposers List of addresses that can propose operations
     * @param executors List of addresses that can execute operations
     * @param admin Address with admin privileges
     */
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {}
}