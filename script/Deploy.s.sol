// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {BaseProof} from "../src/BaseProof.sol";

/// @title Deploy
/// @notice Deployment script for BaseProof contract
contract Deploy is Script {
    function run() public returns (BaseProof) {
        vm.startBroadcast();

        BaseProof baseProof = new BaseProof();

        vm.stopBroadcast();

        return baseProof;
    }
}

