// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {EIP3009Token} from "../src/EIP3009Token.sol";

contract Deploy is Script {
    function run() external returns (EIP3009Token token) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);
        token = new EIP3009Token("Example USD", "xUSD", "1", 6, owner);
        vm.stopBroadcast();
    }
}
