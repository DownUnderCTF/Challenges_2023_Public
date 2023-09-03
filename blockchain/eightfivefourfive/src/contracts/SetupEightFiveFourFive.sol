// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {EightFiveFourFive} from "./EightFiveFourFive.sol";

/**
 * @title SolveMe
 * @author BlueAlder duc.tf
 *
 * This contract **MUST** be the base for any challenge setup contract
 * to ensure compatability with this service.
 */

abstract contract Setup {
    // Stores the address of the deployed challenge
    address public challenge;
    address public player_address;

    constructor(address _player_address) {
        player_address = _player_address;
        challenge = deploy();
    }

    // Deploys the challenge with all the setup parameters
    // returns the address of the deployed challenge instance.
    function deploy() public virtual returns (address);

    // Should return a bool as to whether the challenge is solved or not
    // by whatever criteria is required
    function isSolved() external view virtual returns (bool);
}

contract SetupEightFiveFourFive is Setup {
    constructor(address player_address) Setup(player_address) {}

    function deploy() public override returns (address) {
        EightFiveFourFive _instance = new EightFiveFourFive("I can connect to the blockchain!");
        return address(_instance);
    }

    function isSolved() external view override returns (bool) {
        return EightFiveFourFive(challenge).isSolved();
    }
}
