// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "../src/AnotherPlease.sol";
import "openzeppelin/token/ERC721/IERC721Receiver.sol";

contract Wrapper is IERC721Receiver {
    function mint(AnotherPlease anotherPlease) external {
        anotherPlease.claimFreeTicket();
    }

    function onERC721Received(address, address, uint256, bytes memory) external returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}
