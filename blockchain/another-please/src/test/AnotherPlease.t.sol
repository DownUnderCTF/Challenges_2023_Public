// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/AnotherPlease.sol";
import "./Wrapper.sol";

contract AnotherPleaseTest is Test {
    AnotherPlease public anotherPlease;
    Wrapper public wrapper;

    function setUp() public {
        anotherPlease = new AnotherPlease();
        wrapper = new Wrapper();
    }

    function test_claim() public {
        assertEq(anotherPlease.freeTicketReceivers(address(wrapper)), false);

        wrapper.mint(anotherPlease);

        assertEq(anotherPlease.totalSupply(), 1);
        assertEq(anotherPlease.ownerOf(0), address(wrapper));
        assertEq(anotherPlease.freeTicketReceivers(address(wrapper)), true);
    }

    function test_revertIf_multipleClaimed() public {
        wrapper.mint(anotherPlease);
        vm.expectRevert(AnotherPlease.FreeTicketAlreadyClaimed.selector);
        wrapper.mint(anotherPlease);
    }

    function test_claimAll() public {
        uint256 max = anotherPlease.TICKETS_TO_GIVE_AWAY();
        for (uint256 i; i < max; i++) {
            Wrapper w = new Wrapper();
            w.mint(anotherPlease);
        }
    }

    function test_revertWhen_claimMoreThanAllowed() public {
        uint256 max = anotherPlease.TICKETS_TO_GIVE_AWAY();
        for (uint256 i; i < max; i++) {
            Wrapper w = new Wrapper();
            w.mint(anotherPlease);
        }

        Wrapper w2 = new Wrapper();
        vm.expectRevert(AnotherPlease.FreeTicketsExhausted.selector);
        w2.mint(anotherPlease);
    }
}
