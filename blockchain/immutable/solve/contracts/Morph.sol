// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Create2Deployer {
    event Deployed(address indexed);

    function deployc1Deployer() external {
        Create1Deployer deployed = new Create1Deployer{salt: bytes32(0)}();
        emit Deployed(address(deployed));
    }
}

contract Create1Deployer {
    event Deployed(address indexed);

    function deployMetaphorphic(bytes memory deployCode) external {
        address deployed;
        assembly {
            deployed := create(0, add(deployCode, 0x20), 12)
        }
        emit Deployed(address(deployed));
    }

    function die() external {
        selfdestruct(payable(address(0)));
    }
}
