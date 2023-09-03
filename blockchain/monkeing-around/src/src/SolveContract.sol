pragma solidity ^0.8.19;

contract SolveContract {
    address[] public dummyArray;
    address public owner;

    function solve(address addressToSet) external {
        owner = addressToSet;
    }
}
