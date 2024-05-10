// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

contract Callee {
    address public lastSender;
    bytes public lastCalldata;

    receive() external payable {}
    
    fallback() external payable {
        lastSender = msg.sender;
        lastCalldata = msg.data;
    }
}
