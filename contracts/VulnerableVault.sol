// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVault
 * @notice This contract has INTENTIONAL vulnerabilities for testing audit tools
 * DO NOT USE IN PRODUCTION
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool public paused;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY: No reentrancy guard
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state update (reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call - REENTRANCY VULNERABLE
        balances[msg.sender] -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY: Using tx.origin for authorization
    function emergencyWithdraw() external {
        require(tx.origin == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    // VULNERABILITY: Unprotected selfdestruct
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }

    // VULNERABILITY: Unchecked return value
    function unsafeTransfer(address token, address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        // Return value not checked
        IERC20(token).transfer(to, amount);
    }

    // VULNERABILITY: Integer overflow in unchecked block
    function unsafeIncrement(uint256 value) external pure returns (uint256) {
        unchecked {
            return value + 1; // Can overflow
        }
    }

    // VULNERABILITY: Block timestamp manipulation
    function isLucky() external view returns (bool) {
        return block.timestamp % 15 == 0;
    }

    // VULNERABILITY: Weak randomness
    function random() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender)));
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
