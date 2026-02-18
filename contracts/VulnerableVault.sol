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

    // NEW: Delegate withdrawal to another address
    mapping(address => address) public delegates;

    function setDelegate(address delegate) external {
        // VULNERABILITY (OBVIOUS): No zero address check
        // VULNERABILITY (SUBTLE): No event emitted for critical state change
        delegates[msg.sender] = delegate;
    }

    function withdrawFor(address user, uint256 amount) external {
        require(delegates[user] == msg.sender, "Not delegate");
        require(balances[user] >= amount, "Insufficient balance");

        // VULNERABILITY (OBVIOUS): Same reentrancy pattern as withdraw()
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[user] -= amount;
        emit Withdrawal(user, amount);
    }

    // NEW: Multi-signature withdrawal
    mapping(bytes32 => uint256) public approvalCount;
    mapping(bytes32 => mapping(address => bool)) public hasApproved;
    address[] public signers;
    uint256 public requiredSignatures;

    function initializeMultisig(address[] calldata _signers, uint256 _required) external {
        require(msg.sender == owner, "Not owner");
        // VULNERABILITY (SUBTLE): Can be called multiple times - reinitialize attack
        // VULNERABILITY (OBVIOUS): No validation that _required <= _signers.length
        signers = _signers;
        requiredSignatures = _required;
    }

    function approveWithdrawal(bytes32 withdrawalId) external {
        bool isSigner = false;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == msg.sender) {
                isSigner = true;
                break;
            }
        }
        require(isSigner, "Not a signer");

        // VULNERABILITY (SUBTLE): No check if already approved - can approve multiple times
        // Actually wait, let me check - hasApproved mapping exists but not used properly
        hasApproved[withdrawalId][msg.sender] = true;
        approvalCount[withdrawalId]++; // VULNERABILITY: Increments even if already approved
    }

    function executeMultisigWithdrawal(address to, uint256 amount, bytes32 withdrawalId) external {
        require(approvalCount[withdrawalId] >= requiredSignatures, "Not enough approvals");

        // VULNERABILITY (OBVIOUS): No check that withdrawal wasn't already executed
        // VULNERABILITY (OBVIOUS): No reentrancy guard
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");

        // VULNERABILITY (SUBTLE): approvalCount not reset - withdrawal can be replayed
    }

    // NEW: Time-locked withdrawal
    mapping(address => uint256) public unlockTime;
    mapping(address => uint256) public lockedAmount;

    function lockFunds(uint256 duration) external payable {
        require(msg.value > 0, "Must lock something");
        // VULNERABILITY (SUBTLE): Can overwrite existing lock with smaller amount/shorter duration
        lockedAmount[msg.sender] = msg.value;
        unlockTime[msg.sender] = block.timestamp + duration;
    }

    function withdrawLocked() external {
        require(block.timestamp >= unlockTime[msg.sender], "Still locked");
        // VULNERABILITY (OBVIOUS): block.timestamp can be slightly manipulated by miners

        uint256 amount = lockedAmount[msg.sender];
        // VULNERABILITY (OBVIOUS): Missing reentrancy guard and CEI pattern
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        lockedAmount[msg.sender] = 0;
    }

    // NEW: Fee collection
    uint256 public collectedFees;
    uint256 public constant FEE_PERCENTAGE = 1; // 1%

    function depositWithFee() external payable {
        require(msg.value > 0, "Must deposit something");

        // VULNERABILITY (SUBTLE): Fee calculation before balance update creates rounding issues
        uint256 fee = msg.value / 100; // 1% fee
        uint256 netAmount = msg.value - fee;

        collectedFees += fee;
        balances[msg.sender] += netAmount;

        emit Deposit(msg.sender, netAmount);
    }

    function withdrawFees() external {
        require(msg.sender == owner, "Not owner");
        uint256 amount = collectedFees;
        // VULNERABILITY (SUBTLE): State not zeroed before external call (CEI violation)
        (bool success, ) = owner.call{value: amount}("");
        require(success, "Transfer failed");
        collectedFees = 0;
    }

    // NEW: Signature-based withdrawal
    function withdrawWithSignature(
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) external {
        // VULNERABILITY (SUBTLE): Signature malleability - v can be 27 or 28
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount, nonce));
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));

        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        // VULNERABILITY (SUBTLE): ecrecover can return address(0) on invalid signature
        address signer = ecrecover(ethSignedHash, v, r, s);
        require(signer == owner, "Invalid signature");

        // VULNERABILITY (OBVIOUS): Nonce not tracked - signature replay possible
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        // VULNERABILITY (SUBTLE): No validation of s value (should be in lower half of curve order)
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
