// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UnsafeDeFi
 * @notice A lending protocol with INTENTIONAL vulnerabilities
 * DO NOT USE IN PRODUCTION
 */
contract UnsafeDeFi {
    struct Position {
        uint256 collateral;
        uint256 debt;
        uint256 lastUpdate;
    }

    mapping(address => Position) public positions;
    mapping(address => bool) public supportedTokens;

    address public owner;
    address public oracle;
    uint256 public constant LIQUIDATION_THRESHOLD = 150; // 150%
    uint256 public totalDeposits;
    uint256 public totalBorrows;

    event Deposit(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);
    event Liquidate(address indexed liquidator, address indexed user, uint256 amount);

    constructor(address _oracle) {
        owner = msg.sender;
        oracle = _oracle;
    }

    // VULNERABILITY: No slippage protection
    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        positions[msg.sender].collateral += msg.value;
        positions[msg.sender].lastUpdate = block.timestamp;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY: Oracle manipulation possible
    function borrow(uint256 amount) external {
        Position storage pos = positions[msg.sender];
        uint256 price = IOracle(oracle).getPrice();

        // VULNERABILITY: Price can be manipulated in same transaction
        uint256 maxBorrow = (pos.collateral * price * 100) / LIQUIDATION_THRESHOLD;
        require(pos.debt + amount <= maxBorrow, "Exceeds borrow limit");

        pos.debt += amount;
        pos.lastUpdate = block.timestamp;
        totalBorrows += amount;

        // VULNERABILITY: Reentrancy - external call before full state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Borrow(msg.sender, amount);
    }

    // VULNERABILITY: Flash loan attack vector - no same-block check
    function liquidate(address user) external {
        Position storage pos = positions[user];
        uint256 price = IOracle(oracle).getPrice();

        uint256 collateralValue = pos.collateral * price;
        uint256 debtValue = pos.debt * LIQUIDATION_THRESHOLD / 100;

        require(collateralValue < debtValue, "Position healthy");

        // VULNERABILITY: Liquidator gets all collateral regardless of debt size
        uint256 reward = pos.collateral;
        pos.collateral = 0;
        pos.debt = 0;

        (bool success, ) = msg.sender.call{value: reward}("");
        require(success, "Transfer failed");

        emit Liquidate(msg.sender, user, reward);
    }

    // VULNERABILITY: Denial of Service - unbounded loop
    function calculateInterest(address[] calldata users) external view returns (uint256 total) {
        for (uint256 i = 0; i < users.length; i++) {
            Position memory pos = positions[users[i]];
            uint256 timeElapsed = block.timestamp - pos.lastUpdate;
            total += pos.debt * timeElapsed * 5 / 100 / 365 days;
        }
    }

    // VULNERABILITY: No deadline parameter
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        require(supportedTokens[tokenIn] && supportedTokens[tokenOut], "Token not supported");
        // Swap logic without deadline - vulnerable to sandwich attacks
    }

    // VULNERABILITY: Delegatecall to user-provided address
    function executeStrategy(address strategy, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        // DANGEROUS: delegatecall to arbitrary address
        (bool success, ) = strategy.delegatecall(data);
        require(success, "Strategy failed");
    }

    // VULNERABILITY: Storage collision risk in upgrades
    uint256[50] private __gap;

    receive() external payable {}
}

interface IOracle {
    function getPrice() external view returns (uint256);
}
