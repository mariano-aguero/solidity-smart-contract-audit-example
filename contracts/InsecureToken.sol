// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title InsecureToken
 * @notice ERC20 token with INTENTIONAL vulnerabilities for testing
 * DO NOT USE IN PRODUCTION
 */
contract InsecureToken {
    string public name = "Insecure Token";
    string public symbol = "INSEC";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public owner;
    bool public paused;

    // VULNERABILITY: No indexed parameters in events
    event Transfer(address from, address to, uint256 value);
    event Approval(address owner, address spender, uint256 value);

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply * 10 ** decimals;
        balanceOf[msg.sender] = totalSupply;
    }

    // VULNERABILITY: Missing zero address check
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    // VULNERABILITY: Front-running allowance (no increaseAllowance/decreaseAllowance)
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // VULNERABILITY: Missing zero address checks
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");

        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        emit Transfer(from, to, amount);
        return true;
    }

    // VULNERABILITY: Centralization risk - owner can mint unlimited tokens
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    // VULNERABILITY: Centralization risk - owner can burn anyone's tokens
    function burnFrom(address from, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        require(balanceOf[from] >= amount, "Insufficient balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    // VULNERABILITY: Missing access control on pause
    function pause() external {
        // Anyone can pause!
        paused = true;
    }

    // VULNERABILITY: Hardcoded gas in external call
    function withdrawStuckETH() external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = owner.call{gas: 2300, value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    // VULNERABILITY: Floating pragma in production code (see file header)

    receive() external payable {}
}
