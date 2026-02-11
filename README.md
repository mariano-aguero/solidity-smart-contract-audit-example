# Smart Contract Audit Example

This project contains **intentionally vulnerable** Solidity smart contracts for testing the MCP Audit Server.

## Contracts

| Contract | Vulnerabilities |
|----------|-----------------|
| `VulnerableVault.sol` | Reentrancy, tx.origin, selfdestruct, unchecked return values |
| `InsecureToken.sol` | Missing zero checks, centralization, front-running, access control |
| `UnsafeDeFi.sol` | Oracle manipulation, flash loans, delegatecall, DoS |

## MCP Configuration

This project is configured to connect to the MCP Audit Server via SSE transport. See `.mcp.json`.

## Testing the Audit

Open this project in Claude Code and try:

```
Audit the VulnerableVault.sol contract for security issues
```

```
Analyze all contracts in this project
```

```
Check contracts/UnsafeDeFi.sol for reentrancy and oracle manipulation
```

## Warning

These contracts are for **testing purposes only**. They contain intentional security vulnerabilities and should **never be deployed** to any network.
