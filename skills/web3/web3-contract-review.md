# Web3 / Smart Contract Security Review

**status:** active
**risk:** L0–L2
**approval:** L0 auto, L2 requires explicit approval (mainnet fork PoC)
**program_types:** [web3]
**source:** reviewed from Trail of Bits, Solidity patterns, Immunefi reports

## Pre-Review: Protocol Understanding

1. Read documentation, whitepaper, technical specs
2. Map the contract architecture: inheritance, interfaces, libraries
3. Identify: upgradeability pattern, access control, token standard
4. List all external entry points: public/external functions, receive/fallback
5. Note: trusted roles, timelocks, multisigs, governance parameters
6. Identify: oracles, bridges, cross-chain messaging dependencies

## Vulnerability Classes

### Access Control
- Missing onlyOwner/onlyRole on privileged functions
- Initializable without initializer modifier (can be re-initialized)
- Delegatecall to user-controlled address (proxy pattern misuse)
- tx.origin for authorization (phishing-vulnerable)
- Unprotected selfdestruct
- Ownership transfer without two-step (can be bricked)

### Arithmetic & Overflow
- Unchecked math (Solidity ^0.8.0 has overflow checks, but unchecked blocks bypass)
- Rounding errors in division (to receive 0 tokens due to precision loss)
- Precision loss in fee calculations (fee-on-transfer tokens)
- Phantom overflow with assembly blocks
- ERC20 decimals mismatch in multi-token protocols

### Reentrancy
- Classic reentrancy: external call before state update
- Cross-function reentrancy: two functions sharing state
- Cross-contract reentrancy: multiple contracts in protocol
- Read-only reentrancy: view function seeing inconsistent state
- ERC777/ERC721 callback reentrancy: tokens with hooks
- Reentrancy via receive/fallback

### Oracle / Price Manipulation
- Spot price from thin liquidity pool → flash-loan manipulation
- TWAP with short observation window
- Single oracle source without circuit breakers
- Stale price data without staleness check
- Off-chain oracle: centralized, signature replay possible?

### MEV & Front-Running
- Commit-reveal schemes without proper implementation
- Sandwich attacks: large slippage tolerance on DEX trades
- Time-bandit attacks: reorganization depth insufficient
- Priority gas auction (PGA) for liquidation bots
- Just-in-time (JIT) liquidity attacks

### Governance Attacks
- Flash-loan governance: borrow → vote → repay
- Proposal execution without timelock
- Delegate voting power to malicious address
- Emergency functions not time-locked
- Governance parameter change without minimum delay

### Token-Specific
- ERC20: approve front-running (use increaseAllowance/decreaseAllowance)
- ERC721/1155: reentrancy via onERC721Received
- Fee-on-transfer: balance ≠ amount received
- Rebasing tokens: balanceOf changes without transfer events
- Return value handling: some tokens don't return bool on transfer

## Tool-Based Analysis

| Tool | Type | Notes |
|------|------|-------|
| Slither | Static analysis | Vulnerability detectors, data-flow, inheritance graph |
| Aderyn | Static analysis | Rust-based, fast, focused findings |
| Foundry | Test framework | Fuzz testing, invariant testing, fork testing |
| Echidna | Fuzzer | Property-based, long campaigns |
| Mythril | Symbolic execution | Path coverage for complex branching |
| 4naly3er | Spec generator | Generates invariant specifications |

## Manual Review Checklist

1. [ ] Every external call after state changes? (reentrancy-safe)
2. [ ] Every ETH transfer uses call{value: x}("") with return check?
3. [ ] Access control on every privileged function?
4. [ ] Initializer protected from re-initialization?
5. [ ] Oracle data validated for staleness, deviation, source?
6. [ ] Rounding direction favors protocol over attacker?
7. [ ] Slippage protection on every user-facing swap?
8. [ ] Emergency pause/unpause properly access-controlled?
9. [ ] Upgrade paths secure (no storage collisions, verified implementations)?
10. [ ] Signature replay protection (nonce, deadline, chainId)?

## Fork-Based PoC (L2 — requires approval)

- Deploy to local Anvil fork of mainnet
- Execute transaction sequence proving vulnerability
- Validate with minimal value (1 wei, not 100 ETH)
- Clean up fork after validation
- Never execute on mainnet without explicit program authorization

## Stop Conditions

- PoC on mainnet fork only — never on production
- Demonstrate with minimal value (dust amounts)
- Never drain real funds
- Never broadcast transactions to mainnet
