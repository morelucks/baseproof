# BaseProof

## Trust‑Minimized Action Proofs on Base

BaseProof is a decentralized application that allows users to generate and verify cryptographic proofs that a specific action occurred — without relying on blind trust in centralized services.

The system combines **Solidity smart contracts on Base** with a **Go backend verifier** to create immutable, auditable, and portable proofs of actions.

---

## Why BaseProof?

Most applications rely on centralized servers to attest that something happened:

* A task was completed
* A vote was cast
* A submission was made

BaseProof changes the game by anchoring *verifiable proof* onchain while keeping complex verification logic offchain — minimizing trust and maximizing resilience.

> We measure success not by convenience, but by **trust reduced per action**.

---

## Core Idea

Users perform an action (onchain or offchain).
That action is verified by a deterministic Go service.
A cryptographic proof is generated and submitted onchain.
The blockchain becomes the source of truth.

Anyone can independently verify:

* **Who** performed the action
* **When** it happened
* **That** it cannot be altered or forged

---

## Architecture Overview

```text
User
 ├─ Wallet → BaseProof.sol (Base)
 └─ Action → Go Verifier API

Go Backend
 ├─ Verifies actions
 ├─ Generates proof hashes
 ├─ Signs attestations (EIP‑712)
 └─ Exposes REST / WebSocket APIs

BaseProof Smart Contract
 ├─ Stores proof hashes
 ├─ Enforces submission rules
 ├─ Emits immutable events
```

---

## Smart Contracts (Solidity)

### Responsibilities

* Store action proof hashes (`bytes32`)
* Prevent duplicate or invalid proofs
* Emit verifiable onchain events
* Optionally enforce staking or expiry rules

### Example Event

```solidity
event ProofSubmitted(
    address indexed user,
    bytes32 indexed proofHash,
    uint256 timestamp
);
```

The contract is intentionally minimal to reduce attack surface and gas usage.

### Proof Generation Model

```text
proof = hash(user + action + metadata + timestamp)
```

The backend **does not own trust** — its output is publicly verifiable onchain.

---

## End‑to‑End Flow

1. User performs an action
2. Go backend verifies the action
3. Backend returns a proof hash
4. User submits proof to BaseProof contract
5. Contract stores proof and emits event
6. Anyone can verify the proof forever

---

## Getting Started

### Smart Contracts

```bash
cd contracts
forge build
forge test
```

Deploy to Base:

```bash
forge script script/Deploy.s.sol --rpc-url $BASE_RPC --broadcast
```

---

### Backend

```bash
cd backend
go mod tidy
go run cmd/baseproof/main.go
```

---

Built for builders.
Anchored on Base.
Trust minimized by design.
