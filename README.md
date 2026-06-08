# ZK-DRAIN-LAB

![CI](https://github.com/loxlid/zk-drain-lab/actions/workflows/ci.yml/badge.svg) ![Circom](https://img.shields.io/badge/Circom-2.1.9-1f6feb) ![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636?logo=solidity&logoColor=white) ![Foundry](https://img.shields.io/badge/Foundry-tested-success) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A **Damn-Vulnerable-DeFi-style lab — but for zero-knowledge bugs.** It ships a Tornado-style privacy pool that is *deliberately broken* in a single, devastating way, alongside the fixed version and a Foundry exploit that drains the broken pool to zero. The goal is to teach, in runnable code, the most common class of ZK-mixer vulnerability: **nullifier reuse / double-spend**.

> 🧪 **Educational security research.** Every contract and exploit here targets *this repo's own* code. The vulnerable contract is intentionally wrong. See the **DISCLAIMER** at the bottom — never deploy these to a network holding real value.

---

## What this lab teaches

A privacy pool (Tornado Cash, Semaphore-based mixers, etc.) lets you deposit a fixed amount under a hidden `commitment` and later withdraw to a fresh address by proving — in zero knowledge — that you own *some* deposit in the set, without revealing *which one*. Two cryptographic objects make this work:

- **commitment** = `Poseidon(nullifier, secret)` — published at deposit time as a Merkle-tree leaf.
- **nullifierHash** = `Poseidon(nullifier)` — revealed at withdrawal time so the pool can mark the note **spent**.

The zk proof guarantees the `nullifierHash` is honestly derived from a real deposit. But the proof **cannot** stop you from submitting the *same* `nullifierHash` twice — that is the contract's job. The on-chain "have I seen this nullifier before?" check is the entire anti-double-spend mechanism. Forget it, and one deposit can be withdrawn forever.

---

## The vulnerability

`src/VulnerableMixer.sol` verifies the proof, checks the Merkle root, and pays out — but **never records spent nullifiers**:

```solidity
function withdraw(bytes32 root, uint256 nullifierHash, address recipient, ...) external {
    if (!knownRoots[root]) revert UnknownRoot();
    // VULN: no `if (spentNullifiers[nullifierHash]) revert ...` check
    if (!verifier.verifyProof(pA, pB, pC, pubSignals)) revert InvalidProof();
    // VULN: no `spentNullifiers[nullifierHash] = true;`
    payable(recipient).call{ value: DENOMINATION }("");
}
```

There is no `spentNullifiers` mapping at all. `isSpent()` always returns `false`. A valid proof for one note is therefore **replayable indefinitely** — each call siphons another `DENOMINATION` from the *pooled* balance, which includes everyone else's deposits.

---

## How the exploit works

`test/Exploit.t.sol` proves the drain end to end:

1. The attacker deposits **1 ETH**. Two victims each deposit 1 ETH. The pool now holds **3 ETH**.
2. The attacker calls `withdraw(...)` with their note's `nullifierHash` — a legitimate first spend. Pool: 2 ETH.
3. The attacker calls `withdraw(...)` **again with the exact same `nullifierHash`**. A correct pool rejects this; the vulnerable one pays out again. Pool: 1 ETH.
4. One more replay empties the pool. Pool: **0 ETH**.

Net result: the attacker deposited 1 ETH and walked away with 3 ETH (balance 9 → 12). The two victims' deposits are gone. The test asserts the pool is fully drained and the attacker's balance grew by `3 × DENOMINATION`.

Under a `MockVerifier` the proof always verifies — which is the *realistic* case: an attacker who knows one note's `(nullifier, secret)` can legitimately generate as many valid proofs for it as they like. The bug is purely the missing on-chain bookkeeping.

---

## Vulnerable vs. secure

`src/SecureMixer.sol` is identical except for the fix:

```solidity
mapping(uint256 => bool) public spentNullifiers;          // the missing registry

function withdraw(...) external {
    ...
    if (spentNullifiers[nullifierHash]) revert NullifierAlreadySpent(); // FIX 1: reject reuse
    if (!verifier.verifyProof(...)) revert InvalidProof();
    spentNullifiers[nullifierHash] = true;                 // FIX 2: burn BEFORE payout
    payable(recipient).call{ value: DENOMINATION }("");
}
```

The nullifier is burned *before* the external call (checks-effects-interactions), so a replay reverts and a re-entrant payout can't sneak a second spend. The exploit test confirms the second withdrawal reverts with `NullifierAlreadySpent` and the victims keep their funds.

---

## Build & test

### Contracts (Foundry)

```bash
cd contracts
forge install foundry-rs/forge-std   # forge-std is vendored as a submodule
forge build
forge test -vvv
```

All tests pass. They use a steerable `MockVerifier`, so the mixer logic — deposit accounting, root history, the nullifier-reuse drain, and the fix — is exercised without a real proof.

### Circuit + proof pipeline

```bash
npm install                  # circomlib + snarkjs + circom_tester
npm run build                # compile → powers of tau → groth16 setup → export Verifier.sol
npm run prove                # build a witness + proof from inputs/input.example.json
npm run verify               # snarkjs groth16 verify (off-chain sanity check)
```

`circuits/withdraw.circom` is a depth-20 Poseidon Merkle-inclusion proof with `nullifierHash` derivation. Public signals (in verifier order): `root`, `nullifierHash`, `recipient`, `commitment`.

---

## Repository layout

```
zk-drain-lab/
├── circuits/
│   └── withdraw.circom          Merkle inclusion + nullifierHash derivation (depth 20)
├── contracts/                   Foundry project
│   ├── foundry.toml
│   ├── src/
│   │   ├── VulnerableMixer.sol  ⚠️ nullifier never recorded — drainable
│   │   ├── SecureMixer.sol      ✅ records & rejects spent nullifiers
│   │   └── interfaces/IVerifier.sol  verifyProof ABI (4 public signals)
│   └── test/Exploit.t.sol       drain PoC + fix assertions + accounting tests
├── scripts/build.sh             circom compile → ptau → groth16 setup → export verifier
├── inputs/input.example.json    sample prover input
├── package.json
├── .env.example
└── LICENSE                      MIT © 2026 Loxee
```

---

## ⚠️ DISCLAIMER

`VulnerableMixer.sol` is **intentionally broken** for education. It is missing the spent-nullifier check on purpose so the double-spend drain is demonstrable. **Do not deploy it, or anything derived from it, to any network holding real value.** Use only the patterns in `SecureMixer.sol` (and a properly audited, real trusted setup) for anything production-bound. This repository is for learning how ZK-mixer bugs work and how to catch them — nothing here is audited, and the exploits only ever target this repo's own contracts.

## License

MIT © 2026 Loxee
