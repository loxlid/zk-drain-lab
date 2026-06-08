// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IVerifier } from "./interfaces/IVerifier.sol";

/**
 * @title VulnerableMixer
 * @author Loxee
 * @notice A Tornado-style fixed-denomination privacy pool — DELIBERATELY BROKEN
 *         for educational purposes. DO NOT DEPLOY.
 *
 * Users deposit a fixed `DENOMINATION` of ETH by publishing a Poseidon
 * `commitment = Poseidon(nullifier, secret)` as a leaf in an append-only
 * Merkle tree. Later they withdraw — to a fresh, unlinked address — by
 * submitting a Groth16 proof (from `circuits/withdraw.circom`) attesting that:
 *
 *   - they know the (nullifier, secret) behind some commitment in the tree,
 *   - the disclosed `nullifierHash` is correctly derived from their nullifier,
 *   - the `recipient` is bound into the proof.
 *
 * The pool never learns *which* deposit a withdrawal corresponds to — that is
 * the privacy guarantee. The `nullifierHash` exists precisely so each deposit
 * note can be spent exactly once.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *                            ⚠️  THE VULNERABILITY  ⚠️
 * ─────────────────────────────────────────────────────────────────────────
 * @dev VULN: This contract NEVER records spent nullifiers. `withdraw()` checks
 *      the proof and the root, then pays out — but it does not consult or
 *      update any "nullifier already spent" set. The `nullifierHash` public
 *      signal is accepted and ignored.
 *
 *      Consequence: a single valid proof (or any number of fresh proofs for
 *      the SAME note) can be replayed indefinitely. One 1-ETH deposit can be
 *      withdrawn over and over until the entire pool — everyone else's
 *      deposits included — is drained. This is a classic nullifier-reuse /
 *      double-spend bug. See SecureMixer.sol for the fix and
 *      test/Exploit.t.sol for a working drain PoC.
 */
contract VulnerableMixer {
    // --------------------------------------------------------------------- //
    //                              Constants                                //
    // --------------------------------------------------------------------- //

    /// @notice Fixed deposit/withdrawal amount. All notes are worth this much.
    uint256 public constant DENOMINATION = 1 ether;

    /// @notice Depth of the Merkle tree (matches `Withdraw(20)` in the circuit).
    uint32 public constant TREE_DEPTH = 20;

    // --------------------------------------------------------------------- //
    //                               Storage                                 //
    // --------------------------------------------------------------------- //

    /// @notice Groth16 verifier generated from the trusted setup.
    IVerifier public immutable verifier;

    /// @notice Next free leaf index in the append-only tree.
    uint32 public nextLeafIndex;

    /// @notice Number of deposits made (also the number of leaves).
    uint256 public depositCount;

    /// @notice The current Merkle root after the most recent deposit.
    bytes32 public currentRoot;

    /// @notice Every root this pool has ever held. A withdrawal proof is valid
    ///         against any historical root so deposits made after a user built
    ///         their proof don't invalidate it.
    mapping(bytes32 => bool) public knownRoots;

    /// @notice commitment => already deposited. Prevents accidental dup leaves.
    mapping(bytes32 => bool) public commitments;

    // NOTE: There is intentionally NO `mapping(uint256 => bool) spentNullifiers`
    // here. That omission is the bug.

    // --------------------------------------------------------------------- //
    //                                Events                                 //
    // --------------------------------------------------------------------- //

    event Deposit(bytes32 indexed commitment, uint32 leafIndex, bytes32 newRoot);
    event Withdrawal(address indexed recipient, uint256 nullifierHash);

    // --------------------------------------------------------------------- //
    //                                Errors                                 //
    // --------------------------------------------------------------------- //

    error ZeroAddress();
    error WrongDenomination();
    error CommitmentAlreadyUsed();
    error UnknownRoot();
    error InvalidProof();
    error PayoutFailed();

    // --------------------------------------------------------------------- //
    //                             Constructor                               //
    // --------------------------------------------------------------------- //

    /**
     * @param _verifier Address of the deployed Groth16 verifier.
     * @param _initialRoot The root of the (empty) tree, published off-chain.
     */
    constructor(IVerifier _verifier, bytes32 _initialRoot) {
        if (address(_verifier) == address(0)) revert ZeroAddress();
        verifier = _verifier;
        currentRoot = _initialRoot;
        knownRoots[_initialRoot] = true;
    }

    // --------------------------------------------------------------------- //
    //                               Deposit                                 //
    // --------------------------------------------------------------------- //

    /**
     * @notice Deposit exactly `DENOMINATION` ETH under a commitment.
     * @param commitment Poseidon(nullifier, secret) — a fresh tree leaf.
     * @param newRoot The Merkle root after inserting `commitment`. In a real
     *                pool this is recomputed on-chain; here the caller supplies
     *                the off-chain-computed root and we record it as known.
     *
     * @dev Funds accumulate in the contract; withdrawals draw from this pooled
     *      balance, which is what makes the nullifier-reuse bug a *drain* and
     *      not merely a self-inflicted replay.
     */
    function deposit(bytes32 commitment, bytes32 newRoot) external payable {
        if (msg.value != DENOMINATION) revert WrongDenomination();
        if (commitments[commitment]) revert CommitmentAlreadyUsed();

        commitments[commitment] = true;
        uint32 leafIndex = nextLeafIndex;

        nextLeafIndex = leafIndex + 1;
        depositCount += 1;
        currentRoot = newRoot;
        knownRoots[newRoot] = true;

        emit Deposit(commitment, leafIndex, newRoot);
    }

    // --------------------------------------------------------------------- //
    //                              Withdraw                                 //
    // --------------------------------------------------------------------- //

    /**
     * @notice Withdraw `DENOMINATION` to `recipient` against a valid proof.
     * @param root          Merkle root the proof was built against; must be a
     *                      root this pool has held at some point.
     * @param nullifierHash The note's spend tag. SHOULD be single-use.
     * @param recipient     Address that receives the funds (bound in the proof).
     * @param pA            Groth16 proof element A.
     * @param pB            Groth16 proof element B.
     * @param pC            Groth16 proof element C.
     *
     * @dev VULN: notice what is MISSING. We never check
     *      `spentNullifiers[nullifierHash]` and we never set it. The same
     *      `nullifierHash` — i.e. the same deposit note — can be presented
     *      again and again, each time paying out another `DENOMINATION` from
     *      the pooled balance. An attacker who made one deposit can loop this
     *      call until `address(this).balance` hits zero, stealing every other
     *      depositor's funds.
     */
    function withdraw(
        bytes32 root,
        uint256 nullifierHash,
        address recipient,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC
    ) external {
        if (recipient == address(0)) revert ZeroAddress();
        if (!knownRoots[root]) revert UnknownRoot();

        // VULN: a real pool would short-circuit here:
        //     if (spentNullifiers[nullifierHash]) revert NullifierAlreadySpent();
        // That check does not exist, so reuse is silently allowed.

        // Public signals must match the circuit's declared order:
        // [root, nullifierHash, recipient, commitment].
        uint256[4] memory pubSignals;
        pubSignals[0] = uint256(root);
        pubSignals[1] = nullifierHash;
        pubSignals[2] = uint256(uint160(recipient));
        pubSignals[3] = 0; // commitment is informational here

        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) revert InvalidProof();

        // VULN: no `spentNullifiers[nullifierHash] = true;` — the note is
        // never burned, so it stays spendable forever.

        (bool ok,) = payable(recipient).call{ value: DENOMINATION }("");
        if (!ok) revert PayoutFailed();

        emit Withdrawal(recipient, nullifierHash);
    }

    // --------------------------------------------------------------------- //
    //                                Views                                  //
    // --------------------------------------------------------------------- //

    /// @notice Total ETH currently held by the pool.
    function poolBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Whether a nullifier has been spent.
     * @dev VULN: always returns false — there is no spent-nullifier registry,
     *      so the pool genuinely cannot tell a note has already been redeemed.
     */
    function isSpent(uint256) external pure returns (bool) {
        return false;
    }
}
