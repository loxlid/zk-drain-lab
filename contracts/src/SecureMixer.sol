// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IVerifier } from "./interfaces/IVerifier.sol";

/**
 * @title SecureMixer
 * @author Loxee
 * @notice The FIXED counterpart to `VulnerableMixer`. Same external interface,
 *         same privacy model — but it records spent nullifiers and rejects
 *         reuse, which is what stops the double-withdraw drain.
 *
 * The only meaningful difference from the vulnerable contract is the
 * `spentNullifiers` mapping and the two lines in `withdraw()` that (1) reject
 * an already-spent nullifier and (2) burn the nullifier *before* paying out
 * (checks-effects-interactions, so the external call cannot re-enter into a
 * second spend of the same note).
 */
contract SecureMixer {
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

    /// @notice Every root this pool has ever held.
    mapping(bytes32 => bool) public knownRoots;

    /// @notice commitment => already deposited. Prevents accidental dup leaves.
    mapping(bytes32 => bool) public commitments;

    /// @notice FIX: nullifierHash => already spent. This is the registry the
    ///         vulnerable contract is missing. Once a note is redeemed its
    ///         nullifier is recorded here and can never be redeemed again.
    mapping(uint256 => bool) public spentNullifiers;

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
    error NullifierAlreadySpent();
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
     * @param newRoot The Merkle root after inserting `commitment`.
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
     * @param root          Merkle root the proof was built against.
     * @param nullifierHash The note's single-use spend tag.
     * @param recipient     Address that receives the funds (bound in the proof).
     * @param pA            Groth16 proof element A.
     * @param pB            Groth16 proof element B.
     * @param pC            Groth16 proof element C.
     *
     * @dev FIX: the nullifier is checked first and burned before the payout,
     *      so a replayed note reverts with `NullifierAlreadySpent` and the
     *      external call can never re-enter a second spend.
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

        // FIX: reject a note that has already been redeemed.
        if (spentNullifiers[nullifierHash]) revert NullifierAlreadySpent();

        // Public signals must match the circuit's declared order:
        // [root, nullifierHash, recipient, commitment].
        uint256[4] memory pubSignals;
        pubSignals[0] = uint256(root);
        pubSignals[1] = nullifierHash;
        pubSignals[2] = uint256(uint160(recipient));
        pubSignals[3] = 0; // commitment is informational here

        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) revert InvalidProof();

        // FIX: burn the nullifier BEFORE the interaction (checks-effects-
        // interactions). The note is now permanently spent.
        spentNullifiers[nullifierHash] = true;

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

    /// @notice Whether a nullifier has been spent.
    function isSpent(uint256 nullifierHash) external view returns (bool) {
        return spentNullifiers[nullifierHash];
    }
}
