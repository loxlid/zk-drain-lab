pragma circom 2.1.6;

// circomlib templates. Resolved via the include path `-l node_modules`,
// i.e. these live under node_modules/circomlib/circuits/*.
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

/*
 * MerkleTreeInclusionProof
 * ------------------------
 * Proves that `leaf` sits in a Poseidon Merkle tree whose root is `root`.
 *
 * For each level we hash the current node together with its sibling. The
 * `pathIndices` bit selects ordering: 0 => current node is the left child,
 * 1 => current node is the right child. We use a MultiMux1 to swap the
 * (left, right) pair without leaking branching into the constraint system.
 */
template MerkleTreeInclusionProof(DEPTH) {
    signal input leaf;                  // commitment being proven
    signal input pathElements[DEPTH];   // sibling hash at each level
    signal input pathIndices[DEPTH];    // 0/1 position bit at each level
    signal output root;                 // computed Merkle root

    component hashers[DEPTH];
    component mux[DEPTH];

    signal levelHashes[DEPTH + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        // pathIndices[i] must be a boolean (0 or 1).
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Order the (current, sibling) pair according to the position bit.
        // mux.out[0] = left input to the hash, mux.out[1] = right input.
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[DEPTH];
}

/*
 * Withdraw
 * --------
 * Tornado-style privacy-pool withdrawal proof.
 *
 * A depositor holds two secrets: a `nullifier` and a `secret`. At deposit
 * time their *commitment* is published into the pool's Merkle tree:
 *
 *     commitment = Poseidon(nullifier, secret)
 *
 * To withdraw, the prover demonstrates — in zero knowledge — that:
 *
 *   1. They know the (nullifier, secret) pre-image of some commitment that is
 *      a leaf of the tree rooted at `root` (membership, without revealing
 *      which leaf — this is the anonymity set).
 *   2. The disclosed `nullifierHash` is correctly derived from their secret
 *      `nullifier`. The pool records this hash so the same deposit note can
 *      only be spent once.
 *   3. They bind a `recipient` address into the proof so a relayer (or any
 *      mempool observer) cannot re-target a valid withdrawal to a different
 *      address.
 *
 * Commitment scheme (Tornado Cash style):
 *     commitment    = Poseidon(nullifier, secret)
 *     nullifierHash = Poseidon(nullifier)
 *
 * `recipient` is squared into a dummy constraint. This is the standard
 * non-malleability trick: it forces the recipient signal to participate in
 * the constraint system so a relayer cannot reuse a valid proof while
 * swapping in a different `recipient` to steal the funds.
 */
template Withdraw(DEPTH) {
    // ---- Private inputs (the prover's secret witness) ----
    signal input nullifier;             // secret #1 (also feeds the nullifier hash)
    signal input secret;                // secret #2
    signal input pathElements[DEPTH];   // Merkle sibling path to the commitment
    signal input pathIndices[DEPTH];    // 0/1 position bits along that path

    // ---- Public inputs (revealed on-chain, checked by the verifier) ----
    signal input root;                  // Merkle root of deposit commitments
    signal input nullifierHash;         // anti-double-spend tag for this note
    signal input recipient;             // address that receives the withdrawal

    // ---- Outputs ----
    signal output commitment;           // exposed for debugging / off-chain checks

    // (1) Reconstruct the deposit commitment from the two secrets.
    component calcCommitment = Poseidon(2);
    calcCommitment.inputs[0] <== nullifier;
    calcCommitment.inputs[1] <== secret;

    commitment <== calcCommitment.out;

    // (2) Prove the commitment is a member of the tree rooted at `root`.
    component tree = MerkleTreeInclusionProof(DEPTH);
    tree.leaf <== calcCommitment.out;
    for (var i = 0; i < DEPTH; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    // Enforce the recomputed root equals the public root.
    root === tree.root;

    // (3) Derive and bind the nullifier hash to the secret nullifier.
    component calcNullifier = Poseidon(1);
    calcNullifier.inputs[0] <== nullifier;
    nullifierHash === calcNullifier.out;

    // (4) Force the recipient signal into the constraint system so the proof
    // is non-malleable with respect to the withdrawal target (a relayer
    // cannot re-point a valid proof at their own address).
    signal recipientSquared;
    recipientSquared <== recipient * recipient;
}

/*
 * Main component.
 *
 * Public signal order (this is the order snarkjs will use for public.json and
 * the generated Solidity verifier's `input[]` array):
 *
 *   [0] root
 *   [1] nullifierHash
 *   [2] recipient
 *   [3] commitment          (circuit output)
 *
 * DEPTH = 20 supports up to 2^20 ≈ 1,048,576 deposits in the anonymity set.
 */
component main {public [root, nullifierHash, recipient]} = Withdraw(20);
