// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IVerifier
 * @notice Minimal interface for a Groth16 verifier as emitted by snarkjs'
 *         `snarkjs zkey export solidityverifier`.
 * @dev The concrete `Verifier` contract is generated from the
 *      proving/verification key produced by the trusted setup. Its
 *      `verifyProof` signature is fixed by snarkjs:
 *
 *        - `_pA`  : Groth16 proof element A  (G1 point)
 *        - `_pB`  : Groth16 proof element B  (G2 point)
 *        - `_pC`  : Groth16 proof element C  (G1 point)
 *        - `_pubSignals` : the circuit's public inputs, in declaration order
 *
 *      For `withdraw.circom` the public-signal array has 4 entries:
 *        [0] root
 *        [1] nullifierHash
 *        [2] recipient
 *        [3] commitment
 */
interface IVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}
