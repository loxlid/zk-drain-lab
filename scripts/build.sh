#!/usr/bin/env bash
#
# build.sh — end-to-end zk-drain-lab circuit build pipeline.
#
# Stages:
#   compile   circom -> R1CS + WASM witness generator + symbols
#   ptau      Powers of Tau (phase 1, universal) ceremony
#   setup     Groth16 phase-2 setup -> proving/verification keys (.zkey)
#   verifier  export the Solidity Groth16 verifier from the final zkey
#   all       run every stage in order
#
# Requirements:
#   - circom   >= 2.1   (https://docs.circom.io/getting-started/installation/)
#   - snarkjs            (installed locally via `npm install`)
#   - circomlib          (installed via `npm install`, resolved with -l node_modules)
#
# Usage:
#   npm install
#   bash scripts/build.sh all
#   # or a single stage:
#   bash scripts/build.sh compile
#
set -euo pipefail

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_NAME="withdraw"
CIRCUIT_SRC="${ROOT_DIR}/circuits/${CIRCUIT_NAME}.circom"
BUILD_DIR="${ROOT_DIR}/build"
NODE_MODULES="${ROOT_DIR}/node_modules"
VERIFIER_OUT="${ROOT_DIR}/contracts/src/Verifier.sol"

# Powers of Tau size. 2^PTAU_POWER constraints must exceed the circuit size.
# A depth-20 withdrawal circuit fits comfortably under 2^16.
PTAU_POWER="${PTAU_POWER:-16}"
PTAU_FILE="${BUILD_DIR}/pot${PTAU_POWER}_final.ptau"

# Prefer a locally installed snarkjs; fall back to npx.
SNARKJS="npx --no-install snarkjs"

log()  { printf '\033[1;36m[build]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[build:error]\033[0m %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"
}

# ----------------------------------------------------------------------------
# Stages
# ----------------------------------------------------------------------------
compile() {
    require circom
    [ -d "${NODE_MODULES}/circomlib" ] || fail "circomlib not found — run 'npm install' first"
    mkdir -p "${BUILD_DIR}"
    log "compiling ${CIRCUIT_NAME}.circom"
    circom "${CIRCUIT_SRC}" \
        --r1cs --wasm --sym \
        -l "${NODE_MODULES}" \
        -o "${BUILD_DIR}"
    log "constraint summary:"
    ${SNARKJS} r1cs info "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs"
}

ptau() {
    mkdir -p "${BUILD_DIR}"
    local p1="${BUILD_DIR}/pot${PTAU_POWER}_0000.ptau"
    local p2="${BUILD_DIR}/pot${PTAU_POWER}_0001.ptau"

    log "powers of tau: new ceremony (2^${PTAU_POWER})"
    ${SNARKJS} powersoftau new bn128 "${PTAU_POWER}" "${p1}" -v

    log "powers of tau: first contribution"
    ${SNARKJS} powersoftau contribute "${p1}" "${p2}" \
        --name="zk-drain-lab first contribution" -v -e="$(head -c 64 /dev/urandom | base64)"

    log "powers of tau: prepare phase 2"
    ${SNARKJS} powersoftau prepare phase2 "${p2}" "${PTAU_FILE}" -v
    log "ptau ready: ${PTAU_FILE}"
}

setup() {
    [ -f "${PTAU_FILE}" ] || fail "missing ${PTAU_FILE} — run the 'ptau' stage first"
    [ -f "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" ] || fail "missing R1CS — run 'compile' first"

    local zkey0="${BUILD_DIR}/${CIRCUIT_NAME}_0000.zkey"
    local zkeyf="${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey"

    log "groth16 setup"
    ${SNARKJS} groth16 setup "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" "${PTAU_FILE}" "${zkey0}"

    log "phase-2 contribution"
    ${SNARKJS} zkey contribute "${zkey0}" "${zkeyf}" \
        --name="zk-drain-lab phase2 contribution" -v -e="$(head -c 64 /dev/urandom | base64)"

    log "exporting verification key"
    ${SNARKJS} zkey export verificationkey "${zkeyf}" "${BUILD_DIR}/verification_key.json"
    log "setup complete: ${zkeyf}"
}

verifier() {
    local zkeyf="${BUILD_DIR}/${CIRCUIT_NAME}_final.zkey"
    [ -f "${zkeyf}" ] || fail "missing ${zkeyf} — run 'setup' first"

    log "exporting Solidity verifier -> ${VERIFIER_OUT}"
    ${SNARKJS} zkey export solidityverifier "${zkeyf}" "${VERIFIER_OUT}"

    # snarkjs names the contract `Groth16Verifier` and targets a recent solc,
    # which is exactly what the mixers / IVerifier expect. No post-processing needed.
    log "verifier written. Rebuild contracts with: (cd contracts && forge build)"
}

all() {
    compile
    ptau
    setup
    verifier
    log "pipeline complete. Generate a proof with: npm run prove"
}

# ----------------------------------------------------------------------------
# Dispatch
# ----------------------------------------------------------------------------
cmd="${1:-all}"
case "${cmd}" in
    compile)  compile ;;
    ptau)     ptau ;;
    setup)    setup ;;
    verifier) verifier ;;
    all)      all ;;
    *)        fail "unknown stage '${cmd}' (expected: compile|ptau|setup|verifier|all)" ;;
esac
