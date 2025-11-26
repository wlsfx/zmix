#!/bin/bash

set -e

echo "================================"
echo "zmix Circuit Compilation Script"
echo "================================"

BUILD_DIR="circuits/build"
PTAU_DIR="circuits/ptau"
CIRCUIT_FILE="circuits/mixer.circom"

# Create directories
mkdir -p "$BUILD_DIR"
mkdir -p "$PTAU_DIR"

# Check if circom is installed
if ! command -v circom &> /dev/null; then
    echo ""
    echo "ERROR: circom is not installed."
    echo ""
    echo "To install circom, run:"
    echo "  git clone https://github.com/iden3/circom.git"
    echo "  cd circom"
    echo "  cargo build --release"
    echo "  cargo install --path circom"
    echo ""
    echo "Then add ~/.cargo/bin to your PATH"
    exit 1
fi

echo ""
echo "Step 1: Compiling circuit..."
circom "$CIRCUIT_FILE" --r1cs --wasm --sym -o "$BUILD_DIR" -l node_modules

echo ""
echo "Step 2: Downloading Powers of Tau (if needed)..."
PTAU_FILE="$PTAU_DIR/powersOfTau28_hez_final_20.ptau"
if [ ! -f "$PTAU_FILE" ]; then
    echo "Downloading 20-level Powers of Tau (supports 2^20 = ~1M constraints)..."
    curl -L -o "$PTAU_FILE" https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau
else
    echo "Powers of Tau already downloaded."
fi

echo ""
echo "Step 3: Generating zkey (proving key)..."
ZKEY_FILE="$BUILD_DIR/mixer_final.zkey"
npx snarkjs groth16 setup "$BUILD_DIR/mixer.r1cs" "$PTAU_FILE" "$BUILD_DIR/mixer_0000.zkey"

echo ""
echo "Step 4: Contributing to ceremony (adding entropy)..."
npx snarkjs zkey contribute "$BUILD_DIR/mixer_0000.zkey" "$BUILD_DIR/mixer_0001.zkey" --name="zmix contribution" -v -e="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')"

echo ""
echo "Step 5: Finalizing zkey..."
npx snarkjs zkey beacon "$BUILD_DIR/mixer_0001.zkey" "$ZKEY_FILE" 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"

echo ""
echo "Step 6: Exporting verification key..."
npx snarkjs zkey export verificationkey "$ZKEY_FILE" "$BUILD_DIR/verification_key.json"

echo ""
echo "Step 7: Generating Solidity verifier contract..."
npx snarkjs zkey export solidityverifier "$ZKEY_FILE" "$BUILD_DIR/Verifier.sol"

echo ""
echo "Step 8: Cleanup intermediate files..."
rm -f "$BUILD_DIR/mixer_0000.zkey" "$BUILD_DIR/mixer_0001.zkey"

echo ""
echo "================================"
echo "Circuit compilation complete!"
echo "================================"
echo ""
echo "Generated files:"
echo "  - $BUILD_DIR/mixer.r1cs         (constraint system)"
echo "  - $BUILD_DIR/mixer_js/           (WASM witness generator)"
echo "  - $BUILD_DIR/mixer_final.zkey    (proving key)"
echo "  - $BUILD_DIR/verification_key.json (verification key)"
echo "  - $BUILD_DIR/Verifier.sol        (Solidity verifier)"
echo ""
echo "To use in production:"
echo "  1. Copy mixer_final.zkey and verification_key.json to server/lib/zk/"
echo "  2. Update groth16Prover.ts to use the real keys"
echo "  3. Deploy Verifier.sol to Solana using Neon EVM or equivalent"
echo ""
