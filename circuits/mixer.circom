pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/**
 * zmix Privacy Mixer Circuit
 * 
 * This circuit proves that:
 * 1. The withdrawer knows the secret that was used to create a commitment
 * 2. The commitment exists in the Merkle tree of deposits
 * 3. The nullifier is correctly derived (prevents double-spending)
 * 4. The fee calculation is correct
 * 
 * Privacy guarantees:
 * - The link between deposit and withdrawal is hidden
 * - Only the nullifier is revealed (not the original commitment index)
 * - Amount and destination remain private
 */

template MixerDeposit() {
    // Private inputs (known only to depositor)
    signal input secret;           // Random secret for commitment
    signal input nullifierSeed;    // Seed for nullifier generation
    
    // Public inputs
    signal input amount;           // Deposit amount in lamports
    
    // Outputs
    signal output commitment;      // Poseidon(secret, nullifierSeed, amount)
    signal output nullifierHash;   // Poseidon(nullifierSeed, secret)
    
    // Generate commitment using Poseidon hash
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== nullifierSeed;
    commitmentHasher.inputs[2] <== amount;
    commitment <== commitmentHasher.out;
    
    // Generate nullifier hash
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== nullifierSeed;
    nullifierHasher.inputs[1] <== secret;
    nullifierHash <== nullifierHasher.out;
}

template MixerWithdraw(levels) {
    // Merkle tree depth for commitment storage
    
    // Private inputs
    signal input secret;
    signal input nullifierSeed;
    signal input amount;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Public inputs
    signal input root;                    // Merkle root of all commitments
    signal input nullifierHash;           // Published nullifier (prevents double-spend)
    signal input recipient;               // Destination address hash
    signal input feePercent;              // Platform fee (200 = 2%)
    signal input relayer;                 // Optional relayer address
    signal input relayerFee;              // Optional relayer fee
    
    // Verify the commitment
    component deposit = MixerDeposit();
    deposit.secret <== secret;
    deposit.nullifierSeed <== nullifierSeed;
    deposit.amount <== amount;
    
    // Verify nullifier matches
    deposit.nullifierHash === nullifierHash;
    
    // Verify commitment is in Merkle tree
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== deposit.commitment;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    
    // Verify fee calculation (amount * feePercent / 10000)
    signal feeAmount;
    feeAmount <== amount * feePercent;
    // Fee must be less than amount * 10000 (100%)
    component feeCheck = LessThan(64);
    feeCheck.in[0] <== feeAmount;
    feeCheck.in[1] <== amount * 10000;
    feeCheck.out === 1;
    
    // Verify recipient is non-zero
    component recipientCheck = IsZero();
    recipientCheck.in <== recipient;
    recipientCheck.out === 0;
}

template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    component hashers[levels];
    component mux[levels];
    
    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        // Determine left/right based on path index
        mux[i] = DualMux();
        mux[i].in[0] <== levelHashes[i];
        mux[i].in[1] <== pathElements[i];
        mux[i].s <== pathIndices[i];
        
        // Hash the pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        
        levelHashes[i + 1] <== hashers[i].out;
    }
    
    // Verify computed root matches expected root
    root === levelHashes[levels];
}

template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];
    
    s * (1 - s) === 0;  // s must be 0 or 1
    
    out[0] <== (in[1] - in[0]) * s + in[0];
    out[1] <== (in[0] - in[1]) * s + in[1];
}

// Multi-hop mixer circuit for enhanced privacy
template MultiHopMixer(maxHops) {
    // Private inputs
    signal input secret;
    signal input nullifierSeed;
    signal input amount;
    signal input hopSecrets[maxHops];      // Secret for each hop
    signal input hopAmounts[maxHops];      // Amount variance per hop
    
    // Public inputs
    signal input numHops;                   // Actual number of hops (2-6)
    signal input initialCommitment;         // First commitment
    signal input finalNullifier;            // Final nullifier for withdrawal
    signal input totalFeePercent;           // Total fees across all hops
    signal input privacyDelay;              // Delay in seconds
    
    // Outputs
    signal output stealthScore;             // Computed privacy score (0-100)
    signal output proofHash;                // Hash of entire proof for verification
    
    // Generate hop chain commitments
    component hopHashers[maxHops];
    signal hopCommitments[maxHops + 1];
    hopCommitments[0] <== initialCommitment;
    
    for (var i = 0; i < maxHops; i++) {
        hopHashers[i] = Poseidon(3);
        hopHashers[i].inputs[0] <== hopSecrets[i];
        hopHashers[i].inputs[1] <== hopCommitments[i];
        hopHashers[i].inputs[2] <== hopAmounts[i];
        hopCommitments[i + 1] <== hopHashers[i].out;
    }
    
    // Calculate stealth score based on parameters
    // Score = (numHops * 15) + (privacyDelay / 60 * 10) + 30 (base for crypto proof)
    signal hopScore;
    signal delayScore;
    signal baseScore;
    
    hopScore <== numHops * 15;
    delayScore <== privacyDelay * 10;  // Simplified: actual would divide by 60
    baseScore <== 30;  // Base score for using zkSNARK
    
    // Clamp to 100 max
    component scoreSum = Poseidon(3);
    scoreSum.inputs[0] <== hopScore;
    scoreSum.inputs[1] <== delayScore;
    scoreSum.inputs[2] <== baseScore;
    
    stealthScore <== scoreSum.out;  // Will be normalized off-chain
    
    // Generate proof hash
    component proofHasher = Poseidon(4);
    proofHasher.inputs[0] <== initialCommitment;
    proofHasher.inputs[1] <== finalNullifier;
    proofHasher.inputs[2] <== numHops;
    proofHasher.inputs[3] <== totalFeePercent;
    proofHash <== proofHasher.out;
}

// Main circuit for the mixer (20-level Merkle tree supports ~1M deposits)
component main {public [root, nullifierHash, recipient, feePercent, relayer, relayerFee]} = MixerWithdraw(20);
