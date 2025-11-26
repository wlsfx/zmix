/**
 * zmix Production Zero-Knowledge Proof System
 * 
 * This module provides production-ready zkSNARK infrastructure for the mixer:
 * 
 * 1. Trusted Setup - Powers of Tau ceremony with real curve operations
 * 2. Groth16 Prover - Generate proofs using real BN128 cryptography
 * 3. Merkle Tree - Database-backed storage for deposit commitments
 * 4. Solana Verifier - On-chain proof verification
 * 
 * SECURITY: All operations use production-grade cryptographic libraries
 * (circomlibjs, ffjavascript) suitable for handling real funds.
 * 
 * Privacy Guarantees:
 * - Zero-knowledge: Proof reveals nothing about private inputs
 * - Soundness: Invalid proofs cannot be forged
 * - Completeness: Valid transactions always produce valid proofs
 */

export * from './trustedSetup';
export * from './groth16Prover';
export * from './merkleTree';
export * from './solanaVerifier';

import { createHash } from 'crypto';
import { buildPoseidon } from 'circomlibjs';
import { getCommitmentTree, isNullifierUsed, markNullifierUsed, type MerkleProof, getNullifierCount } from './merkleTree';
import { generateFullZKProof, verifyGroth16Proof, createDeposit, poseidonHash, type FullZKProof, type MixerWitness } from './groth16Prover';
import { getVerificationKey, type VerificationKey } from './trustedSetup';
import { encodeProofForSolana, estimateVerificationCost } from './solanaVerifier';

const BN128_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

let poseidonInstance: any = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

export interface DepositNote {
  commitment: string;
  nullifierHash: string;
  secret: string;
  nullifierSeed: string;
  amount: string;
  leafIndex: number;
  timestamp: number;
}

export interface WithdrawalRequest {
  note: DepositNote;
  recipient: string;
  relayer?: string;
  relayerFee?: string;
}

export interface WithdrawalResult {
  success: boolean;
  proof?: FullZKProof;
  merkleProof?: MerkleProof;
  transactionHash?: string;
  error?: string;
}

/**
 * Create a new deposit with zero-knowledge commitment
 * Uses real Poseidon hashing for production security
 */
export async function createZKDeposit(amountLamports: bigint): Promise<DepositNote> {
  const deposit = await createDeposit(amountLamports);
  
  // Add commitment to Merkle tree with database persistence
  const tree = await getCommitmentTree();
  const commitment = BigInt('0x' + deposit.commitment);
  const amountSol = (Number(amountLamports) / 1e9).toString();
  const leafIndex = await tree.insert(commitment, amountSol);
  
  return {
    commitment: deposit.commitment,
    nullifierHash: deposit.nullifierHash,
    secret: deposit.secret,
    nullifierSeed: deposit.nullifierSeed,
    amount: amountLamports.toString(),
    leafIndex,
    timestamp: Date.now(),
  };
}

/**
 * Generate withdrawal proof with full zero-knowledge properties
 */
export async function generateWithdrawalProof(
  request: WithdrawalRequest
): Promise<WithdrawalResult> {
  try {
    const { note, recipient, relayer, relayerFee } = request;
    
    // Check nullifier against database
    const nullifierUsed = await isNullifierUsed(note.nullifierHash);
    if (nullifierUsed) {
      return {
        success: false,
        error: 'Nullifier already used - deposit has been withdrawn',
      };
    }
    
    // Get Merkle proof
    const tree = await getCommitmentTree();
    const merkleProof = await tree.getProof(note.leafIndex);
    
    // Verify proof validity
    const isValidPath = await tree.verifyProof(merkleProof);
    if (!isValidPath) {
      return {
        success: false,
        error: 'Invalid Merkle proof - commitment not in tree',
      };
    }
    
    // Hash recipient to field element
    const recipientHash = createHash('sha256').update(recipient).digest();
    let recipientField = BigInt(0);
    for (let i = 0; i < 31; i++) {
      recipientField = (recipientField << BigInt(8)) + BigInt(recipientHash[i]);
    }
    recipientField = recipientField % BN128_PRIME;
    
    // Prepare witness
    const witness: MixerWitness = {
      secret: BigInt('0x' + note.secret),
      nullifierSeed: BigInt('0x' + note.nullifierSeed),
      amount: BigInt(note.amount),
      pathElements: merkleProof.pathElements.map(e => BigInt('0x' + e)),
      pathIndices: merkleProof.pathIndices,
      root: BigInt('0x' + merkleProof.root),
      nullifierHash: BigInt('0x' + note.nullifierHash),
      recipient: recipientField,
      feePercent: 200, // 2% platform fee
      relayer: relayer ? BigInt('0x' + createHash('sha256').update(relayer).digest('hex').slice(0, 40)) : BigInt(0),
      relayerFee: relayerFee ? BigInt(relayerFee) : BigInt(0),
    };
    
    // Generate proof
    const zkProof = await generateFullZKProof(witness);
    
    // Verify proof locally
    const verification = await verifyGroth16Proof(zkProof);
    if (!verification.isValid) {
      return {
        success: false,
        error: `Proof verification failed: ${verification.error}`,
      };
    }
    
    // Mark nullifier as used in database
    await markNullifierUsed(note.nullifierHash, undefined, recipient);
    
    return {
      success: true,
      proof: zkProof,
      merkleProof,
    };
  } catch (error: any) {
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Verify a withdrawal proof
 */
export async function verifyWithdrawalProof(proof: FullZKProof): Promise<{
  isValid: boolean;
  nullifier: string;
  root: string;
  error?: string;
}> {
  const verification = await verifyGroth16Proof(proof);
  
  return {
    isValid: verification.isValid,
    nullifier: proof.nullifier,
    root: proof.root,
    error: verification.error,
  };
}

/**
 * Get current Merkle tree state
 */
export async function getMerkleTreeState(): Promise<{
  root: string;
  leafCount: number;
  nullifiersUsed: number;
}> {
  const tree = await getCommitmentTree();
  const root = await tree.getRoot();
  const nullifiersUsed = await getNullifierCount();
  
  return {
    root: root.toString(16),
    leafCount: tree.getLeafCount(),
    nullifiersUsed,
  };
}

/**
 * Prepare proof for on-chain verification
 */
export async function prepareOnChainVerification(proof: FullZKProof): Promise<{
  encodedProof: ReturnType<typeof encodeProofForSolana>;
  verificationKey: VerificationKey;
  estimatedCost: ReturnType<typeof estimateVerificationCost>;
}> {
  const encodedProof = encodeProofForSolana(proof);
  const verificationKey = await getVerificationKey();
  const estimatedCost = estimateVerificationCost();
  
  return {
    encodedProof,
    verificationKey,
    estimatedCost,
  };
}

/**
 * Calculate privacy score based on ZK proof parameters
 */
export function calculateZKPrivacyScore(params: {
  hopCount: number;
  delaySeconds: number;
  hasZKProof: boolean;
  merkleTreeSize: number;
}): {
  score: number;
  breakdown: {
    hopComplexity: number;
    delayVariance: number;
    anonymitySet: number;
    cryptographicProof: number;
  };
} {
  const hopComplexity = Math.min(25, (params.hopCount - 1) * 8);
  const delayVariance = Math.min(25, (params.delaySeconds / 60) * 5);
  const anonSetLog = Math.log2(Math.max(1, params.merkleTreeSize));
  const anonymitySet = Math.min(25, anonSetLog * 2.5);
  const cryptographicProof = params.hasZKProof ? 25 : 5;
  
  const score = Math.round(hopComplexity + delayVariance + anonymitySet + cryptographicProof);
  
  return {
    score: Math.min(100, score),
    breakdown: {
      hopComplexity: Math.round(hopComplexity),
      delayVariance: Math.round(delayVariance),
      anonymitySet: Math.round(anonymitySet),
      cryptographicProof: Math.round(cryptographicProof),
    },
  };
}
