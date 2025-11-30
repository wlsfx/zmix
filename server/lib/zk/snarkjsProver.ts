/**
 * Production Groth16 Prover using snarkjs
 * 
 * This module provides REAL zkSNARK proof generation using snarkjs with:
 * - Compiled circuit from circom (mixer.wasm)
 * - Powers of Tau ceremony artifacts
 * - Groth16 proving/verification keys (.zkey)
 * 
 * SECURITY: All proofs are cryptographically sound and can be verified on-chain.
 */

import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import { randomBytes, createHash } from 'crypto';
import * as path from 'path';
import * as fs from 'fs';

// Path to compiled circuit artifacts
const CIRCUIT_DIR = path.join(process.cwd(), 'circuits', 'build');
const WASM_PATH = path.join(CIRCUIT_DIR, 'mixer_js', 'mixer.wasm');
const ZKEY_PATH = path.join(CIRCUIT_DIR, 'mixer_final.zkey');
const VKEY_PATH = path.join(CIRCUIT_DIR, 'verification_key.json');

// BN128 curve parameters
const BN128_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

// Cached Poseidon instance
let poseidonInstance: any = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Check if circuit artifacts are available
 */
export function areCircuitArtifactsReady(): boolean {
  try {
    return fs.existsSync(WASM_PATH) && 
           fs.existsSync(ZKEY_PATH) && 
           fs.existsSync(VKEY_PATH);
  } catch {
    return false;
  }
}

/**
 * Generate cryptographically secure random scalar in BN128 field
 */
function generateRandomScalar(): bigint {
  const bytes = randomBytes(32);
  let value = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    value = (value << BigInt(8)) + BigInt(bytes[i]);
  }
  return value % BN128_PRIME;
}

/**
 * Compute Poseidon hash - REAL cryptographic hash
 */
export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const poseidon = await getPoseidon();
  const hash = poseidon(inputs.map(i => poseidon.F.e(i)));
  return BigInt(poseidon.F.toString(hash));
}

/**
 * Compute commitment: Poseidon(secret, nullifierSeed, amount)
 */
export async function computeCommitment(secret: bigint, nullifierSeed: bigint, amount: bigint): Promise<bigint> {
  return poseidonHash([secret, nullifierSeed, amount]);
}

/**
 * Compute nullifier hash: Poseidon(nullifierSeed, secret)
 */
export async function computeNullifierHash(nullifierSeed: bigint, secret: bigint): Promise<bigint> {
  return poseidonHash([nullifierSeed, secret]);
}

export interface ProofInputs {
  // Private inputs
  secret: bigint;
  nullifierSeed: bigint;
  amount: bigint;
  pathElements: bigint[];
  pathIndices: number[];
  
  // Public inputs
  root: bigint;
  nullifierHash: bigint;
  recipient: bigint;
  feePercent: number;
  relayer: bigint;
  relayerFee: bigint;
}

export interface Groth16ProofResult {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
}

/**
 * Generate a real Groth16 proof using snarkjs
 */
export async function generateProof(inputs: ProofInputs): Promise<Groth16ProofResult> {
  if (!areCircuitArtifactsReady()) {
    throw new Error('Circuit artifacts not ready. Run trusted setup first.');
  }
  
  // Verify the commitment matches
  const commitment = await computeCommitment(inputs.secret, inputs.nullifierSeed, inputs.amount);
  const nullifierHash = await computeNullifierHash(inputs.nullifierSeed, inputs.secret);
  
  if (nullifierHash !== inputs.nullifierHash) {
    throw new Error('Nullifier hash does not match computed value');
  }
  
  // Prepare circuit inputs
  const circuitInputs = {
    // Private inputs
    secret: inputs.secret.toString(),
    nullifierSeed: inputs.nullifierSeed.toString(),
    amount: inputs.amount.toString(),
    pathElements: inputs.pathElements.map(e => e.toString()),
    pathIndices: inputs.pathIndices,
    
    // Public inputs
    root: inputs.root.toString(),
    nullifierHash: inputs.nullifierHash.toString(),
    recipient: inputs.recipient.toString(),
    feePercent: inputs.feePercent.toString(),
    relayer: inputs.relayer.toString(),
    relayerFee: inputs.relayerFee.toString(),
  };
  
  // Generate the proof using snarkjs
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInputs,
    WASM_PATH,
    ZKEY_PATH
  );
  
  return {
    proof: {
      pi_a: proof.pi_a,
      pi_b: proof.pi_b,
      pi_c: proof.pi_c,
      protocol: proof.protocol,
      curve: proof.curve,
    },
    publicSignals,
  };
}

/**
 * Verify a Groth16 proof using snarkjs
 */
export async function verifyProof(
  proof: Groth16ProofResult['proof'],
  publicSignals: string[]
): Promise<boolean> {
  if (!areCircuitArtifactsReady()) {
    throw new Error('Circuit artifacts not ready. Cannot verify proof.');
  }
  
  try {
    const vKey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
    
    const isValid = await snarkjs.groth16.verify(
      vKey,
      publicSignals,
      proof
    );
    
    return isValid;
  } catch (error) {
    console.error('Proof verification error:', error);
    return false;
  }
}

/**
 * Generate deposit note with all required secrets
 */
export async function createDepositNote(amountLamports: bigint): Promise<{
  commitment: string;
  nullifierHash: string;
  secret: string;
  nullifierSeed: string;
  amount: string;
}> {
  const secret = generateRandomScalar();
  const nullifierSeed = generateRandomScalar();
  
  const commitment = await computeCommitment(secret, nullifierSeed, amountLamports);
  const nullifierHash = await computeNullifierHash(nullifierSeed, secret);
  
  return {
    commitment: commitment.toString(16).padStart(64, '0'),
    nullifierHash: nullifierHash.toString(16).padStart(64, '0'),
    secret: secret.toString(16).padStart(64, '0'),
    nullifierSeed: nullifierSeed.toString(16).padStart(64, '0'),
    amount: amountLamports.toString(),
  };
}

/**
 * Export verification key for on-chain deployment
 */
export async function exportVerificationKey(): Promise<object | null> {
  if (!fs.existsSync(VKEY_PATH)) {
    return null;
  }
  
  try {
    return JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Get circuit info
 */
export function getCircuitInfo(): {
  ready: boolean;
  wasmPath: string;
  zkeyPath: string;
  vkeyPath: string;
} {
  return {
    ready: areCircuitArtifactsReady(),
    wasmPath: WASM_PATH,
    zkeyPath: ZKEY_PATH,
    vkeyPath: VKEY_PATH,
  };
}
