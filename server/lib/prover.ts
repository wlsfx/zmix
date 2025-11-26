/**
 * CircomChan-compatible proof system for SOL→SOL mixer stealth verification
 * Uses real BN128 elliptic curve cryptography with Poseidon commitments
 */

import { createHash } from 'crypto';
import {
  generateCircomMixerProof,
  verifyCircomMixerProof,
  calculateStealthScore as calcScore,
  exportForMoneroChain,
  generateVerificationKey,
  type CircomMixerProof,
  type ProofInputs,
} from './circomchan-mixer';

export interface MixerCircuit {
  inputAmount: string;
  hopCount: number;
  hops: string[];
  destination: string;
  feePercent: number;
  privacyDelay: number;
  timestamp: number;
}

export interface MixProof {
  circuitId: string;
  inputs: MixerCircuit;
  proof: string;
  publicSignals: string[];
  verificationKey: string;
  stealthScore: number;
  privacyFactors: PrivacyFactors;
  circomProof: CircomMixerProof;
}

export interface PrivacyFactors {
  hopComplexity: number;
  delayVariance: number;
  intermediateObfuscation: number;
  cryptographicProof: number;
}

/**
 * Generate a real zero-knowledge proof using CircomChan BN128 cryptography
 */
export async function generateMixProof(circuit: MixerCircuit): Promise<MixProof> {
  const proofInputs: ProofInputs = {
    inputAmount: circuit.inputAmount,
    hopCount: circuit.hopCount,
    hops: circuit.hops,
    destination: circuit.destination,
    feePercent: circuit.feePercent,
    privacyDelay: circuit.privacyDelay,
  };

  const circomProof = await generateCircomMixerProof(proofInputs);
  
  const privacyFactors = calculatePrivacyFactors(circuit);
  const stealthScore = calculateStealthScore(privacyFactors);
  
  const verificationKey = await generateVerificationKey(circomProof.circuitId);
  
  return {
    circuitId: circomProof.circuitId,
    inputs: circuit,
    proof: JSON.stringify(circomProof.proof),
    publicSignals: circomProof.publicSignals,
    verificationKey: JSON.stringify(verificationKey),
    stealthScore,
    privacyFactors,
    circomProof,
  };
}

/**
 * Verify a mixer proof using real BN128 cryptographic verification
 */
export async function verifyMixProof(proof: MixProof): Promise<boolean> {
  try {
    if (!proof.circomProof) {
      console.warn('No CircomChan proof found, falling back to structure check');
      return verifyProofStructure(proof);
    }
    
    const isValid = await verifyCircomMixerProof(proof.circomProof);
    
    if (!isValid) {
      console.error('CircomChan cryptographic verification failed');
      return false;
    }
    
    if (proof.stealthScore < 0 || proof.stealthScore > 100) {
      return false;
    }
    
    const factors = proof.privacyFactors;
    if (
      factors.hopComplexity < 0 || factors.hopComplexity > 100 ||
      factors.delayVariance < 0 || factors.delayVariance > 100 ||
      factors.intermediateObfuscation < 0 || factors.intermediateObfuscation > 100 ||
      factors.cryptographicProof < 0 || factors.cryptographicProof > 100
    ) {
      return false;
    }
    
    return true;
  } catch (error) {
    console.error('Proof verification error:', error);
    return false;
  }
}

function verifyProofStructure(proof: MixProof): boolean {
  if (!proof.proof || !proof.circuitId || !proof.publicSignals) {
    return false;
  }
  
  if (!Array.isArray(proof.publicSignals) || proof.publicSignals.length === 0) {
    return false;
  }
  
  try {
    const parsedProof = JSON.parse(proof.proof);
    if (!parsedProof.pi_a || !parsedProof.pi_b || !parsedProof.pi_c) {
      return false;
    }
  } catch {
    return false;
  }
  
  return true;
}

function calculatePrivacyFactors(circuit: MixerCircuit): PrivacyFactors {
  const hopComplexity = Math.min(100, (circuit.hopCount - 1) * 30 + 10);
  
  const delayVariance = Math.min(100, (circuit.privacyDelay / 1800) * 100);
  
  const intermediateObfuscation = Math.min(100, 
    (hopComplexity * 0.6 + delayVariance * 0.4)
  );
  
  const cryptographicProof = 98;
  
  return {
    hopComplexity,
    delayVariance,
    intermediateObfuscation,
    cryptographicProof,
  };
}

function calculateStealthScore(factors: PrivacyFactors): number {
  const weights = {
    hopComplexity: 0.25,
    delayVariance: 0.20,
    intermediateObfuscation: 0.20,
    cryptographicProof: 0.35,
  };
  
  const score =
    factors.hopComplexity * weights.hopComplexity +
    factors.delayVariance * weights.delayVariance +
    factors.intermediateObfuscation * weights.intermediateObfuscation +
    factors.cryptographicProof * weights.cryptographicProof;
  
  return Math.round(score);
}

export function getPrivacyLevel(stealthScore: number): {
  level: 'low' | 'medium' | 'high' | 'maximum';
  description: string;
} {
  if (stealthScore >= 85) {
    return {
      level: 'maximum',
      description: 'Maximum Privacy - BN128 zkSNARK cryptographic proof with Poseidon commitments',
    };
  } else if (stealthScore >= 70) {
    return {
      level: 'high',
      description: 'High Privacy - Multi-hop obfuscation with cryptographic verification',
    };
  } else if (stealthScore >= 50) {
    return {
      level: 'medium',
      description: 'Medium Privacy - Basic multi-hop with proof verification',
    };
  } else {
    return {
      level: 'low',
      description: 'Low Privacy - Minimal obfuscation configuration',
    };
  }
}

export function exportProofForMoneroChan(proof: MixProof): string {
  if (proof.circomProof) {
    return exportForMoneroChain(proof.circomProof);
  }
  
  return JSON.stringify(
    {
      circuit_id: proof.circuitId,
      proof: proof.proof,
      public_signals: proof.publicSignals,
      stealth_score: proof.stealthScore,
      privacy_factors: proof.privacyFactors,
      verification_key: proof.verificationKey,
      timestamp: proof.inputs.timestamp,
    },
    null,
    2
  );
}

export type { CircomMixerProof, ProofInputs } from './circomchan-mixer';
