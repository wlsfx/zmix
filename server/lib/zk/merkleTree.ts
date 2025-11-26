/**
 * Production Merkle Tree for storing mixer commitments
 * 
 * Uses real Poseidon hash for zkSNARK compatibility.
 * Supports up to 2^20 (1,048,576) deposits.
 * 
 * SECURITY: Persists to database for production use with real funds.
 */

import { buildPoseidon } from 'circomlibjs';
import { db } from '../../db';
import { zkCommitments, zkNullifiers, zkMerkleRoots } from '@shared/schema';
import { eq, desc } from 'drizzle-orm';

const BN128_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

let poseidonInstance: any = null;

async function getPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

export interface MerkleProof {
  root: string;
  pathElements: string[];
  pathIndices: number[];
  leaf: string;
  leafIndex: number;
}

export class MerkleTree {
  private levels: number;
  private leaves: bigint[];
  private layers: bigint[][];
  private zeros: bigint[];
  private poseidon: any;
  private initialized: boolean = false;
  
  constructor(levels: number = 20) {
    this.levels = levels;
    this.leaves = [];
    this.layers = [];
    this.zeros = [];
  }
  
  async initialize(): Promise<void> {
    if (this.initialized) return;
    
    this.poseidon = await getPoseidon();
    
    // Compute zero values for empty leaves using real Poseidon
    this.zeros = [BigInt(0)];
    
    for (let i = 1; i <= this.levels; i++) {
      const hash = this.poseidon([this.zeros[i - 1], this.zeros[i - 1]]);
      this.zeros.push(BigInt(this.poseidon.F.toString(hash)));
    }
    
    // Initialize empty tree layers
    this.layers = [];
    for (let i = 0; i <= this.levels; i++) {
      this.layers.push([]);
    }
    
    // Load existing commitments from database
    await this.loadFromDatabase();
    
    this.initialized = true;
  }
  
  private async loadFromDatabase(): Promise<void> {
    try {
      const commitments = await db
        .select()
        .from(zkCommitments)
        .where(eq(zkCommitments.status, 'active'))
        .orderBy(zkCommitments.leafIndex);
      
      for (const c of commitments) {
        const commitment = BigInt('0x' + c.commitment);
        this.leaves.push(commitment);
        this.layers[0].push(commitment);
      }
      
      // Rebuild tree from leaves
      if (this.leaves.length > 0) {
        await this.rebuildTree();
      }
    } catch (error) {
      console.error('Error loading Merkle tree from database:', error);
    }
  }
  
  private async rebuildTree(): Promise<void> {
    // Rebuild all layers from leaves
    for (let level = 0; level < this.levels; level++) {
      const levelSize = this.layers[level].length;
      const parentLevel: bigint[] = [];
      
      for (let i = 0; i < levelSize; i += 2) {
        const left = this.layers[level][i];
        const right = this.layers[level][i + 1] ?? this.zeros[level];
        parentLevel.push(this.hash(left, right));
      }
      
      this.layers[level + 1] = parentLevel;
    }
  }
  
  private hash(left: bigint, right: bigint): bigint {
    const hash = this.poseidon([left, right]);
    return BigInt(this.poseidon.F.toString(hash));
  }
  
  async insert(commitment: bigint, amount: string): Promise<number> {
    await this.initialize();
    
    const index = this.leaves.length;
    if (index >= Math.pow(2, this.levels)) {
      throw new Error('Merkle tree is full');
    }
    
    this.leaves.push(commitment);
    this.layers[0].push(commitment);
    
    // Update path from leaf to root
    let currentIndex = index;
    let currentValue = commitment;
    
    for (let level = 0; level < this.levels; level++) {
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
      
      const sibling = this.layers[level][siblingIndex] ?? this.zeros[level];
      const left = isRightNode ? sibling : currentValue;
      const right = isRightNode ? currentValue : sibling;
      currentValue = this.hash(left, right);
      
      const parentIndex = Math.floor(currentIndex / 2);
      if (this.layers[level + 1].length <= parentIndex) {
        this.layers[level + 1].push(currentValue);
      } else {
        this.layers[level + 1][parentIndex] = currentValue;
      }
      
      currentIndex = parentIndex;
    }
    
    // Persist to database
    try {
      await db.insert(zkCommitments).values({
        commitment: commitment.toString(16),
        leafIndex: index,
        amount: amount,
        status: 'active',
      });
      
      // Update Merkle root
      const root = await this.getRoot();
      await db.update(zkMerkleRoots).set({ isActive: 0 });
      await db.insert(zkMerkleRoots).values({
        root: root.toString(16),
        leafCount: this.leaves.length,
        isActive: 1,
      });
    } catch (error) {
      console.error('Error persisting commitment:', error);
    }
    
    return index;
  }
  
  async getRoot(): Promise<bigint> {
    await this.initialize();
    
    if (this.leaves.length === 0) {
      return this.zeros[this.levels];
    }
    
    return this.layers[this.levels][0];
  }
  
  async getProof(leafIndex: number): Promise<MerkleProof> {
    await this.initialize();
    
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error('Leaf index out of range');
    }
    
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    
    let currentIndex = leafIndex;
    
    for (let level = 0; level < this.levels; level++) {
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
      
      const sibling = this.layers[level][siblingIndex] ?? this.zeros[level];
      pathElements.push(sibling);
      pathIndices.push(isRightNode ? 1 : 0);
      
      currentIndex = Math.floor(currentIndex / 2);
    }
    
    const root = await this.getRoot();
    
    return {
      root: root.toString(16),
      pathElements: pathElements.map(e => e.toString(16)),
      pathIndices,
      leaf: this.leaves[leafIndex].toString(16),
      leafIndex,
    };
  }
  
  async verifyProof(proof: MerkleProof): Promise<boolean> {
    await this.initialize();
    
    let currentValue = BigInt('0x' + proof.leaf);
    
    for (let i = 0; i < proof.pathElements.length; i++) {
      const sibling = BigInt('0x' + proof.pathElements[i]);
      const isRight = proof.pathIndices[i] === 1;
      
      const left = isRight ? sibling : currentValue;
      const right = isRight ? currentValue : sibling;
      currentValue = this.hash(left, right);
    }
    
    return currentValue.toString(16) === proof.root;
  }
  
  getLeafCount(): number {
    return this.leaves.length;
  }
  
  export(): { leaves: string[]; root: string } {
    return {
      leaves: this.leaves.map(l => l.toString(16)),
      root: this.layers[this.levels][0]?.toString(16) || this.zeros[this.levels].toString(16),
    };
  }
}

// Global commitment tree instance
let commitmentTree: MerkleTree | null = null;

export async function getCommitmentTree(): Promise<MerkleTree> {
  if (!commitmentTree) {
    commitmentTree = new MerkleTree(20);
    await commitmentTree.initialize();
  }
  return commitmentTree;
}

/**
 * Check if nullifier has been used (database-backed)
 */
export async function isNullifierUsed(nullifier: string): Promise<boolean> {
  try {
    const result = await db
      .select()
      .from(zkNullifiers)
      .where(eq(zkNullifiers.nullifierHash, nullifier))
      .limit(1);
    
    return result.length > 0;
  } catch (error) {
    console.error('Error checking nullifier:', error);
    return false;
  }
}

/**
 * Mark nullifier as used (database-backed)
 */
export async function markNullifierUsed(
  nullifier: string,
  commitmentId?: string,
  recipient?: string,
  txSignature?: string
): Promise<void> {
  try {
    await db.insert(zkNullifiers).values({
      nullifierHash: nullifier,
      commitmentId,
      recipient,
      txSignature,
    });
    
    // Mark commitment as withdrawn
    if (commitmentId) {
      await db
        .update(zkCommitments)
        .set({ status: 'withdrawn', withdrawnAt: new Date() })
        .where(eq(zkCommitments.id, commitmentId));
    }
  } catch (error) {
    console.error('Error marking nullifier as used:', error);
    throw error;
  }
}

/**
 * Get nullifier count from database
 */
export async function getNullifierCount(): Promise<number> {
  try {
    const result = await db.select().from(zkNullifiers);
    return result.length;
  } catch (error) {
    console.error('Error getting nullifier count:', error);
    return 0;
  }
}

/**
 * Get active Merkle root from database
 */
export async function getActiveMerkleRoot(): Promise<string | null> {
  try {
    const result = await db
      .select()
      .from(zkMerkleRoots)
      .where(eq(zkMerkleRoots.isActive, 1))
      .limit(1);
    
    return result.length > 0 ? result[0].root : null;
  } catch (error) {
    console.error('Error getting active Merkle root:', error);
    return null;
  }
}
