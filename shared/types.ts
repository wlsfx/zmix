export type ChainType = 'solana';

interface BaseWallet {
  id: string;
  createdAt: number;
  balance?: number;
  isLoading?: boolean;
  transactions?: WalletTransaction[];
  label?: string;
  txCount?: number;
  autoBurn?: number; // 0 = disabled, 1 = enabled
}

export interface SolanaWallet extends BaseWallet {
  chain: 'solana';
  publicKey: string;
  secretKey?: string; // Optional - fetched from server when needed for signing
}

export type BurnerWallet = SolanaWallet;

export interface WalletTransaction {
  chain: ChainType;
  signature: string;
  from: string;
  to: string;
  amount: number;
  timestamp: number;
  direction: 'incoming' | 'outgoing';
  memo?: string;
}

export interface BridgeTransaction {
  id: string;
  fromChain: ChainType;
  toChain: ChainType;
  fromAddress: string;
  toAddress: string;
  fromAmount: number;
  toAmount: number;
  rate: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  createdAt: number;
  completedAt?: number;
  fromTxHash?: string;
  toTxHash?: string;
  bridgeOrderId?: string;
}
