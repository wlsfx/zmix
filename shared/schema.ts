import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, numeric, json } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const wallets = pgTable("wallets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(), // Allow wallets without auth (public access)
  publicKey: text("public_key").notNull().unique(),
  encryptedPrivateKey: text("encrypted_private_key").notNull(), // AES encrypted
  label: text("label"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  txCount: integer("tx_count").default(0).notNull(),
  isBurned: integer("is_burned").default(0).notNull(), // 0 = active, 1 = burned
  autoBurn: integer("auto_burn").default(0).notNull(), // 0 = disabled, 1 = auto-burn after mix
});

// Mixer sessions for progress persistence (SOL→SOL with platform fees)
export const mixerSessions = pgTable("mixer_sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  walletId: varchar("wallet_id").notNull(),
  destinationAddress: text("destination_address"), // Final SOL destination address
  status: text("status").notNull(), // 'hopping', 'sending', 'completed', 'failed'
  grossAmount: numeric("gross_amount", { precision: 18, scale: 9 }).notNull(),
  platformFee: numeric("platform_fee", { precision: 18, scale: 9 }),
  netAmount: numeric("net_amount", { precision: 18, scale: 9 }),
  finalAmount: numeric("final_amount", { precision: 18, scale: 9 }), // Actual amount delivered
  referralCode: text("referral_code"), // Referral code used (if any)
  currentMessage: text("current_message"),
  preset: text("preset"), // 'fast', 'balanced', 'max_privacy', 'stealth'
  hopConfig: json("hop_config"), // Stores the hop configuration used
  hopWallets: json("hop_wallets"), // Array of hop wallet public keys for checkpoint resume
  createdAt: timestamp("created_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
  failedAt: timestamp("failed_at"),
  errorMessage: text("error_message"),
});

// Individual hop events for audit trail
export const hopEvents = pgTable("hop_events", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: varchar("session_id").notNull(),
  hopNumber: integer("hop_number").notNull(),
  fromWallet: text("from_wallet").notNull(),
  toWallet: text("to_wallet").notNull(),
  amount: numeric("amount", { precision: 18, scale: 9 }).notNull(),
  signature: text("signature"),
  delayMs: integer("delay_ms"),
  status: text("status").notNull(), // 'pending', 'sent', 'confirmed', 'failed'
  createdAt: timestamp("created_at").defaultNow().notNull(),
  confirmedAt: timestamp("confirmed_at"),
  errorMessage: text("error_message"),
});

// Mix history for completed transactions
export const mixHistory = pgTable("mix_history", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  sessionId: varchar("session_id").notNull(),
  walletPublicKey: text("wallet_public_key").notNull(),
  grossAmount: numeric("gross_amount", { precision: 18, scale: 9 }).notNull(),
  platformFee: numeric("platform_fee", { precision: 18, scale: 9 }).notNull(),
  networkFees: numeric("network_fees", { precision: 18, scale: 9 }).notNull(),
  totalFees: numeric("total_fees", { precision: 18, scale: 9 }).notNull(),
  netAmount: numeric("net_amount", { precision: 18, scale: 9 }).notNull(),
  solSent: numeric("sol_sent", { precision: 18, scale: 9 }).notNull(),
  solReceived: numeric("zec_received", { precision: 18, scale: 9 }), // Legacy column name, now stores final SOL received
  hopCount: integer("hop_count").notNull(),
  preset: text("preset"),
  privacyScore: integer("privacy_score"),
  payoutAddress: text("payout_address"),
  status: text("status").notNull(), // 'completed', 'failed', 'refunded'
  createdAt: timestamp("created_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});

// Fee ledger for transparency
export const feeLedger = pgTable("fee_ledger", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: varchar("session_id"),
  userId: varchar("user_id").notNull(),
  feeType: text("fee_type").notNull(), // 'platform', 'network', 'hop', 'discount'
  amount: numeric("amount", { precision: 18, scale: 9 }).notNull(),
  currency: text("currency").notNull(), // 'SOL'
  description: text("description"),
  allocation: text("allocation"), // 'development', 'security', 'operations'
  signature: text("signature"), // Transaction signature if applicable
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Exchange rate tracking
export const exchangeRates = pgTable("exchange_rates", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  fromCurrency: text("from_currency").notNull(),
  toCurrency: text("to_currency").notNull(),
  rate: numeric("rate", { precision: 18, scale: 9 }).notNull(),
  provider: text("provider").notNull(), // 'changenow', 'manual'
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Gas price snapshots for optimization
export const gasSnapshots = pgTable("gas_snapshots", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  network: text("network").notNull(), // 'solana'
  averageFee: numeric("average_fee", { precision: 18, scale: 9 }).notNull(),
  medianFee: numeric("median_fee", { precision: 18, scale: 9 }).notNull(),
  fastFee: numeric("fast_fee", { precision: 18, scale: 9 }).notNull(),
  recommendation: text("recommendation"), // 'good', 'average', 'busy', 'wait'
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Dynamic pricing tiers
export const pricingTiers = pgTable("pricing_tiers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  minAmount: numeric("min_amount", { precision: 18, scale: 9 }).notNull(),
  maxAmount: numeric("max_amount", { precision: 18, scale: 9 }),
  feePercent: numeric("fee_percent", { precision: 5, scale: 2 }).notNull(),
  description: text("description"),
  isActive: integer("is_active").default(1).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// User rewards and loyalty
export const userRewards = pgTable("user_rewards", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().unique(),
  totalMixes: integer("total_mixes").default(0).notNull(),
  totalVolume: numeric("total_volume", { precision: 18, scale: 9 }).default('0').notNull(),
  lifetimeFees: numeric("lifetime_fees", { precision: 18, scale: 9 }).default('0').notNull(),
  loyaltyTier: text("loyalty_tier").default('bronze').notNull(), // 'bronze', 'silver', 'gold', 'platinum'
  feeDiscountPercent: numeric("fee_discount_percent", { precision: 5, scale: 2 }).default('0').notNull(),
  creditsBalance: numeric("credits_balance", { precision: 18, scale: 9 }).default('0').notNull(),
  firstMixCompleted: integer("first_mix_completed").default(0).notNull(),
  lastMixAt: timestamp("last_mix_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Referral system
export const referralCodes = pgTable("referral_codes", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  code: text("code").notNull().unique(),
  discountPercent: numeric("discount_percent", { precision: 5, scale: 2 }).default('10').notNull(),
  referrerRewardPercent: numeric("referrer_reward_percent", { precision: 5, scale: 2 }).default('0.5').notNull(),
  usageCount: integer("usage_count").default(0).notNull(),
  maxUsages: integer("max_usages"),
  expiresAt: timestamp("expires_at"),
  isActive: integer("is_active").default(1).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Referral usage tracking
export const referralUsages = pgTable("referral_usages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  referralCodeId: varchar("referral_code_id").notNull(),
  referrerId: varchar("referrer_id").notNull(),
  refereeId: varchar("referee_id").notNull(),
  sessionId: varchar("session_id"),
  discountAmount: numeric("discount_amount", { precision: 18, scale: 9 }).notNull(),
  referrerRewardAmount: numeric("referrer_reward_amount", { precision: 18, scale: 9 }).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// User settings for preferences
export const userSettings = pgTable("user_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().unique(),
  theme: text("theme").default('dark').notNull(), // 'light', 'dark'
  defaultPreset: text("default_preset").default('balanced'), // 'fast', 'balanced', 'max_privacy', 'stealth'
  autoBurnEnabled: integer("auto_burn_enabled").default(0).notNull(),
  notifications: integer("notifications").default(1).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const insertUserSchema = createInsertSchema(users)
  .pick({
    username: true,
    password: true,
  })
  .extend({
    username: z.string().min(3).max(30).trim().toLowerCase(),
    password: z.string().regex(/^\d{4,6}$/, 'PIN must be 4-6 digits'),
  });

export const insertWalletSchema = createInsertSchema(wallets)
  .omit({
    id: true,
    createdAt: true,
  })
  .extend({
    publicKey: z.string(),
    encryptedPrivateKey: z.string(),
    label: z.string().optional(),
  });

export const insertMixerSessionSchema = createInsertSchema(mixerSessions).omit({
  id: true,
  createdAt: true,
  completedAt: true,
  failedAt: true,
});

export const insertHopEventSchema = createInsertSchema(hopEvents).omit({
  id: true,
  createdAt: true,
  confirmedAt: true,
});

export const insertMixHistorySchema = createInsertSchema(mixHistory).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export const insertFeeLedgerSchema = createInsertSchema(feeLedger).omit({
  id: true,
  createdAt: true,
});

export const insertExchangeRateSchema = createInsertSchema(exchangeRates).omit({
  id: true,
  createdAt: true,
});

export const insertGasSnapshotSchema = createInsertSchema(gasSnapshots).omit({
  id: true,
  createdAt: true,
});

export const insertPricingTierSchema = createInsertSchema(pricingTiers).omit({
  id: true,
  createdAt: true,
});

export const insertUserRewardsSchema = createInsertSchema(userRewards).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertReferralCodeSchema = createInsertSchema(referralCodes).omit({
  id: true,
  createdAt: true,
});

export const insertReferralUsageSchema = createInsertSchema(referralUsages).omit({
  id: true,
  createdAt: true,
});

export const insertUserSettingsSchema = createInsertSchema(userSettings).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// ZK Commitment tree for privacy mixer
export const zkCommitments = pgTable("zk_commitments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  commitment: text("commitment").notNull().unique(), // Poseidon hash in hex
  leafIndex: integer("leaf_index").notNull(),
  amount: numeric("amount", { precision: 18, scale: 9 }).notNull(), // Amount in SOL (encrypted in commitment)
  status: text("status").notNull().default('active'), // 'active', 'withdrawn', 'expired'
  createdAt: timestamp("created_at").defaultNow().notNull(),
  withdrawnAt: timestamp("withdrawn_at"),
});

// Nullifier registry for double-spend prevention
export const zkNullifiers = pgTable("zk_nullifiers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  nullifierHash: text("nullifier_hash").notNull().unique(), // Poseidon hash in hex
  commitmentId: varchar("commitment_id"), // Reference to original commitment
  recipient: text("recipient"), // Withdrawal destination
  txSignature: text("tx_signature"), // Solana transaction signature
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Merkle tree snapshots for efficient root verification
export const zkMerkleRoots = pgTable("zk_merkle_roots", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  root: text("root").notNull().unique(), // Merkle root in hex
  leafCount: integer("leaf_count").notNull(),
  isActive: integer("is_active").default(1).notNull(), // 1 = current, 0 = historical
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Hop wallet recovery - encrypted backup for automatic fund recovery
export const hopWalletRecovery = pgTable("hop_wallet_recovery", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: text("session_id").notNull(), // Anonymous session ID
  mixSessionId: text("mix_session_id"), // Associated mixer session
  encryptedKeys: text("encrypted_keys").notNull(), // AES-256-CBC encrypted hop wallet keys (JSON array)
  hopCount: integer("hop_count").notNull(),
  status: text("status").notNull().default('pending'), // 'pending', 'recovered', 'expired'
  expiresAt: timestamp("expires_at").notNull(), // 24-hour recovery window
  createdAt: timestamp("created_at").defaultNow().notNull(),
  recoveredAt: timestamp("recovered_at"),
});

export const insertHopWalletRecoverySchema = createInsertSchema(hopWalletRecovery).omit({
  id: true,
  createdAt: true,
  recoveredAt: true,
});

// Privacy Pool Deposits - tracks deposits into the ZK pool for integrated mixer
export const zkPoolDeposits = pgTable("zk_pool_deposits", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  sessionId: text("session_id").notNull(), // Anonymous session ID
  mixerSessionId: varchar("mixer_session_id"), // Link to mixerSessions for integrated flow
  tier: text("tier").notNull(), // 'TIER_0_1', 'TIER_0_5', 'TIER_1_0', 'TIER_5_0'
  amountSol: numeric("amount_sol", { precision: 18, scale: 9 }).notNull(),
  commitmentHash: text("commitment_hash").notNull().unique(), // Poseidon commitment
  encryptedNote: text("encrypted_note").notNull(), // AES encrypted deposit note for recovery
  depositTxSignature: text("deposit_tx_signature"), // Solana tx when deposit confirmed
  status: text("status").notNull().default('pending'), // 'pending', 'deposited', 'queued', 'withdrawing', 'withdrawn', 'failed'
  anonymityDelay: integer("anonymity_delay").default(300).notNull(), // Seconds to wait before withdrawal (min 5 min)
  withdrawAfter: timestamp("withdraw_after"), // When withdrawal can be processed
  destinationAddress: text("destination_address"), // Final destination after multi-hop
  createdAt: timestamp("created_at").defaultNow().notNull(),
  depositedAt: timestamp("deposited_at"),
  withdrawnAt: timestamp("withdrawn_at"),
  errorMessage: text("error_message"),
});

// Privacy Pool Withdrawals - tracks withdrawal execution
export const zkPoolWithdrawals = pgTable("zk_pool_withdrawals", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  depositId: varchar("deposit_id").notNull(), // Reference to zkPoolDeposits
  sessionId: text("session_id").notNull(),
  nullifierHash: text("nullifier_hash").notNull().unique(), // For double-spend prevention
  recipientAddress: text("recipient_address").notNull(), // Hop wallet 0 address (not final destination)
  proofData: text("proof_data"), // JSON stringified Groth16 proof
  amountReceived: numeric("amount_received", { precision: 18, scale: 9 }), // After fees
  platformFee: numeric("platform_fee", { precision: 18, scale: 9 }),
  relayerFee: numeric("relayer_fee", { precision: 18, scale: 9 }),
  withdrawalTxSignature: text("withdrawal_tx_signature"),
  status: text("status").notNull().default('pending'), // 'pending', 'proving', 'broadcasting', 'confirmed', 'failed'
  createdAt: timestamp("created_at").defaultNow().notNull(),
  confirmedAt: timestamp("confirmed_at"),
  errorMessage: text("error_message"),
});

export const insertZkPoolDepositSchema = createInsertSchema(zkPoolDeposits).omit({
  id: true,
  createdAt: true,
  depositedAt: true,
  withdrawnAt: true,
});

export const insertZkPoolWithdrawalSchema = createInsertSchema(zkPoolWithdrawals).omit({
  id: true,
  createdAt: true,
  confirmedAt: true,
});

export const insertZkCommitmentSchema = createInsertSchema(zkCommitments).omit({
  id: true,
  createdAt: true,
  withdrawnAt: true,
});

export const insertZkNullifierSchema = createInsertSchema(zkNullifiers).omit({
  id: true,
  createdAt: true,
});

export const insertZkMerkleRootSchema = createInsertSchema(zkMerkleRoots).omit({
  id: true,
  createdAt: true,
});

// Types
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertWallet = z.infer<typeof insertWalletSchema>;
export type Wallet = typeof wallets.$inferSelect;
export type InsertMixerSession = z.infer<typeof insertMixerSessionSchema>;
export type MixerSession = typeof mixerSessions.$inferSelect;
export type InsertHopEvent = z.infer<typeof insertHopEventSchema>;
export type HopEvent = typeof hopEvents.$inferSelect;
export type InsertMixHistory = z.infer<typeof insertMixHistorySchema>;
export type MixHistory = typeof mixHistory.$inferSelect;
export type InsertFeeLedger = z.infer<typeof insertFeeLedgerSchema>;
export type FeeLedger = typeof feeLedger.$inferSelect;
export type InsertExchangeRate = z.infer<typeof insertExchangeRateSchema>;
export type ExchangeRate = typeof exchangeRates.$inferSelect;
export type InsertGasSnapshot = z.infer<typeof insertGasSnapshotSchema>;
export type GasSnapshot = typeof gasSnapshots.$inferSelect;
export type InsertPricingTier = z.infer<typeof insertPricingTierSchema>;
export type PricingTier = typeof pricingTiers.$inferSelect;
export type InsertUserRewards = z.infer<typeof insertUserRewardsSchema>;
export type UserRewards = typeof userRewards.$inferSelect;
export type InsertReferralCode = z.infer<typeof insertReferralCodeSchema>;
export type ReferralCode = typeof referralCodes.$inferSelect;
export type InsertReferralUsage = z.infer<typeof insertReferralUsageSchema>;
export type ReferralUsage = typeof referralUsages.$inferSelect;
export type InsertUserSettings = z.infer<typeof insertUserSettingsSchema>;
export type UserSettings = typeof userSettings.$inferSelect;
export type InsertZkCommitment = z.infer<typeof insertZkCommitmentSchema>;
export type ZkCommitment = typeof zkCommitments.$inferSelect;
export type InsertZkNullifier = z.infer<typeof insertZkNullifierSchema>;
export type ZkNullifier = typeof zkNullifiers.$inferSelect;
export type InsertZkMerkleRoot = z.infer<typeof insertZkMerkleRootSchema>;
export type ZkMerkleRoot = typeof zkMerkleRoots.$inferSelect;
export type InsertHopWalletRecovery = z.infer<typeof insertHopWalletRecoverySchema>;
export type HopWalletRecovery = typeof hopWalletRecovery.$inferSelect;
export type InsertZkPoolDeposit = z.infer<typeof insertZkPoolDepositSchema>;
export type ZkPoolDeposit = typeof zkPoolDeposits.$inferSelect;
export type InsertZkPoolWithdrawal = z.infer<typeof insertZkPoolWithdrawalSchema>;
export type ZkPoolWithdrawal = typeof zkPoolWithdrawals.$inferSelect;
