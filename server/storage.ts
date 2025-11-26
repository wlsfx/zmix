import { 
  type User, type InsertUser, type Wallet, type InsertWallet, 
  type MixerSession, type InsertMixerSession,
  type HopEvent, type InsertHopEvent,
  type MixHistory, type InsertMixHistory,
  type FeeLedger, type InsertFeeLedger,
  type ExchangeRate, type InsertExchangeRate,
  type GasSnapshot, type InsertGasSnapshot,
  type PricingTier, type InsertPricingTier,
  type UserRewards, type InsertUserRewards,
  type ReferralCode, type InsertReferralCode,
  type ReferralUsage, type InsertReferralUsage,
  type UserSettings, type InsertUserSettings,
  users, wallets, mixerSessions, hopEvents, mixHistory, feeLedger,
  exchangeRates, gasSnapshots, pricingTiers, userRewards,
  referralCodes, referralUsages, userSettings
} from "@shared/schema";
import { randomUUID } from "crypto";
import { db } from "./db";
import { eq, and, or, desc, asc, gte, lte, sql } from "drizzle-orm";

// modify the interface with any CRUD methods
// you might need

export interface IStorage {
  // User operations
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Wallet operations
  getWallet(id: string): Promise<Wallet | undefined>;
  getWalletByPublicKey(publicKey: string): Promise<Wallet | undefined>;
  getUserWallets(userId: string): Promise<Wallet[]>;
  createWallet(wallet: InsertWallet): Promise<Wallet>;
  updateWallet(id: string, updates: Partial<Wallet>): Promise<Wallet | undefined>;
  deleteWallet(id: string): Promise<boolean>;
  
  // Mixer session operations
  createMixerSession(session: InsertMixerSession): Promise<MixerSession>;
  getMixerSession(id: string): Promise<MixerSession | undefined>;
  getUserActiveMixerSession(userId: string): Promise<MixerSession | undefined>;
  getWalletActiveMixerSession(walletId: string): Promise<MixerSession | undefined>;
  getUserMixerSessions(userId: string): Promise<MixerSession[]>;
  updateMixerSessionStatus(id: string, status: string, message?: string): Promise<MixerSession | undefined>;
  updateMixerSessionCheckpoint(id: string, data: { status?: string; message?: string; hopWallets?: any; hopConfig?: any }): Promise<MixerSession | undefined>;
  completeMixerSession(id: string, data: { platformFee: string; netAmount: string; finalAmount: string }): Promise<MixerSession | undefined>;
  failMixerSession(id: string, errorMessage: string): Promise<MixerSession | undefined>;
  
  // Hop event operations
  createHopEvent(event: InsertHopEvent): Promise<HopEvent>;
  getSessionHopEvents(sessionId: string): Promise<HopEvent[]>;
  
  // Mix history operations
  createMixHistory(history: InsertMixHistory): Promise<MixHistory>;
  getUserMixHistory(userId: string, limit?: number, offset?: number): Promise<{ items: MixHistory[]; total: number }>;
  
  // Fee ledger operations
  createFeeLedgerEntry(entry: InsertFeeLedger): Promise<FeeLedger>;
  getUserFees(userId: string): Promise<FeeLedger[]>;
  getSessionFees(sessionId: string): Promise<FeeLedger[]>;
  
  // Exchange rate operations
  createExchangeRate(rate: InsertExchangeRate): Promise<ExchangeRate>;
  getLatestExchangeRate(fromCurrency: string, toCurrency: string): Promise<ExchangeRate | undefined>;
  getExchangeRateHistory(fromCurrency: string, toCurrency: string, limit?: number): Promise<ExchangeRate[]>;
  
  // Gas snapshot operations
  createGasSnapshot(snapshot: InsertGasSnapshot): Promise<GasSnapshot>;
  getLatestGasSnapshot(network: string): Promise<GasSnapshot | undefined>;
  
  // Pricing tier operations
  createPricingTier(tier: InsertPricingTier): Promise<PricingTier>;
  getActivePricingTiers(): Promise<PricingTier[]>;
  getTierForAmount(amount: number): Promise<PricingTier | undefined>;
  
  // User rewards operations
  ensureUserRewards(userId: string): Promise<UserRewards>;
  getUserRewards(userId: string): Promise<UserRewards | undefined>;
  updateUserRewards(userId: string, updates: Partial<UserRewards>): Promise<UserRewards | undefined>;
  
  // Referral code operations
  createReferralCode(code: InsertReferralCode): Promise<ReferralCode>;
  getReferralCodeByCode(code: string): Promise<ReferralCode | undefined>;
  getUserReferralCodes(userId: string): Promise<ReferralCode[]>;
  incrementReferralUsage(codeId: string): Promise<ReferralCode | undefined>;
  
  // Referral usage operations
  createReferralUsage(usage: InsertReferralUsage): Promise<ReferralUsage>;
  getReferrerUsages(referrerId: string): Promise<ReferralUsage[]>;
  getReferralUsageByRefereeId(refereeId: string, referralCodeId: string): Promise<ReferralUsage | undefined>;
  incrementReferralCodeUsage(codeId: string): Promise<ReferralCode | undefined>;
  adjustUserCredits(userId: string, amount: string): Promise<UserRewards | undefined>;
  
  // User settings operations
  ensureUserSettings(userId: string): Promise<UserSettings>;
  getUserSettings(userId: string): Promise<UserSettings | undefined>;
  updateUserSettings(userId: string, updates: Partial<UserSettings>): Promise<UserSettings | undefined>;
}

export class MemStorage implements IStorage {
  private users: Map<string, User>;
  private wallets: Map<string, Wallet>;
  private mixerSessions: Map<string, MixerSession>;
  private hopEvents: Map<string, HopEvent>;
  private mixHistory: Map<string, MixHistory>;
  private feeLedger: Map<string, FeeLedger>;
  private exchangeRates: Map<string, ExchangeRate>;
  private gasSnapshots: Map<string, GasSnapshot>;
  private pricingTiers: Map<string, PricingTier>;
  private userRewards: Map<string, UserRewards>;
  private referralCodes: Map<string, ReferralCode>;
  private referralUsages: Map<string, ReferralUsage>;
  private userSettings: Map<string, UserSettings>;

  constructor() {
    this.users = new Map();
    this.wallets = new Map();
    this.mixerSessions = new Map();
    this.hopEvents = new Map();
    this.mixHistory = new Map();
    this.feeLedger = new Map();
    this.exchangeRates = new Map();
    this.gasSnapshots = new Map();
    this.pricingTiers = new Map();
    this.userRewards = new Map();
    this.referralCodes = new Map();
    this.referralUsages = new Map();
    this.userSettings = new Map();
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username,
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = randomUUID();
    const user: User = { ...insertUser, id };
    this.users.set(id, user);
    return user;
  }

  // Wallet operations
  async getWallet(id: string): Promise<Wallet | undefined> {
    return this.wallets.get(id);
  }

  async getWalletByPublicKey(publicKey: string): Promise<Wallet | undefined> {
    return Array.from(this.wallets.values()).find(
      (wallet) => wallet.publicKey === publicKey,
    );
  }

  async getUserWallets(userId: string): Promise<Wallet[]> {
    return Array.from(this.wallets.values()).filter(
      (wallet) => wallet.userId === userId && wallet.isBurned === 0,
    );
  }

  async createWallet(insertWallet: InsertWallet): Promise<Wallet> {
    const id = randomUUID();
    const wallet: Wallet = {
      ...insertWallet,
      id,
      label: insertWallet.label || null,
      createdAt: new Date(),
      txCount: insertWallet.txCount || 0,
      isBurned: insertWallet.isBurned || 0,
      autoBurn: insertWallet.autoBurn || 0,
    };
    this.wallets.set(id, wallet);
    return wallet;
  }

  async updateWallet(id: string, updates: Partial<Wallet>): Promise<Wallet | undefined> {
    const wallet = this.wallets.get(id);
    if (!wallet) return undefined;
    
    const updated = { ...wallet, ...updates };
    this.wallets.set(id, updated);
    return updated;
  }

  async deleteWallet(id: string): Promise<boolean> {
    return this.wallets.delete(id);
  }

  // Mixer session operations (SOL→SOL with fees)
  async createMixerSession(insertSession: InsertMixerSession): Promise<MixerSession> {
    const id = randomUUID();
    const session: MixerSession = {
      ...insertSession,
      id,
      destinationAddress: insertSession.destinationAddress || null,
      platformFee: insertSession.platformFee || null,
      netAmount: insertSession.netAmount || null,
      finalAmount: insertSession.finalAmount || null,
      referralCode: insertSession.referralCode || null,
      currentMessage: insertSession.currentMessage || null,
      preset: insertSession.preset || null,
      hopConfig: insertSession.hopConfig || null,
      hopWallets: insertSession.hopWallets || null,
      createdAt: new Date(),
      completedAt: null,
      failedAt: null,
      errorMessage: insertSession.errorMessage || null,
    };
    this.mixerSessions.set(id, session);
    return session;
  }

  async getMixerSession(id: string): Promise<MixerSession | undefined> {
    return this.mixerSessions.get(id);
  }

  async getUserActiveMixerSession(userId: string): Promise<MixerSession | undefined> {
    return Array.from(this.mixerSessions.values()).find(
      (session) => session.userId === userId && 
        !['completed', 'failed'].includes(session.status)
    );
  }

  async getWalletActiveMixerSession(walletId: string): Promise<MixerSession | undefined> {
    return Array.from(this.mixerSessions.values()).find(
      (session) => session.walletId === walletId && 
        !['completed', 'failed'].includes(session.status)
    );
  }

  async getUserMixerSessions(userId: string): Promise<MixerSession[]> {
    return Array.from(this.mixerSessions.values())
      .filter((session) => session.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async updateMixerSessionStatus(id: string, status: string, message?: string): Promise<MixerSession | undefined> {
    const session = this.mixerSessions.get(id);
    if (!session) return undefined;
    
    const updated = { 
      ...session, 
      status,
      currentMessage: message || session.currentMessage
    };
    this.mixerSessions.set(id, updated);
    return updated;
  }

  async updateMixerSessionCheckpoint(id: string, data: { status?: string; message?: string; hopWallets?: any; hopConfig?: any }): Promise<MixerSession | undefined> {
    const session = this.mixerSessions.get(id);
    if (!session) return undefined;
    
    const updated = {
      ...session,
      ...(data.status && { status: data.status }),
      ...(data.message && { currentMessage: data.message }),
      ...(data.hopWallets && { hopWallets: data.hopWallets }),
      ...(data.hopConfig && { hopConfig: data.hopConfig }),
    };
    this.mixerSessions.set(id, updated);
    return updated;
  }

  async completeMixerSession(id: string, data: { platformFee: string; netAmount: string; finalAmount: string }): Promise<MixerSession | undefined> {
    const session = this.mixerSessions.get(id);
    if (!session) return undefined;
    
    const updated = {
      ...session,
      status: 'completed',
      platformFee: data.platformFee,
      netAmount: data.netAmount,
      finalAmount: data.finalAmount,
      completedAt: new Date(),
    };
    this.mixerSessions.set(id, updated);
    return updated;
  }

  async failMixerSession(id: string, errorMessage: string): Promise<MixerSession | undefined> {
    const session = this.mixerSessions.get(id);
    if (!session) return undefined;
    
    const updated = {
      ...session,
      status: 'failed',
      errorMessage,
      failedAt: new Date(),
    };
    this.mixerSessions.set(id, updated);
    return updated;
  }

  // Hop event operations
  async createHopEvent(insertEvent: InsertHopEvent): Promise<HopEvent> {
    const id = randomUUID();
    const event: HopEvent = {
      ...insertEvent,
      id,
      signature: insertEvent.signature || null,
      delayMs: insertEvent.delayMs || null,
      createdAt: new Date(),
      confirmedAt: null,
      errorMessage: insertEvent.errorMessage || null,
    };
    this.hopEvents.set(id, event);
    return event;
  }

  async getSessionHopEvents(sessionId: string): Promise<HopEvent[]> {
    return Array.from(this.hopEvents.values())
      .filter((event) => event.sessionId === sessionId)
      .sort((a, b) => a.hopNumber - b.hopNumber);
  }

  // Mix history operations
  async createMixHistory(insertHistory: InsertMixHistory): Promise<MixHistory> {
    const id = randomUUID();
    const history: MixHistory = {
      ...insertHistory,
      id,
      solReceived: insertHistory.solReceived || null,
      preset: insertHistory.preset || null,
      privacyScore: insertHistory.privacyScore || null,
      payoutAddress: insertHistory.payoutAddress || null,
      createdAt: new Date(),
      completedAt: null,
    };
    this.mixHistory.set(id, history);
    return history;
  }

  async getUserMixHistory(userId: string, limit: number = 50, offset: number = 0): Promise<{ items: MixHistory[]; total: number }> {
    const allHistory = Array.from(this.mixHistory.values())
      .filter((history) => history.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    
    const items = allHistory.slice(offset, offset + limit);
    return { items, total: allHistory.length };
  }

  // Fee ledger operations
  async createFeeLedgerEntry(insertEntry: InsertFeeLedger): Promise<FeeLedger> {
    const id = randomUUID();
    const entry: FeeLedger = {
      ...insertEntry,
      id,
      sessionId: insertEntry.sessionId || null,
      description: insertEntry.description || null,
      allocation: insertEntry.allocation || null,
      signature: insertEntry.signature || null,
      createdAt: new Date(),
    };
    this.feeLedger.set(id, entry);
    return entry;
  }

  async getUserFees(userId: string): Promise<FeeLedger[]> {
    return Array.from(this.feeLedger.values())
      .filter((fee) => fee.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getSessionFees(sessionId: string): Promise<FeeLedger[]> {
    return Array.from(this.feeLedger.values())
      .filter((fee) => fee.sessionId === sessionId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  // Exchange rate operations
  async createExchangeRate(insertRate: InsertExchangeRate): Promise<ExchangeRate> {
    const id = randomUUID();
    const rate: ExchangeRate = {
      ...insertRate,
      id,
      createdAt: new Date(),
    };
    this.exchangeRates.set(id, rate);
    return rate;
  }

  async getLatestExchangeRate(fromCurrency: string, toCurrency: string): Promise<ExchangeRate | undefined> {
    const rates = Array.from(this.exchangeRates.values())
      .filter((rate) => rate.fromCurrency === fromCurrency && rate.toCurrency === toCurrency)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    return rates[0];
  }

  async getExchangeRateHistory(fromCurrency: string, toCurrency: string, limit: number = 100): Promise<ExchangeRate[]> {
    return Array.from(this.exchangeRates.values())
      .filter((rate) => rate.fromCurrency === fromCurrency && rate.toCurrency === toCurrency)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit);
  }

  // Gas snapshot operations
  async createGasSnapshot(insertSnapshot: InsertGasSnapshot): Promise<GasSnapshot> {
    const id = randomUUID();
    const snapshot: GasSnapshot = {
      ...insertSnapshot,
      id,
      recommendation: insertSnapshot.recommendation || null,
      createdAt: new Date(),
    };
    this.gasSnapshots.set(id, snapshot);
    return snapshot;
  }

  async getLatestGasSnapshot(network: string): Promise<GasSnapshot | undefined> {
    const snapshots = Array.from(this.gasSnapshots.values())
      .filter((snapshot) => snapshot.network === network)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    return snapshots[0];
  }

  // Pricing tier operations
  async createPricingTier(insertTier: InsertPricingTier): Promise<PricingTier> {
    const id = randomUUID();
    const tier: PricingTier = {
      ...insertTier,
      id,
      maxAmount: insertTier.maxAmount || null,
      description: insertTier.description || null,
      isActive: insertTier.isActive ?? 1,
      createdAt: new Date(),
    };
    this.pricingTiers.set(id, tier);
    return tier;
  }

  async getActivePricingTiers(): Promise<PricingTier[]> {
    return Array.from(this.pricingTiers.values())
      .filter((tier) => tier.isActive === 1)
      .sort((a, b) => parseFloat(a.minAmount) - parseFloat(b.minAmount));
  }

  async getTierForAmount(amount: number): Promise<PricingTier | undefined> {
    const tiers = await this.getActivePricingTiers();
    return tiers.find((tier) => 
      amount >= parseFloat(tier.minAmount) && (tier.maxAmount === null || amount <= parseFloat(tier.maxAmount))
    );
  }

  // User rewards operations
  async ensureUserRewards(userId: string): Promise<UserRewards> {
    const existing = Array.from(this.userRewards.values()).find(
      (reward) => reward.userId === userId
    );
    if (existing) return existing;

    const id = randomUUID();
    const rewards: UserRewards = {
      id,
      userId,
      totalMixes: 0,
      totalVolume: '0',
      lifetimeFees: '0',
      loyaltyTier: 'bronze',
      feeDiscountPercent: '0',
      creditsBalance: '0',
      firstMixCompleted: 0,
      lastMixAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.userRewards.set(id, rewards);
    return rewards;
  }

  async getUserRewards(userId: string): Promise<UserRewards | undefined> {
    return Array.from(this.userRewards.values()).find(
      (reward) => reward.userId === userId
    );
  }

  async updateUserRewards(userId: string, updates: Partial<UserRewards>): Promise<UserRewards | undefined> {
    const rewards = await this.getUserRewards(userId);
    if (!rewards) return undefined;

    const updated = {
      ...rewards,
      ...updates,
      updatedAt: new Date(),
    };
    this.userRewards.set(rewards.id, updated);
    return updated;
  }

  // Referral code operations
  async createReferralCode(insertCode: InsertReferralCode): Promise<ReferralCode> {
    const id = randomUUID();
    const code: ReferralCode = {
      ...insertCode,
      id,
      discountPercent: insertCode.discountPercent ?? '10',
      referrerRewardPercent: insertCode.referrerRewardPercent ?? '0.5',
      usageCount: insertCode.usageCount ?? 0,
      maxUsages: insertCode.maxUsages || null,
      expiresAt: insertCode.expiresAt || null,
      isActive: insertCode.isActive ?? 1,
      createdAt: new Date(),
    };
    this.referralCodes.set(id, code);
    return code;
  }

  async getReferralCodeByCode(code: string): Promise<ReferralCode | undefined> {
    return Array.from(this.referralCodes.values()).find(
      (ref) => ref.code === code
    );
  }

  async getUserReferralCodes(userId: string): Promise<ReferralCode[]> {
    return Array.from(this.referralCodes.values())
      .filter((code) => code.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async incrementReferralUsage(codeId: string): Promise<ReferralCode | undefined> {
    const code = this.referralCodes.get(codeId);
    if (!code) return undefined;

    const updated = {
      ...code,
      usageCount: code.usageCount + 1,
    };
    this.referralCodes.set(codeId, updated);
    return updated;
  }

  // Referral usage operations
  async createReferralUsage(insertUsage: InsertReferralUsage): Promise<ReferralUsage> {
    const id = randomUUID();
    const usage: ReferralUsage = {
      ...insertUsage,
      id,
      sessionId: insertUsage.sessionId || null,
      createdAt: new Date(),
    };
    this.referralUsages.set(id, usage);
    return usage;
  }

  async getReferrerUsages(referrerId: string): Promise<ReferralUsage[]> {
    return Array.from(this.referralUsages.values())
      .filter((usage) => usage.referrerId === referrerId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getReferralUsageByRefereeId(refereeId: string, referralCodeId: string): Promise<ReferralUsage | undefined> {
    return Array.from(this.referralUsages.values())
      .find((usage) => usage.refereeId === refereeId && usage.referralCodeId === referralCodeId);
  }

  async incrementReferralCodeUsage(codeId: string): Promise<ReferralCode | undefined> {
    const code = this.referralCodes.get(codeId);
    if (code) {
      const updated = {
        ...code,
        usageCount: code.usageCount + 1,
      };
      this.referralCodes.set(codeId, updated);
      return updated;
    }
    return undefined;
  }

  async adjustUserCredits(userId: string, amount: string): Promise<UserRewards | undefined> {
    const rewards = Array.from(this.userRewards.values()).find((r) => r.userId === userId);
    if (rewards) {
      const currentBalance = parseFloat(rewards.creditsBalance);
      const adjustment = parseFloat(amount);
      const newBalance = Math.max(currentBalance + adjustment, 0); // Prevent negative balance
      
      const updated = {
        ...rewards,
        creditsBalance: newBalance.toFixed(9),
        updatedAt: new Date(),
      };
      this.userRewards.set(rewards.id, updated);
      return updated;
    }
    return undefined;
  }

  // User settings operations
  async ensureUserSettings(userId: string): Promise<UserSettings> {
    const existing = Array.from(this.userSettings.values()).find(
      (settings) => settings.userId === userId
    );
    if (existing) return existing;

    const id = randomUUID();
    const settings: UserSettings = {
      id,
      userId,
      theme: 'dark',
      defaultPreset: 'balanced',
      autoBurnEnabled: 0,
      notifications: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.userSettings.set(id, settings);
    return settings;
  }

  async getUserSettings(userId: string): Promise<UserSettings | undefined> {
    return Array.from(this.userSettings.values()).find(
      (settings) => settings.userId === userId
    );
  }

  async updateUserSettings(userId: string, updates: Partial<UserSettings>): Promise<UserSettings | undefined> {
    const settings = await this.getUserSettings(userId);
    if (!settings) return undefined;

    const updated = {
      ...settings,
      ...updates,
      updatedAt: new Date(),
    };
    this.userSettings.set(settings.id, updated);
    return updated;
  }
}

export class DbStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return result[0];
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const result = await db.select().from(users).where(eq(users.username, username)).limit(1);
    return result[0];
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const result = await db.insert(users).values(insertUser).returning();
    return result[0];
  }

  // Wallet operations
  async getWallet(id: string): Promise<Wallet | undefined> {
    const result = await db.select().from(wallets).where(eq(wallets.id, id)).limit(1);
    return result[0];
  }

  async getWalletByPublicKey(publicKey: string): Promise<Wallet | undefined> {
    const result = await db.select().from(wallets).where(eq(wallets.publicKey, publicKey)).limit(1);
    return result[0];
  }

  async getUserWallets(userId: string): Promise<Wallet[]> {
    return await db.select().from(wallets)
      .where(and(
        eq(wallets.userId, userId),
        eq(wallets.isBurned, 0)
      ));
  }

  async createWallet(insertWallet: InsertWallet): Promise<Wallet> {
    const result = await db.insert(wallets).values(insertWallet).returning();
    return result[0];
  }

  async updateWallet(id: string, updates: Partial<Wallet>): Promise<Wallet | undefined> {
    // Whitelist allowed update fields to prevent undefined/NULL assignments
    const allowedUpdates: Partial<typeof wallets.$inferInsert> = {};
    if (updates.label !== undefined) allowedUpdates.label = updates.label;
    if (updates.txCount !== undefined) allowedUpdates.txCount = updates.txCount;
    if (updates.isBurned !== undefined) allowedUpdates.isBurned = updates.isBurned;
    if (updates.autoBurn !== undefined) allowedUpdates.autoBurn = updates.autoBurn;
    
    const result = await db.update(wallets).set(allowedUpdates).where(eq(wallets.id, id)).returning();
    return result[0];
  }

  async deleteWallet(id: string): Promise<boolean> {
    const result = await db.delete(wallets).where(eq(wallets.id, id)).returning();
    return result.length > 0;
  }

  // Mixer session operations
  async createMixerSession(insertSession: InsertMixerSession): Promise<MixerSession> {
    const result = await db.insert(mixerSessions).values(insertSession).returning();
    return result[0];
  }

  async getMixerSession(id: string): Promise<MixerSession | undefined> {
    const result = await db.select().from(mixerSessions).where(eq(mixerSessions.id, id)).limit(1);
    return result[0];
  }

  async getUserActiveMixerSession(userId: string): Promise<MixerSession | undefined> {
    const result = await db.select().from(mixerSessions)
      .where(and(
        eq(mixerSessions.userId, userId),
        sql`${mixerSessions.status} NOT IN ('completed', 'failed')`
      ))
      .limit(1);
    return result[0];
  }

  async getWalletActiveMixerSession(walletId: string): Promise<MixerSession | undefined> {
    const result = await db.select().from(mixerSessions)
      .where(and(
        eq(mixerSessions.walletId, walletId),
        sql`${mixerSessions.status} NOT IN ('completed', 'failed')`
      ))
      .limit(1);
    return result[0];
  }

  async getUserMixerSessions(userId: string): Promise<MixerSession[]> {
    return await db.select().from(mixerSessions)
      .where(eq(mixerSessions.userId, userId))
      .orderBy(desc(mixerSessions.createdAt));
  }

  async updateMixerSessionStatus(id: string, status: string, message?: string): Promise<MixerSession | undefined> {
    const allowedUpdates: Partial<typeof mixerSessions.$inferInsert> = { status };
    if (message !== undefined) allowedUpdates.currentMessage = message;
    
    const result = await db.update(mixerSessions)
      .set(allowedUpdates)
      .where(eq(mixerSessions.id, id))
      .returning();
    return result[0];
  }

  async updateMixerSessionCheckpoint(id: string, data: { status?: string; message?: string; hopWallets?: any; hopConfig?: any }): Promise<MixerSession | undefined> {
    const allowedUpdates: Partial<typeof mixerSessions.$inferInsert> = {};
    if (data.status !== undefined) allowedUpdates.status = data.status;
    if (data.message !== undefined) allowedUpdates.currentMessage = data.message;
    if (data.hopWallets !== undefined) allowedUpdates.hopWallets = data.hopWallets;
    if (data.hopConfig !== undefined) allowedUpdates.hopConfig = data.hopConfig;
    
    const result = await db.update(mixerSessions)
      .set(allowedUpdates)
      .where(eq(mixerSessions.id, id))
      .returning();
    return result[0];
  }

  async completeMixerSession(id: string, data: { platformFee: string; netAmount: string; finalAmount: string }): Promise<MixerSession | undefined> {
    const result = await db.update(mixerSessions)
      .set({
        status: 'completed',
        platformFee: data.platformFee,
        netAmount: data.netAmount,
        finalAmount: data.finalAmount,
        completedAt: new Date(),
      })
      .where(eq(mixerSessions.id, id))
      .returning();
    return result[0];
  }

  async failMixerSession(id: string, errorMessage: string): Promise<MixerSession | undefined> {
    const result = await db.update(mixerSessions)
      .set({
        status: 'failed',
        errorMessage,
        failedAt: new Date(),
      })
      .where(eq(mixerSessions.id, id))
      .returning();
    return result[0];
  }

  // Hop event operations
  async createHopEvent(insertEvent: InsertHopEvent): Promise<HopEvent> {
    const result = await db.insert(hopEvents).values(insertEvent).returning();
    return result[0];
  }

  async getSessionHopEvents(sessionId: string): Promise<HopEvent[]> {
    return await db.select().from(hopEvents)
      .where(eq(hopEvents.sessionId, sessionId))
      .orderBy(asc(hopEvents.hopNumber));
  }

  // Mix history operations
  async createMixHistory(insertHistory: InsertMixHistory): Promise<MixHistory> {
    const result = await db.insert(mixHistory).values(insertHistory).returning();
    return result[0];
  }

  async getUserMixHistory(userId: string, limit: number = 50, offset: number = 0): Promise<{ items: MixHistory[]; total: number }> {
    const items = await db.select().from(mixHistory)
      .where(eq(mixHistory.userId, userId))
      .orderBy(desc(mixHistory.createdAt))
      .limit(limit)
      .offset(offset);

    const totalResult = await db.select({ count: sql<number>`count(*)` })
      .from(mixHistory)
      .where(eq(mixHistory.userId, userId));
    
    const total = Number(totalResult[0]?.count || 0);
    return { items, total };
  }

  // Fee ledger operations
  async createFeeLedgerEntry(insertEntry: InsertFeeLedger): Promise<FeeLedger> {
    const result = await db.insert(feeLedger).values(insertEntry).returning();
    return result[0];
  }

  async getUserFees(userId: string): Promise<FeeLedger[]> {
    return await db.select().from(feeLedger)
      .where(eq(feeLedger.userId, userId))
      .orderBy(desc(feeLedger.createdAt));
  }

  async getSessionFees(sessionId: string): Promise<FeeLedger[]> {
    return await db.select().from(feeLedger)
      .where(eq(feeLedger.sessionId, sessionId))
      .orderBy(desc(feeLedger.createdAt));
  }

  // Exchange rate operations
  async createExchangeRate(insertRate: InsertExchangeRate): Promise<ExchangeRate> {
    const result = await db.insert(exchangeRates).values(insertRate).returning();
    return result[0];
  }

  async getLatestExchangeRate(fromCurrency: string, toCurrency: string): Promise<ExchangeRate | undefined> {
    const result = await db.select().from(exchangeRates)
      .where(and(
        eq(exchangeRates.fromCurrency, fromCurrency),
        eq(exchangeRates.toCurrency, toCurrency)
      ))
      .orderBy(desc(exchangeRates.createdAt))
      .limit(1);
    return result[0];
  }

  async getExchangeRateHistory(fromCurrency: string, toCurrency: string, limit: number = 100): Promise<ExchangeRate[]> {
    return await db.select().from(exchangeRates)
      .where(and(
        eq(exchangeRates.fromCurrency, fromCurrency),
        eq(exchangeRates.toCurrency, toCurrency)
      ))
      .orderBy(desc(exchangeRates.createdAt))
      .limit(limit);
  }

  // Gas snapshot operations
  async createGasSnapshot(insertSnapshot: InsertGasSnapshot): Promise<GasSnapshot> {
    const result = await db.insert(gasSnapshots).values(insertSnapshot).returning();
    return result[0];
  }

  async getLatestGasSnapshot(network: string): Promise<GasSnapshot | undefined> {
    const result = await db.select().from(gasSnapshots)
      .where(eq(gasSnapshots.network, network))
      .orderBy(desc(gasSnapshots.createdAt))
      .limit(1);
    return result[0];
  }

  // Pricing tier operations
  async createPricingTier(insertTier: InsertPricingTier): Promise<PricingTier> {
    const result = await db.insert(pricingTiers).values(insertTier).returning();
    return result[0];
  }

  async getActivePricingTiers(): Promise<PricingTier[]> {
    return await db.select().from(pricingTiers)
      .where(eq(pricingTiers.isActive, 1))
      .orderBy(asc(pricingTiers.minAmount));
  }

  async getTierForAmount(amount: number): Promise<PricingTier | undefined> {
    const result = await db.select().from(pricingTiers)
      .where(and(
        eq(pricingTiers.isActive, 1),
        sql`CAST(${pricingTiers.minAmount} AS NUMERIC) <= ${amount}`,
        or(
          sql`${pricingTiers.maxAmount} IS NULL`,
          sql`CAST(${pricingTiers.maxAmount} AS NUMERIC) >= ${amount}`
        )
      ))
      .limit(1);
    return result[0];
  }

  // User rewards operations
  async ensureUserRewards(userId: string): Promise<UserRewards> {
    const existing = await db.select().from(userRewards)
      .where(eq(userRewards.userId, userId))
      .limit(1);
    
    if (existing[0]) return existing[0];

    const result = await db.insert(userRewards).values({
      userId,
      totalMixes: 0,
      totalVolume: '0',
      lifetimeFees: '0',
      loyaltyTier: 'bronze',
      feeDiscountPercent: '0',
      creditsBalance: '0',
      firstMixCompleted: 0,
    }).returning();
    return result[0];
  }

  async getUserRewards(userId: string): Promise<UserRewards | undefined> {
    const result = await db.select().from(userRewards)
      .where(eq(userRewards.userId, userId))
      .limit(1);
    return result[0];
  }

  async updateUserRewards(userId: string, updates: Partial<UserRewards>): Promise<UserRewards | undefined> {
    const allowedUpdates: Partial<typeof userRewards.$inferInsert> = {};
    if (updates.totalMixes !== undefined) allowedUpdates.totalMixes = updates.totalMixes;
    if (updates.totalVolume !== undefined) allowedUpdates.totalVolume = updates.totalVolume;
    if (updates.lifetimeFees !== undefined) allowedUpdates.lifetimeFees = updates.lifetimeFees;
    if (updates.loyaltyTier !== undefined) allowedUpdates.loyaltyTier = updates.loyaltyTier;
    if (updates.feeDiscountPercent !== undefined) allowedUpdates.feeDiscountPercent = updates.feeDiscountPercent;
    if (updates.creditsBalance !== undefined) allowedUpdates.creditsBalance = updates.creditsBalance;
    if (updates.firstMixCompleted !== undefined) allowedUpdates.firstMixCompleted = updates.firstMixCompleted;
    if (updates.lastMixAt !== undefined) allowedUpdates.lastMixAt = updates.lastMixAt;
    
    allowedUpdates.updatedAt = new Date();

    const result = await db.update(userRewards)
      .set(allowedUpdates)
      .where(eq(userRewards.userId, userId))
      .returning();
    return result[0];
  }

  // Referral code operations
  async createReferralCode(insertCode: InsertReferralCode): Promise<ReferralCode> {
    const result = await db.insert(referralCodes).values(insertCode).returning();
    return result[0];
  }

  async getReferralCodeByCode(code: string): Promise<ReferralCode | undefined> {
    const result = await db.select().from(referralCodes)
      .where(eq(referralCodes.code, code))
      .limit(1);
    return result[0];
  }

  async getUserReferralCodes(userId: string): Promise<ReferralCode[]> {
    return await db.select().from(referralCodes)
      .where(eq(referralCodes.userId, userId))
      .orderBy(desc(referralCodes.createdAt));
  }

  async incrementReferralUsage(codeId: string): Promise<ReferralCode | undefined> {
    const result = await db.update(referralCodes)
      .set({ usageCount: sql`${referralCodes.usageCount} + 1` })
      .where(eq(referralCodes.id, codeId))
      .returning();
    return result[0];
  }

  // Referral usage operations
  async createReferralUsage(insertUsage: InsertReferralUsage): Promise<ReferralUsage> {
    const result = await db.insert(referralUsages).values(insertUsage).returning();
    return result[0];
  }

  async getReferrerUsages(referrerId: string): Promise<ReferralUsage[]> {
    return await db.select().from(referralUsages)
      .where(eq(referralUsages.referrerId, referrerId))
      .orderBy(desc(referralUsages.createdAt));
  }

  async getReferralUsageByRefereeId(refereeId: string, referralCodeId: string): Promise<ReferralUsage | undefined> {
    const results = await db.select().from(referralUsages)
      .where(and(
        eq(referralUsages.refereeId, refereeId),
        eq(referralUsages.referralCodeId, referralCodeId)
      ))
      .limit(1);
    return results[0];
  }

  async incrementReferralCodeUsage(codeId: string): Promise<ReferralCode | undefined> {
    const updated = await db.update(referralCodes)
      .set({ usageCount: sql`${referralCodes.usageCount} + 1` })
      .where(eq(referralCodes.id, codeId))
      .returning();
    return updated[0];
  }

  async adjustUserCredits(userId: string, amount: string): Promise<UserRewards | undefined> {
    const adjustment = parseFloat(amount);
    const updated = await db.update(userRewards)
      .set({
        creditsBalance: sql`GREATEST(CAST(${userRewards.creditsBalance} AS NUMERIC) + ${adjustment}, 0)`,
        updatedAt: new Date(),
      })
      .where(eq(userRewards.userId, userId))
      .returning();
    return updated[0];
  }

  // User settings operations
  async ensureUserSettings(userId: string): Promise<UserSettings> {
    const existing = await db.select().from(userSettings)
      .where(eq(userSettings.userId, userId))
      .limit(1);
    
    if (existing[0]) return existing[0];

    const result = await db.insert(userSettings).values({
      userId,
      theme: 'dark',
      defaultPreset: 'balanced',
      autoBurnEnabled: 0,
      notifications: 1,
    }).returning();
    return result[0];
  }

  async getUserSettings(userId: string): Promise<UserSettings | undefined> {
    const result = await db.select().from(userSettings)
      .where(eq(userSettings.userId, userId))
      .limit(1);
    return result[0];
  }

  async updateUserSettings(userId: string, updates: Partial<UserSettings>): Promise<UserSettings | undefined> {
    const allowedUpdates: Partial<typeof userSettings.$inferInsert> = {};
    if (updates.theme !== undefined) allowedUpdates.theme = updates.theme;
    if (updates.defaultPreset !== undefined) allowedUpdates.defaultPreset = updates.defaultPreset;
    if (updates.autoBurnEnabled !== undefined) allowedUpdates.autoBurnEnabled = updates.autoBurnEnabled;
    if (updates.notifications !== undefined) allowedUpdates.notifications = updates.notifications;
    
    allowedUpdates.updatedAt = new Date();

    const result = await db.update(userSettings)
      .set(allowedUpdates)
      .where(eq(userSettings.userId, userId))
      .returning();
    return result[0];
  }
}

export const storage = new DbStorage();
