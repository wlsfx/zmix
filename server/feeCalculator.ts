import { IStorage } from './storage';

export interface FeeCalculationInput {
  userId: string;
  grossAmount: string;
  referralCode?: string;
}

export interface FeeCalculationResult {
  grossAmount: string;
  baseFeePercent: string;
  loyaltyDiscountPercent: string;
  referralDiscountPercent: string;
  totalDiscountPercent: string;
  effectiveFeePercent: string;
  platformFee: string;
  referrerRewardAmount: string;
  refereeDiscountAmount: string;
  isFirstMixFree: boolean;
  appliedTier: string;
  loyaltyTier: string;
  creditsUsed: string;
  referralCodeId?: string;
  referrerId?: string;
}

export class FeeCalculator {
  constructor(private storage: IStorage) {}

  /**
   * Calculate fee using staged pipeline:
   * 1. Get base fee from pricing tier
   * 2. Apply loyalty discount (reduces fee %)
   * 3. Apply referral discount (reduces fee %)
   * 4. Apply credits (reduces final SOL amount)
   * 5. Enforce minimum fee floor (0.25%)
   * 
   * Special case: First mix is free (skips all discounts)
   */
  async calculateFee(input: FeeCalculationInput): Promise<FeeCalculationResult> {
    const { userId, grossAmount, referralCode } = input;
    const amount = parseFloat(grossAmount);

    // Initialize result
    const result: FeeCalculationResult = {
      grossAmount,
      baseFeePercent: '5.00',
      loyaltyDiscountPercent: '0.00',
      referralDiscountPercent: '0.00',
      totalDiscountPercent: '0.00',
      effectiveFeePercent: '5.00',
      platformFee: '0',
      referrerRewardAmount: '0',
      refereeDiscountAmount: '0',
      isFirstMixFree: false,
      appliedTier: 'Standard',
      loyaltyTier: 'bronze',
      creditsUsed: '0',
    };

    // Ensure user rewards record exists
    const userRewards = await this.storage.ensureUserRewards(userId);

    // Check if first mix is free (special case - skips all discounts)
    if (userRewards.firstMixCompleted === 0) {
      result.isFirstMixFree = true;
      result.platformFee = '0';
      result.effectiveFeePercent = '0.00';
      result.totalDiscountPercent = '100.00';
      return result;
    }

    // Stage 1: Get base fee from pricing tier
    const pricingTier = await this.getPricingTierForAmount(amount);
    result.baseFeePercent = pricingTier.feePercent;
    result.appliedTier = pricingTier.name;

    let currentFeePercent = parseFloat(result.baseFeePercent);

    // Stage 2: Apply loyalty discount (reduces fee %)
    result.loyaltyTier = userRewards.loyaltyTier;
    const loyaltyDiscount = parseFloat(userRewards.feeDiscountPercent);
    result.loyaltyDiscountPercent = loyaltyDiscount.toFixed(2);
    currentFeePercent = Math.max(currentFeePercent - loyaltyDiscount, 0);

    // Stage 3: Apply referral discount if code provided (reduces fee %)
    if (referralCode) {
      const referralInfo = await this.validateReferralCode(referralCode, userId);
      if (referralInfo.isValid && referralInfo.code) {
        const referralDiscount = parseFloat(referralInfo.code.discountPercent);
        result.referralDiscountPercent = referralDiscount.toFixed(2);
        currentFeePercent = Math.max(currentFeePercent - referralDiscount, 0);
        
        // Store referral info for later usage recording
        result.referralCodeId = referralInfo.code.id;
        result.referrerId = referralInfo.code.userId;
        
        // Calculate referrer reward (% of original base fee before discounts)
        const baseFee = (amount * parseFloat(result.baseFeePercent)) / 100;
        const referrerRewardPercent = parseFloat(referralInfo.code.referrerRewardPercent);
        result.referrerRewardAmount = ((baseFee * referrerRewardPercent) / 100).toFixed(9);
      }
    }

    // Enforce minimum fee floor (0.25%)
    currentFeePercent = Math.max(currentFeePercent, 0.25);
    result.effectiveFeePercent = currentFeePercent.toFixed(2);

    // Calculate total discount percent
    const totalDiscount = parseFloat(result.baseFeePercent) - currentFeePercent;
    result.totalDiscountPercent = totalDiscount.toFixed(2);

    // Stage 4: Calculate platform fee in SOL
    let platformFee = (amount * currentFeePercent) / 100;

    // Stage 5: Apply credits (reduces final SOL amount)
    const creditsAvailable = parseFloat(userRewards.creditsBalance);
    if (creditsAvailable > 0) {
      // Calculate minimum fee that must be charged
      const minFee = (amount * 0.25) / 100;
      const maxCreditsUsable = Math.max(platformFee - minFee, 0);
      const creditsToUse = Math.min(creditsAvailable, maxCreditsUsable);
      
      if (creditsToUse > 0) {
        platformFee = Math.max(platformFee - creditsToUse, minFee);
        result.creditsUsed = creditsToUse.toFixed(9);
      }
    }

    result.platformFee = platformFee.toFixed(9);
    
    // Calculate referee discount amount (savings vs base fee)
    const baseFee = (amount * parseFloat(result.baseFeePercent)) / 100;
    result.refereeDiscountAmount = (baseFee - platformFee).toFixed(9);

    return result;
  }

  /**
   * Get pricing tier based on transaction amount
   */
  private async getPricingTierForAmount(amount: number): Promise<{
    name: string;
    feePercent: string;
    minAmount: string;
    maxAmount: string | null;
  }> {
    const tiers = await this.storage.getActivePricingTiers();
    
    // Find matching tier
    for (const tier of tiers) {
      const minAmount = parseFloat(tier.minAmount);
      const maxAmount = tier.maxAmount ? parseFloat(tier.maxAmount) : Infinity;
      
      if (amount >= minAmount && amount < maxAmount) {
        return {
          name: tier.name,
          feePercent: tier.feePercent,
          minAmount: tier.minAmount,
          maxAmount: tier.maxAmount,
        };
      }
    }

    // Default fallback
    return {
      name: 'Standard',
      feePercent: '5.00',
      minAmount: '0',
      maxAmount: null,
    };
  }

  /**
   * Validate referral code
   */
  private async validateReferralCode(code: string, userId: string): Promise<{
    isValid: boolean;
    code?: any;
    message?: string;
  }> {
    const referralCode = await this.storage.getReferralCodeByCode(code);

    if (!referralCode) {
      return { isValid: false, message: 'Invalid referral code' };
    }

    if (referralCode.isActive === 0) {
      return { isValid: false, message: 'Referral code is inactive' };
    }

    if (referralCode.userId === userId) {
      return { isValid: false, message: 'Cannot use your own referral code' };
    }

    if (referralCode.expiresAt && new Date(referralCode.expiresAt) < new Date()) {
      return { isValid: false, message: 'Referral code has expired' };
    }

    if (referralCode.maxUsages && referralCode.usageCount >= referralCode.maxUsages) {
      return { isValid: false, message: 'Referral code has reached maximum usages' };
    }

    // Check if user has already used this code
    const existingUsage = await this.storage.getReferralUsageByRefereeId(userId, referralCode.id);
    if (existingUsage) {
      return { isValid: false, message: 'You have already used this referral code' };
    }

    return { isValid: true, code: referralCode };
  }

  /**
   * Update loyalty tier based on total volume
   */
  async updateLoyaltyTier(userId: string, newTotalVolume: string): Promise<string> {
    const volume = parseFloat(newTotalVolume);
    
    let newTier = 'bronze';
    let discountPercent = '0.00';

    if (volume >= 200) {
      newTier = 'platinum';
      discountPercent = '4.00'; // 4% discount
    } else if (volume >= 50) {
      newTier = 'gold';
      discountPercent = '3.00'; // 3% discount
    } else if (volume >= 10) {
      newTier = 'silver';
      discountPercent = '2.00'; // 2% discount
    } else {
      newTier = 'bronze';
      discountPercent = '1.00'; // 1% discount for any activity
    }

    await this.storage.updateUserRewards(userId, {
      loyaltyTier: newTier,
      feeDiscountPercent: discountPercent,
    });

    return newTier;
  }

  /**
   * Record referral usage and distribute rewards (transactional)
   */
  async recordReferralUsage(
    referralCodeId: string,
    referrerId: string,
    refereeId: string,
    sessionId: string,
    discountAmount: string,
    referrerRewardAmount: string
  ): Promise<void> {
    // Create referral usage record
    await this.storage.createReferralUsage({
      referralCodeId,
      referrerId,
      refereeId,
      sessionId,
      discountAmount,
      referrerRewardAmount,
    });

    // Increment referral code usage count
    await this.storage.incrementReferralCodeUsage(referralCodeId);

    // Add credits to referrer (positive adjustment)
    await this.storage.adjustUserCredits(referrerId, referrerRewardAmount);
  }

  /**
   * Mark first mix as completed
   */
  async markFirstMixCompleted(userId: string): Promise<void> {
    await this.storage.updateUserRewards(userId, {
      firstMixCompleted: 1,
    });
  }

  /**
   * Update user statistics after mix completion
   */
  async updateMixStatistics(userId: string, grossAmount: string, platformFee: string): Promise<void> {
    const userRewards = await this.storage.getUserRewards(userId);
    if (!userRewards) return;

    const newTotalMixes = userRewards.totalMixes + 1;
    const newTotalVolume = (parseFloat(userRewards.totalVolume) + parseFloat(grossAmount)).toFixed(9);
    const newLifetimeFees = (parseFloat(userRewards.lifetimeFees) + parseFloat(platformFee)).toFixed(9);

    await this.storage.updateUserRewards(userId, {
      totalMixes: newTotalMixes,
      totalVolume: newTotalVolume,
      lifetimeFees: newLifetimeFees,
      lastMixAt: new Date(),
    });

    // Update loyalty tier based on new volume
    await this.updateLoyaltyTier(userId, newTotalVolume);
  }
}
