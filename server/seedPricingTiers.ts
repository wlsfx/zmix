import { IStorage } from './storage';
import { db } from './db';
import { pricingTiers } from '@shared/schema';
import { sql } from 'drizzle-orm';

/**
 * Seed default pricing tiers for the mixer platform
 * 
 * IMPORTANT: Tier names match loyalty tier names
 * Standard is the baseline for all users (5%)
 * Higher tiers represent amount ranges, not user status
 * 
 * - Standard: 0-1 SOL @ 5.00% (baseline for all amounts)
 * - Bronze: 1-10 SOL @ 4.00% (medium amounts)
 * - Silver: 10-50 SOL @ 3.00% (larger amounts)
 * - Gold: 50-100 SOL @ 2.00% (high value)
 * - Platinum: 100+ SOL @ 1.00% (premium)
 * 
 * Note: User loyalty discounts stack on top of these base fees
 */
export async function seedPricingTiers(storage: IStorage): Promise<void> {
  const existingTiers = await storage.getActivePricingTiers();
  
  // Check if we need to migrate old tier names (Micro/VIP) to new ones (Standard/Platinum)
  const hasOldTiers = existingTiers.some(tier => 
    tier.name === 'Micro' || tier.name === 'VIP' || tier.name === 'Premium'
  );

  const hasCorrectTiers = existingTiers.some(tier => tier.name === 'Platinum');

  // If we have old tiers or no tiers at all, we need to seed/migrate
  if (!hasOldTiers && hasCorrectTiers) {
    console.log('✓ Pricing tiers already correctly configured');
    return;
  }

  if (hasOldTiers) {
    console.log('⚠️  Detected legacy pricing tiers - deactivating and replacing...');
    // Deactivate all existing tiers before creating new ones
    await db.update(pricingTiers)
      .set({ isActive: 0 })
      .execute();
  } else {
    console.log('Seeding pricing tiers for first time...');
  }

  const defaultTiers = [
    {
      name: 'Standard',
      minAmount: '0',
      maxAmount: '1',
      feePercent: '5.00',
      description: 'Standard tier for amounts under 1 SOL',
      isActive: 1,
    },
    {
      name: 'Bronze',
      minAmount: '1',
      maxAmount: '10',
      feePercent: '4.00',
      description: 'Bronze tier for amounts 1-10 SOL',
      isActive: 1,
    },
    {
      name: 'Silver',
      minAmount: '10',
      maxAmount: '50',
      feePercent: '3.00',
      description: 'Silver tier for amounts 10-50 SOL',
      isActive: 1,
    },
    {
      name: 'Gold',
      minAmount: '50',
      maxAmount: '100',
      feePercent: '2.00',
      description: 'Gold tier for amounts 50-100 SOL',
      isActive: 1,
    },
    {
      name: 'Platinum',
      minAmount: '100',
      maxAmount: null,
      feePercent: '1.00',
      description: 'Platinum tier for amounts 100+ SOL',
      isActive: 1,
    },
  ];

  for (const tier of defaultTiers) {
    await storage.createPricingTier(tier);
  }

  console.log(`✓ Seeded ${defaultTiers.length} pricing tiers`);
}
