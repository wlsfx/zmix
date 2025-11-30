import { z } from 'zod';

export const sendSOLSchema = z.object({
  recipient: z
    .string()
    .min(32, 'Please enter a valid Solana address')
    .max(44, 'Please enter a valid Solana address'),
  amount: z
    .string()
    .refine((val) => !isNaN(parseFloat(val)) && parseFloat(val) > 0, {
      message: 'Amount must be greater than 0',
    }),
});

export type SendSOLFormData = z.infer<typeof sendSOLSchema>;
export type SendFormData = SendSOLFormData;

// Platform configuration - SOL→SOL mixer with 2% platform fee
export const PLATFORM_FEE_PERCENT = 2; // 2% platform fee
export const REFERRAL_REWARD_PERCENT = 0.5; // 0.5% goes to referrer
export const PLATFORM_WALLET_ADDRESS = 'FQycqpNecXG4sszC36h9KyfsYqoojyqw3X7oPKBeYkuF';

// Privacy Mixer Schema - SOL to SOL with platform fees
export const mixerSchema = z.object({
  destinationAddress: z
    .string()
    .min(32, 'Please enter a valid Solana address')
    .max(44, 'Please enter a valid Solana address'),
  amount: z
    .string()
    .refine((val) => !isNaN(parseFloat(val)) && parseFloat(val) > 0, {
      message: 'Amount must be greater than 0',
    }),
  usePrivacyPool: z.boolean().default(true), // Route through ZK privacy pool first
  enableDelay: z.boolean().default(false),
  delayMinutes: z.number().min(1).max(60).default(5),
  referralCode: z.string().optional(),
});

export type MixerFormData = z.infer<typeof mixerSchema>;
