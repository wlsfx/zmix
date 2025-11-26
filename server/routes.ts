import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { z } from "zod";
import bcrypt from "bcryptjs";
import { insertUserSchema } from "@shared/schema";
import rateLimit from "express-rate-limit";
import { randomBytes, randomUUID } from "crypto";

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
    max: 100, // 100 requests per minute
    message: { message: 'Too many requests. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Rate limiting for wallet operations (more strict)
  const walletLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // 30 wallet operations per minute
    message: { message: 'Too many wallet operations. Please wait.' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Rate limiting for mixer/ZK operations (resource intensive)
  const mixerLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 mix operations per 5 minutes
    message: { message: 'Too many mix operations. Please wait before starting another mix.' },
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

  // Delete wallet
  app.delete('/api/wallets/:id', walletLimiter, async (req, res) => {
    try {
      const { id } = req.params;
      
      const wallet = await storage.getWallet(id);
      if (!wallet) {
        return res.status(404).json({ error: 'Wallet not found' });
      }
      
      // Verify ownership
      const userId = getOrCreateAnonymousId(req.session);
      if (wallet.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      // Soft delete by setting isBurned flag
      await storage.updateWallet(id, { isBurned: 1 });
      res.json({ message: 'Wallet deleted successfully' });
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

  // ==================== Zero-Knowledge Proof Routes ====================

  // Create a ZK deposit commitment
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
        // Return note data encrypted or via secure channel in production
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

  const httpServer = createServer(app);

  return httpServer;
}
