# zmix Backend - Solana Privacy Mixer

A production-grade Solana privacy mixer backend with multi-hop obfuscation, zkSNARK proofs, and real cryptographic operations for handling SOL funds.

## Features

- **Multi-Hop Privacy Chain**: Routes SOL through 2-4 randomized intermediate wallets with dynamic hop counts, amount variance, and jittered delays
- **zkSNARK Integration**: Groth16 proving system with Poseidon hashing for zero-knowledge withdrawals
- **Database-Backed Merkle Tree**: Persistent 20-level tree supporting 1M+ deposits with nullifier registry
- **2% Platform Fee**: Configurable fee collection with transparent ledger
- **0.5% Referral Rewards**: Built-in referral system for user incentives
- **Production Rate Limiting**: Multiple limiters for auth, API, wallet, mixer, and ZK operations
- **Enhanced Error Recovery**: Exponential backoff with error classification for network resilience
- **WebSocket Notifications**: Real-time updates for mix progress and completion
- **Background Job Queue**: BullMQ-powered async processing for long-running operations

## Architecture

```
server/
├── index.ts              # Express server entry point
├── routes.ts             # API routes with rate limiting
├── storage.ts            # Database storage interface
├── db.ts                 # Drizzle ORM database connection
├── feeCalculator.ts      # Platform fee calculations
├── seedPricingTiers.ts   # Dynamic pricing initialization
├── lib/
│   ├── encryption.ts     # AES-256-CBC wallet encryption
│   ├── zk/
│   │   ├── index.ts           # ZK module exports
│   │   ├── groth16Prover.ts   # Groth16 proof generation
│   │   ├── merkleTree.ts      # Poseidon-based Merkle tree
│   │   ├── solanaVerifier.ts  # On-chain verification
│   │   └── trustedSetup.ts    # Powers of Tau ceremony
│   └── ...
├── types/
│   ├── circomlibjs.d.ts      # Type definitions
│   └── express-session.d.ts
shared/
├── schema.ts             # Drizzle ORM database schema
├── schemas.ts            # Zod validation schemas
└── types.ts              # TypeScript types
circuits/
└── mixer.circom          # zkSNARK circuit for mixer
scripts/
└── build-circuits.sh     # Circuit compilation script
```

## Prerequisites

- Node.js 18+
- PostgreSQL (Neon serverless recommended)
- Redis (optional, for BullMQ job queue)
- Circom 2.x (for circuit compilation)
- Rust/Cargo (for building circom)

## Environment Variables

Create a `.env` file with:

```bash
# Required
DATABASE_URL=postgresql://user:pass@host:5432/dbname
SESSION_SECRET=your-secure-random-session-secret
ENCRYPTION_KEY=your-32-byte-hex-encryption-key

# Solana Configuration
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
PLATFORM_FEE_WALLET=your-platform-fee-collection-wallet

# Optional - Redis for BullMQ job queue
# If not set, jobs run synchronously in-process
REDIS_URL=redis://localhost:6379

# Optional - WebSocket notifications
# Enabled by default, set to 'false' to disable
ENABLE_WEBSOCKET=true

# Environment
NODE_ENV=production
PORT=5000
```

## Installation

```bash
# Install dependencies
npm install

# Push database schema
npm run db:push

# Build the server
npm run build

# Start production server
npm start
```

## Development

```bash
# Run in development mode
npm run dev

# Type check
npm run check

# Build ZK circuits (requires circom)
./scripts/build-circuits.sh
```

## Infrastructure Options

### Minimal Setup (No Redis)
The backend works without Redis - jobs run synchronously in-process. Suitable for development or low-traffic deployments.

### Production Setup (With Redis)
For high-traffic production deployments, add Redis for:
- BullMQ job queue for async mix processing
- Better scalability and fault tolerance
- Job retries and dead letter queues

```bash
# Start Redis (Docker)
docker run -d -p 6379:6379 redis:alpine

# Or use a managed Redis service and set REDIS_URL
```

### WebSocket Notifications
Real-time notifications are enabled by default. Clients can connect to receive:
- Mix progress updates
- Transaction confirmations
- Error notifications

To disable: `ENABLE_WEBSOCKET=false`

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register with username/PIN
- `POST /api/auth/login` - Login with credentials
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout

### Wallets
- `GET /api/wallets` - List user wallets
- `POST /api/wallets` - Create new wallet
- `GET /api/wallets/:id` - Get wallet details
- `DELETE /api/wallets/:id` - Burn wallet
- `POST /api/wallets/:id/private-key` - Get decrypted private key

### Mixer
- `POST /api/mixer/sessions` - Create mixer session
- `GET /api/mixer/sessions/:id` - Get session status
- `POST /api/mixer/sessions/:id/complete` - Complete mix
- `GET /api/mixer/history` - Get mix history

### ZK Operations
- `POST /api/zk/deposit` - Create ZK deposit with Poseidon commitment
- `POST /api/zk/withdraw` - Generate Groth16 withdrawal proof
- `POST /api/zk/verify` - Verify zkSNARK proof
- `GET /api/zk/tree` - Get Merkle tree state
- `POST /api/zk/privacy-score` - Calculate privacy score
- `POST /api/zk/prepare-onchain` - Encode proof for Solana
- `GET /api/zk/verifier-info` - Get verifier program info

### Referrals
- `POST /api/referrals` - Create referral code
- `GET /api/referrals` - Get user's referral codes
- `POST /api/referrals/validate` - Validate referral code

### Fees & Rewards
- `GET /api/fees/estimate` - Estimate fees for amount
- `GET /api/fees/tiers` - Get pricing tiers
- `GET /api/rewards` - Get user rewards
- `GET /api/rewards/stats` - Get reward statistics

### Health Check
- `GET /health` - Server health status

## Database Schema

The backend uses PostgreSQL with Drizzle ORM. Key tables:

- `users` - User accounts with hashed PINs
- `wallets` - Encrypted wallet storage
- `mixer_sessions` - Active mixing operations
- `hop_events` - Individual hop audit trail
- `mix_history` - Completed mix records
- `zk_commitments` - ZK deposit commitments
- `zk_nullifiers` - Double-spend prevention
- `zk_merkle_roots` - Merkle tree snapshots
- `referral_codes` - Referral system
- `fee_ledger` - Fee transparency

## Security

- AES-256-CBC encryption for private keys
- bcrypt hashing for user PINs
- Rate limiting on all sensitive endpoints
- Session-based authentication with secure cookies
- Nullifier registry prevents double-spending
- zkSNARK proofs for withdrawal privacy

## Building ZK Circuits

For production use with real proofs:

```bash
# Install circom (requires Rust)
git clone https://github.com/iden3/circom.git
cd circom && cargo build --release
sudo cp target/release/circom /usr/local/bin/

# Install snarkjs globally
npm install -g snarkjs

# Build circuits
./scripts/build-circuits.sh
```

This generates:
- `mixer.wasm` - Circuit WASM
- `mixer_final.zkey` - Proving key
- `verification_key.json` - Verification key

## Rate Limits

| Endpoint Type | Limit | Window |
|--------------|-------|--------|
| Authentication | 10 requests | 15 minutes |
| General API | 100 requests | 1 minute |
| Wallet Operations | 30 requests | 1 minute |
| Mixer Operations | 10 requests | 5 minutes |
| ZK Operations | 20 requests | 1 minute |

## Multi-Hop Configuration

Three presets available:

- **Fast**: 2-3 hops, 3-10s delays
- **Balanced**: 2-4 hops, 5-30s delays (default)
- **Max Privacy**: 3-4 hops, 15-60s delays

## Deployment

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 5000
CMD ["npm", "start"]
```

### Environment Checklist

Before deploying to production:

- [ ] Set strong `SESSION_SECRET` (min 32 chars)
- [ ] Generate secure `ENCRYPTION_KEY` with `openssl rand -hex 32`
- [ ] Configure `DATABASE_URL` with connection pooling
- [ ] Set `NODE_ENV=production`
- [ ] Configure `PLATFORM_FEE_WALLET` for fee collection
- [ ] Set up Redis if using BullMQ (optional)
- [ ] Build ZK circuits with trusted setup

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Disclaimer

This software is provided for educational and research purposes. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction. The authors are not liable for any misuse of this software.
