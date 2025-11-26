import crypto from 'crypto';

// Use SESSION_SECRET as encryption key (already in environment)
const ENCRYPTION_KEY = process.env.SESSION_SECRET || 'zmix-fallback-key-change-in-production';

// Ensure key is 32 bytes for AES-256
const KEY = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
const ALGORITHM = 'aes-256-cbc';

/**
 * Encrypt a private key for secure database storage
 */
export function encryptPrivateKey(privateKey: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  
  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Return IV + encrypted data (separated by :)
  return iv.toString('hex') + ':' + encrypted;
}

/**
 * Decrypt a private key from database storage
 */
export function decryptPrivateKey(encryptedData: string): string {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}
