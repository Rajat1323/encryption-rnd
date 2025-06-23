import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-cbc';
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100_000;
const SECRET_PASSWORD =
  'xA7r!29V#e6qWp$4D@fGzL0t!jYc*Pv9MhRu$Xn2bQsJ^KmCwTz&LdVo!rHgYb8Q';

function deriveKey(salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(
    SECRET_PASSWORD,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    'sha512',
  );
}

export function encryptObject(obj: Record<string, any>): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(salt);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const json = JSON.stringify(obj);
  const encrypted = Buffer.concat([
    cipher.update(json, 'utf8'),
    cipher.final(),
  ]);

  // Combine salt + iv + encrypted
  const combined = Buffer.concat([salt, iv, encrypted]);
  return combined.toString('base64'); // encode final output
}

export function decryptObject(encryptedBase64: string): Record<string, any> {
  try {
    const buffer = Buffer.from(encryptedBase64, 'base64');

    if (buffer.length < SALT_LENGTH + IV_LENGTH) {
      throw new Error('Invalid input length');
    }

    const salt = buffer.subarray(0, SALT_LENGTH);
    const iv = buffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const encrypted = buffer.subarray(SALT_LENGTH + IV_LENGTH);

    const key = deriveKey(salt);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return JSON.parse(decrypted.toString('utf8'));
  } catch (err: any) {
    console.error('❌ Decryption failed:', err);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    throw new Error('Decryption failed: ' + err.message);
  }
}
