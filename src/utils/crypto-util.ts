import * as CryptoJS from 'crypto-js';

const SECRET_PASSWORD =
  'xA7r!29V#e6qWp$4D@fGzL0t!jYc*Pv9MhRu$Xn2bQsJ^KmCwTz&LdVo!rHgYb8Q';

const SALT_LENGTH = 32; // bytes
const IV_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 10_000;

export function encryptObject(obj: Record<string, any>): string {
  const start = Date.now();
  const json = JSON.stringify(obj);

  // Generate random salt and IV
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const salt = CryptoJS.lib.WordArray.random(SALT_LENGTH);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const iv = CryptoJS.lib.WordArray.random(IV_LENGTH);

  // Derive key using PBKDF2
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const key = CryptoJS.PBKDF2(SECRET_PASSWORD, salt, {
    keySize: KEY_LENGTH / 4,
    iterations: PBKDF2_ITERATIONS,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    hasher: CryptoJS.algo.SHA512,
  });

  // Encrypt
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const encrypted = CryptoJS.AES.encrypt(json, key, {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    iv,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    mode: CryptoJS.mode.CBC,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    padding: CryptoJS.pad.Pkcs7,
  });

  // Return salt + iv + encrypted ciphertext in Base64
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const payload = CryptoJS.enc.Base64.stringify(
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    salt.concat(iv).concat(encrypted.ciphertext),
  );
  const end = Date.now();
  console.log('Took:', end - start, 'ms');

  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return payload;
}

export function decryptObject(encryptedBase64: string): Record<string, any> {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const payload = CryptoJS.enc.Base64.parse(encryptedBase64);

  // 🛠 CORRECTED: Each word = 4 bytes
  const saltWordCount = SALT_LENGTH / 4; // 32 / 4 = 8
  const ivWordCount = IV_LENGTH / 4; // 16 / 4 = 4

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const salt = CryptoJS.lib.WordArray.create(
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    payload.words.slice(0, saltWordCount),
  );
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const iv = CryptoJS.lib.WordArray.create(
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    payload.words.slice(saltWordCount, saltWordCount + ivWordCount),
  );
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const ciphertext = CryptoJS.lib.WordArray.create(
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
    payload.words.slice(saltWordCount + ivWordCount),
  );

  const key = CryptoJS.PBKDF2(SECRET_PASSWORD, salt, {
    keySize: KEY_LENGTH / 4,
    iterations: PBKDF2_ITERATIONS,
    hasher: CryptoJS.algo.SHA512,
  });

  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
    iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const json = decrypted.toString(CryptoJS.enc.Utf8);
  return JSON.parse(json);
}
