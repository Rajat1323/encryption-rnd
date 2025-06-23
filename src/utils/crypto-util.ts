import * as CryptoJS from 'crypto-js';

const SECRET_PASSWORD =
  'xA7r!29V#e6qWp$4D@fGzL0t!jYc*Pv9MhRu$Xn2bQsJ^KmCwTz&LdVo!rHgYb8Q';

export function encryptObject(obj: Record<string, any>): string {
  const start = Date.now();
  const json = JSON.stringify(obj);

  // Generate random salt and IV
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const salt = CryptoJS.lib.WordArray.random(128 / 8); // 16 bytes
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const iv = CryptoJS.lib.WordArray.random(128 / 8); // 16 bytes

  // Derive key using PBKDF2
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const key = CryptoJS.PBKDF2(SECRET_PASSWORD, salt, {
    keySize: 256 / 32,
    iterations: 10_000,
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
  const start = Date.now();
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const payload = CryptoJS.enc.Base64.parse(encryptedBase64);

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const salt = CryptoJS.lib.WordArray.create(payload.words.slice(0, 4)); // 16 bytes
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const iv = CryptoJS.lib.WordArray.create(payload.words.slice(4, 8)); // 16 bytes
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const ciphertext = CryptoJS.lib.WordArray.create(payload.words.slice(8));

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const key = CryptoJS.PBKDF2(SECRET_PASSWORD, salt, {
    keySize: 256 / 32,
    iterations: 10_000,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    hasher: CryptoJS.algo.SHA512,
  });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext });

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const decrypted = CryptoJS.AES.decrypt(
    cipherParams,
    key,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
  );

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const json = decrypted.toString(CryptoJS.enc.Utf8);
  const end = Date.now();
  console.log('Took:', end - start, 'ms');
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return JSON.parse(json);
}
