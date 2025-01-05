import { AITTPS } from '../src/index';

describe('AITTPS Library', () => {
  let privateKey1: string;
  let publicKey1: string;
  let privateKey2: string;
  let publicKey2: string;

  beforeAll(() => {
    // Generate two key pairs for testing
    const keyPair1 = AITTPS.generateNewKeyPair();
    privateKey1 = keyPair1.privateKey;
    publicKey1 = keyPair1.publicKey;

    const keyPair2 = AITTPS.generateNewKeyPair();
    privateKey2 = keyPair2.privateKey;
    publicKey2 = keyPair2.publicKey;
  });

  test('should generate ECC P-521 key pair', () => {
    const { privateKey, publicKey } = AITTPS.generateNewKeyPair();
    expect(privateKey).toContain('PRIVATE KEY');
    expect(publicKey).toContain('PUBLIC KEY');
  });

  test('should derive public key from private key', () => {
    const derivedPublicKey = AITTPS.derivePublicKeyFromPrivateKey(privateKey1);
    expect(derivedPublicKey).toBe(publicKey1);
  });

  test('should derive a shared session key using ECDH', () => {
    const sessionKey1 = AITTPS.deriveSessionKey(privateKey1, publicKey2);
    const sessionKey2 = AITTPS.deriveSessionKey(privateKey2, publicKey1);

    expect(sessionKey1).toBeDefined();
    expect(sessionKey2).toBeDefined();
    expect(sessionKey1).toEqual(sessionKey2); // Session keys must match
  });

  test('should encrypt and decrypt data using AES-GCM', () => {
    const sessionKey = AITTPS.deriveSessionKey(privateKey1, publicKey2);
    const message = Buffer.from('Sensitive Data');
    const encryptedData = AITTPS.encryptDataWithAES(message, sessionKey);
    const decryptedData = AITTPS.decryptDataWithAES(encryptedData, sessionKey);

    expect(decryptedData.toString()).toEqual(message.toString());
  });

  test('should generate a random 256-bit AES key', () => {
    const randomKey = AITTPS.generateRandomAESKey();
    expect(randomKey).toHaveLength(32); // 256 bits = 32 bytes
  });

  test('should throw an error for invalid AES key size', () => {
    const invalidKey = Buffer.alloc(10); // Invalid key size
    const message = Buffer.from('Sensitive Data');
    expect(() => AITTPS.encryptDataWithAES(message, invalidKey)).toThrow('Invalid AES key size.');
  });
});
