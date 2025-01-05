import * as crypto from 'crypto';

export class AITTPS {
  /**
   * Generates a new ECC P-521 key pair.
   */
  static generateNewKeyPair(): { privateKey: string; publicKey: string } {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'secp521r1',
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
    });
    return { privateKey, publicKey };
  }

  /**
   * Derives the public key from the given private key.
   */
  static derivePublicKeyFromPrivateKey(privateKeyPem: string): string {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const publicKey = privateKey.asymmetricKeyType === 'ec'
      ? crypto.createPublicKey(privateKey)
      : null;

    if (!publicKey) throw new Error('Invalid private key.');
    return publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }

  /**
   * Derives a shared session key using ECC ECDH.
   */
  static deriveSessionKey(privateKeyPem: string, peerPublicKeyPem: string): Buffer {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const peerPublicKey = crypto.createPublicKey(peerPublicKeyPem);

    // ECDH key exchange
    const sharedSecret = crypto.diffieHellman({ privateKey, publicKey: peerPublicKey });

    // Derive a symmetric key using HKDF
    return crypto.createHmac('sha256', sharedSecret).digest();
  }

  /**
   * Encrypts data using AES-GCM.
   */
  static encryptDataWithAES(data: Buffer, symmetricKey: Buffer): Buffer {
    if (![16, 24, 32].includes(symmetricKey.length)) {
      throw new Error('Invalid AES key size.');
    }

    const iv = crypto.randomBytes(12); // 12 bytes IV for AES-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);

    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Return IV + encrypted data + GCM tag
    return Buffer.concat([iv, ciphertext, tag]);
  }

  /**
   * Decrypts data using AES-GCM.
   */
  static decryptDataWithAES(encryptedData: Buffer, symmetricKey: Buffer): Buffer {
    const iv = encryptedData.slice(0, 12);
    const tag = encryptedData.slice(-16);
    const ciphertext = encryptedData.slice(12, -16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Generates a random 256-bit AES symmetric key.
   */
  static generateRandomAESKey(): Buffer {
    return crypto.randomBytes(32); // 32 bytes = 256 bits
  }
}

// Example Usage
if (require.main === module) {
  const { privateKey, publicKey } = AITTPS.generateNewKeyPair();
  console.log('Private Key:', privateKey);
  console.log('Public Key:', publicKey);

  const { publicKey: peerPublicKey } = AITTPS.generateNewKeyPair();
  const sessionKey = AITTPS.deriveSessionKey(privateKey, peerPublicKey);
  console.log('Derived Session Key:', sessionKey.toString('hex'));

  const message = Buffer.from('Sensitive Data');
  const encryptedMessage = AITTPS.encryptDataWithAES(message, sessionKey);
  console.log('Encrypted Message:', encryptedMessage.toString('hex'));

  const decryptedMessage = AITTPS.decryptDataWithAES(encryptedMessage, sessionKey);
  console.log('Decrypted Message:', decryptedMessage.toString());
}
