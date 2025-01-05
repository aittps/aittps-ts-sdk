Here's the **TypeScript README** based on the Python README:

---

# AITTPS

**AITTPS** is an open-source security and privacy protocol designed for AI agents to communicate securely over public channels like Twitter, Telegram, or APIs. It ensures that no human, bot, or centralized entity can intercept or eavesdrop on communications, maintaining complete confidentiality and privacy.

---

## Features

- **End-to-End Encryption**: Ensures secure communication between AI agents.
- **Elliptic Curve Cryptography (ECC)**: Utilizes ECC P-521 for generating robust cryptographic keys.
- **AES Encryption**: Secures data using 256-bit AES encryption for speed and security.
- **Random Key Generation**: Generates high-entropy symmetric keys for encrypting data.
- **Interoperability**: Can be integrated with public channels like Twitter, Telegram, APIs, and more.
- **Open Source**: Designed for transparency and extensibility.

---

## Installation

To install AITTPS, use npm:

```bash
npm install aittps
```

---

## Getting Started

### 1. Importing AITTPS

```typescript
import { AITTPS } from 'aittps';
```

### 2. Generating Key Pairs

Generate a secure ECC key pair:

```typescript
const aittps = new AITTPS();
const { privateKey: senderPrivateKey, publicKey: senderPublicKey } = aittps.generateNewKeyPair();
console.log("Private Key:", senderPrivateKey);
console.log("Public Key:", senderPublicKey);
```

### 3. Deriving Shared AES Key

Generate shared AES key from your private key and receiver's public key.

```typescript
// On sender side
const sharedAesKey = aittps.deriveSessionKey(senderPrivateKey, receiverPublicKey);

// On receiver side
const sharedAesKey = aittps.deriveSessionKey(receiverPrivateKey, senderPublicKey);
```

### 4. Encrypting and Decrypting Data

#### Encrypt Data (On Sender side):

```typescript
// Shared AES key has been generated using step 3 with sender's private and receiver's public key.
const data = "Secure message for AI agent.";
const encryptedData = aittps.encryptDataWithAES(Buffer.from(data), sharedAesKey);
console.log("Encrypted Data:", encryptedData);
```

#### Decrypt Data (On Receiver side):

```typescript
// Shared AES key has been generated using step 3 with receiver's private and sender's public key.
const decryptedData = aittps.decryptDataWithAES(encryptedData, sharedAesKey);
console.log("Decrypted Data:", decryptedData.toString());
```

---

## Use Cases

- **Secure AI Communication**: Protect sensitive data exchanged between AI agents.
- **Public Channel Security**: Encrypt messages sent over public platforms like Twitter or Telegram.
- **API Communication**: Secure API-based interactions with strong cryptography.

---

## Example Workflow

Here’s an example of encrypting a message, sharing it over a public channel, and decrypting it on the receiving end:

1. **Sender Side**:

   ```typescript
   import { AITTPS } from 'aittps';

   const aittps = new AITTPS();
   const { privateKey, publicKey } = aittps.generateNewKeyPair();
   const receiverPublicKey = "Public Key of receiver"; // TO BE ADDED, AS PROVIDED BY RECEIVER
   const sharedAesKey = aittps.deriveSessionKey(privateKey, receiverPublicKey);

   const message = "This is a secure message.";
   const encryptedData = aittps.encryptDataWithAES(Buffer.from(message), sharedAesKey);

   // Share `encryptedData` over a public channel
   console.log("Encrypted Message Sent.");
   ```

2. **Receiver Side**:

   ```typescript
   const privateKey = ""; // TO BE GENERATED USING 'generateNewKeyPair'
   const senderPublicKey = ""; // TO BE UPDATED AS PROVIDED BY SENDER
   const sharedAesKey = aittps.deriveSessionKey(privateKey, senderPublicKey);
   const decryptedMessage = aittps.decryptDataWithAES(encryptedData, sharedAesKey);

   console.log("Decrypted Message:", decryptedMessage.toString());
   ```

---

## Contributing

We welcome contributions to AITTPS! If you’d like to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Support

If you encounter any issues or have questions, feel free to open an issue on our [GitHub repository](https://github.com/your-repo/aittps).

---

## Acknowledgments

Special thanks to the open-source community for their contributions and support.

---

This README should work well for your TypeScript project and help guide users in using your library.
