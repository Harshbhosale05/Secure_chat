import crypto from 'crypto';
import pkg from 'elliptic';
const { ec: EC } = pkg;
import forge from 'node-forge';

// Initialize elliptic curve (secp256k1 - same as Bitcoin)
const ec = new EC('secp256k1');

class EncryptionManager {
  constructor() {
    this.keySize = 2048; // RSA key size
    this.algorithm = 'aes-256-gcm'; // Symmetric encryption algorithm
    this.hashAlgorithm = 'sha256';
  }

  // Generate ECC key pair (faster, smaller keys)
  generateECCKeyPair() {
    try {
      const keyPair = ec.genKeyPair();
      
      return {
        privateKey: keyPair.getPrivate('hex'),
        publicKey: keyPair.getPublic('hex'),
        keyType: 'ECC'
      };
    } catch (error) {
      throw new Error(`ECC key generation failed: ${error.message}`);
    }
  }

  // Generate RSA key pair (more compatible, larger keys)
  generateRSAKeyPair() {
    try {
      const keyPair = forge.pki.rsa.generateKeyPair(this.keySize);
      
      return {
        privateKey: forge.pki.privateKeyToPem(keyPair.privateKey),
        publicKey: forge.pki.publicKeyToPem(keyPair.publicKey),
        keyType: 'RSA'
      };
    } catch (error) {
      throw new Error(`RSA key generation failed: ${error.message}`);
    }
  }

  // Hybrid Encryption: Use ECC for key exchange, AES for message encryption
  encryptMessage(message, recipientPublicKey, senderPrivateKey) {
    try {
      // Generate random AES key
      const aesKey = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);

      // Encrypt message with AES
      const cipher = crypto.createCipher(this.algorithm, aesKey);
      let encryptedMessage = cipher.update(message, 'utf8', 'hex');
      encryptedMessage += cipher.final('hex');
      const authTag = cipher.getAuthTag();

      // Encrypt AES key with recipient's public key (ECC)
      const recipientKey = ec.keyFromPublic(recipientPublicKey, 'hex');
      const senderKey = ec.keyFromPrivate(senderPrivateKey, 'hex');
      
      // ECDH key exchange
      const sharedSecret = senderKey.derive(recipientKey.getPublic());
      const sharedKey = crypto.createHash(this.hashAlgorithm)
        .update(sharedSecret.toString(16))
        .digest();

      // Encrypt AES key with shared secret
      const keyCipher = crypto.createCipher('aes-256-cbc', sharedKey);
      let encryptedAESKey = keyCipher.update(aesKey.toString('hex'), 'utf8', 'hex');
      encryptedAESKey += keyCipher.final('hex');

      return {
        encryptedMessage,
        encryptedKey: encryptedAESKey,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm: this.algorithm,
        timestamp: Date.now()
      };
    } catch (error) {
      throw new Error(`Message encryption failed: ${error.message}`);
    }
  }

  // Decrypt message using hybrid decryption
  decryptMessage(encryptedData, senderPublicKey, recipientPrivateKey) {
    try {
      const { encryptedMessage, encryptedKey, iv, authTag } = encryptedData;

      // Recreate shared secret
      const senderKey = ec.keyFromPublic(senderPublicKey, 'hex');
      const recipientKey = ec.keyFromPrivate(recipientPrivateKey, 'hex');
      
      const sharedSecret = recipientKey.derive(senderKey.getPublic());
      const sharedKey = crypto.createHash(this.hashAlgorithm)
        .update(sharedSecret.toString(16))
        .digest();

      // Decrypt AES key
      const keyDecipher = crypto.createDecipher('aes-256-cbc', sharedKey);
      let aesKeyHex = keyDecipher.update(encryptedKey, 'hex', 'utf8');
      aesKeyHex += keyDecipher.final('utf8');
      const aesKey = Buffer.from(aesKeyHex, 'hex');

      // Decrypt message
      const decipher = crypto.createDecipher(this.algorithm, aesKey);
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8');
      decryptedMessage += decipher.final('utf8');

      return decryptedMessage;
    } catch (error) {
      throw new Error(`Message decryption failed: ${error.message}`);
    }
  }

  // Create digital signature for message verification
  signMessage(message, privateKey) {
    try {
      const key = ec.keyFromPrivate(privateKey, 'hex');
      const msgHash = crypto.createHash(this.hashAlgorithm).update(message).digest('hex');
      const signature = key.sign(msgHash);
      
      return {
        r: signature.r.toString('hex'),
        s: signature.s.toString('hex'),
        recovery: signature.recoveryParam
      };
    } catch (error) {
      throw new Error(`Message signing failed: ${error.message}`);
    }
  }

  // Verify digital signature
  verifySignature(message, signature, publicKey) {
    try {
      const key = ec.keyFromPublic(publicKey, 'hex');
      const msgHash = crypto.createHash(this.hashAlgorithm).update(message).digest('hex');
      
      return key.verify(msgHash, signature);
    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  // Encrypt file/image data
  encryptFile(fileBuffer, recipientPublicKey, senderPrivateKey) {
    try {
      // Convert buffer to base64 for processing
      const fileData = fileBuffer.toString('base64');
      return this.encryptMessage(fileData, recipientPublicKey, senderPrivateKey);
    } catch (error) {
      throw new Error(`File encryption failed: ${error.message}`);
    }
  }

  // Decrypt file/image data
  decryptFile(encryptedData, senderPublicKey, recipientPrivateKey) {
    try {
      const decryptedData = this.decryptMessage(encryptedData, senderPublicKey, recipientPrivateKey);
      return Buffer.from(decryptedData, 'base64');
    } catch (error) {
      throw new Error(`File decryption failed: ${error.message}`);
    }
  }

  // Generate secure random password for key derivation
  generateSecurePassword(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Hash data securely
  hashData(data) {
    return crypto.createHash(this.hashAlgorithm).update(data).digest('hex');
  }

  // Constant-time string comparison to prevent timing attacks
  constantTimeCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    
    return result === 0;
  }
}

// Export singleton instance
const encryptionManager = new EncryptionManager();
export default encryptionManager;

// Export class for testing
export { EncryptionManager };
