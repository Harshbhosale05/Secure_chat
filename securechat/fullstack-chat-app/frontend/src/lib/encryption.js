import CryptoJS from 'crypto-js';
import * as elliptic from 'elliptic';
const EC = elliptic.ec;
const ec = new EC('secp256k1');

class ClientEncryption {
  constructor() {
    this.keyStorageKey = 'secure_chat_private_key';
    this.keyVersionKey = 'secure_chat_key_version';
    this.settingsKey = 'secure_chat_security_settings';
  }

  // Store private key securely in browser
  storePrivateKey(privateKey, keyVersion = 1) {
    try {
      // In production, consider using Web Crypto API or IndexedDB with encryption
      const encryptedKey = CryptoJS.AES.encrypt(privateKey, this.getDeviceId()).toString();
      localStorage.setItem(this.keyStorageKey, encryptedKey);
      localStorage.setItem(this.keyVersionKey, keyVersion.toString());
      return true;
    } catch (error) {
      console.error('Failed to store private key:', error);
      return false;
    }
  }

  // Retrieve private key from storage
  getPrivateKey() {
    try {
      const encryptedKey = localStorage.getItem(this.keyStorageKey);
      if (!encryptedKey) return null;

      const decryptedKey = CryptoJS.AES.decrypt(encryptedKey, this.getDeviceId()).toString(CryptoJS.enc.Utf8);
      return decryptedKey || null;
    } catch (error) {
      console.error('Failed to retrieve private key:', error);
      return null;
    }
  }

  // Get stored key version
  getKeyVersion() {
    try {
      return parseInt(localStorage.getItem(this.keyVersionKey)) || 1;
    } catch (error) {
      return 1;
    }
  }

  // Generate device-specific identifier for key encryption
  getDeviceId() {
    try {
      let deviceId = localStorage.getItem('device_id');
      if (!deviceId) {
        deviceId = this.generateRandomString(32);
        localStorage.setItem('device_id', deviceId);
      }
      return deviceId;
    } catch (error) {
      return 'fallback_device_id';
    }
  }

  // Generate random string
  generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  // Simple AES encryption for messages (client-side only backup)
  encryptMessageLocal(message, password) {
    try {
      return CryptoJS.AES.encrypt(message, password).toString();
    } catch (error) {
      throw new Error(`Local encryption failed: ${error.message}`);
    }
  }

  // Simple AES decryption for messages (client-side only backup)
  decryptMessageLocal(encryptedMessage, password) {
    try {
      const bytes = CryptoJS.AES.decrypt(encryptedMessage, password);
      return bytes.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      throw new Error(`Local decryption failed: ${error.message}`);
    }
  }

  // Hash data for integrity checking
  hashData(data) {
    return CryptoJS.SHA256(data).toString();
  }

  // Generate secure password
  generateSecurePassword(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // Store security settings
  storeSecuritySettings(settings) {
    try {
      localStorage.setItem(this.settingsKey, JSON.stringify(settings));
      return true;
    } catch (error) {
      console.error('Failed to store security settings:', error);
      return false;
    }
  }

  // Get security settings
  getSecuritySettings() {
    try {
      const settings = localStorage.getItem(this.settingsKey);
      return settings ? JSON.parse(settings) : {
        allowScreenshots: true,
        defaultMessageTTL: 0,
        encryptionEnabled: true,
        requireEncryption: false
      };
    } catch (error) {
      return {
        allowScreenshots: true,
        defaultMessageTTL: 0,
        encryptionEnabled: true,
        requireEncryption: false
      };
    }
  }

  // Clear all stored encryption data (logout/reset)
  clearStoredData() {
    try {
      localStorage.removeItem(this.keyStorageKey);
      localStorage.removeItem(this.keyVersionKey);
      localStorage.removeItem(this.settingsKey);
      return true;
    } catch (error) {
      console.error('Failed to clear stored data:', error);
      return false;
    }
  }

  // Check if user has encryption keys
  hasKeys() {
    return !!this.getPrivateKey();
  }

  // Validate encryption setup
  validateEncryptionSetup() {
    const privateKey = this.getPrivateKey();
    const keyVersion = this.getKeyVersion();
    
    return {
      hasPrivateKey: !!privateKey,
      keyVersion,
      isValid: !!privateKey && keyVersion > 0
    };
  }

  // Generate temporary session password
  generateSessionPassword() {
    return this.generateSecurePassword(16);
  }

  // Encrypt file data for upload
  encryptFileData(fileData, password) {
    try {
      // Convert file to base64 if it's a buffer
      const dataToEncrypt = typeof fileData === 'string' ? fileData : btoa(fileData);
      return this.encryptMessageLocal(dataToEncrypt, password);
    } catch (error) {
      throw new Error(`File encryption failed: ${error.message}`);
    }
  }

  // Decrypt file data after download
  decryptFileData(encryptedData, password) {
    try {
      const decryptedData = this.decryptMessageLocal(encryptedData, password);
      // Return as base64 - can be converted to blob/file as needed
      return decryptedData;
    } catch (error) {
      throw new Error(`File decryption failed: ${error.message}`);
    }
  }

  // Create expiration timestamp
  createExpirationTime(ttlSeconds) {
    if (!ttlSeconds || ttlSeconds <= 0) return null;
    return new Date(Date.now() + (ttlSeconds * 1000));
  }

  // Check if message has expired
  isMessageExpired(expiresAt) {
    if (!expiresAt) return false;
    return new Date() > new Date(expiresAt);
  }

  // Get time until expiration
  getTimeUntilExpiration(expiresAt) {
    if (!expiresAt) return null;
    const now = new Date();
    const expiry = new Date(expiresAt);
    const diff = expiry.getTime() - now.getTime();
    return diff > 0 ? diff : 0;
  }

  // Format expiration time for display
  formatExpirationTime(expiresAt) {
    if (!expiresAt) return 'Never';
    
    const timeLeft = this.getTimeUntilExpiration(expiresAt);
    if (timeLeft <= 0) return 'Expired';
    
    const seconds = Math.floor(timeLeft / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }
}

// Helper: AES-GCM encryption
async function aesGcmEncrypt(plainText, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const alg = { name: 'AES-GCM', iv };
  const cryptoKey = await crypto.subtle.importKey('raw', key, alg, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt(alg, cryptoKey, enc.encode(plainText));
  return { cipherText: new Uint8Array(encrypted), iv };
}

// Helper: AES-GCM decryption
async function aesGcmDecrypt(cipherText, key, iv) {
  const alg = { name: 'AES-GCM', iv };
  const cryptoKey = await crypto.subtle.importKey('raw', key, alg, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt(alg, cryptoKey, cipherText);
  return new TextDecoder().decode(decrypted);
}

// ECC Hybrid Encryption (frontend)
async function encryptMessageHybrid(message, receiverPublicKeyHex, senderPrivateKeyHex) {
  // 1. Derive shared secret
  const receiverKey = ec.keyFromPublic(receiverPublicKeyHex, 'hex');
  const senderKey = ec.keyFromPrivate(senderPrivateKeyHex, 'hex');
  const sharedSecret = senderKey.derive(receiverKey.getPublic());
  // 2. Hash shared secret to get AES key
  const sharedKey = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sharedSecret.toString(16)));
  // 3. Encrypt message with AES-GCM
  const { cipherText, iv } = await aesGcmEncrypt(message, new Uint8Array(sharedKey));
  return {
    encryptedMessage: Array.from(cipherText),
    iv: Array.from(iv),
    algorithm: 'AES-GCM',
    timestamp: Date.now(),
  };
}

// ECC Hybrid Decryption (frontend)
async function decryptMessageHybrid(encryptedData, senderPublicKeyHex, receiverPrivateKeyHex) {
  const { encryptedMessage, iv } = encryptedData;
  const senderKey = ec.keyFromPublic(senderPublicKeyHex, 'hex');
  const receiverKey = ec.keyFromPrivate(receiverPrivateKeyHex, 'hex');
  const sharedSecret = receiverKey.derive(senderKey.getPublic());
  const sharedKey = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sharedSecret.toString(16)));
  const plainText = await aesGcmDecrypt(new Uint8Array(encryptedMessage), new Uint8Array(sharedKey), new Uint8Array(iv));
  return plainText;
}

// Attach to clientEncryption for use in UI
ClientEncryption.prototype.encryptMessageHybrid = encryptMessageHybrid;
ClientEncryption.prototype.decryptMessageHybrid = decryptMessageHybrid;

ClientEncryption.prototype.getPublicKey = function() {
  // Try zustand store first
  try {
    const store = window.__zustandStore || null;
    if (store && store.getState) {
      const pub = store.getState().publicKey;
      if (pub) return pub;
    }
  } catch {}
  // Fallback: try to get from window.authUser or similar
  if (window.authUser && window.authUser.publicKey) return window.authUser.publicKey;
  // Fallback: try to get from localStorage (not secure, but for completeness)
  return '';
};

// Export singleton instance
const clientEncryption = new ClientEncryption();
window.clientEncryption = clientEncryption;
export default clientEncryption;

// Export class for testing
export { ClientEncryption };
