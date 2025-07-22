import encryptionManager from './encryption.js';
import User from '../models/user.model.js';

class KeyManager {
  constructor() {
    this.keyRotationInterval = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
  }

  // Generate and store user keys during registration (ECC by default)
  // ECC (Elliptic Curve Cryptography) is used for key generation unless specified otherwise.
  async generateUserKeys(userId, keyType = 'ECC') {
    try {
      let keyPair;
      if (keyType === 'ECC') {
        keyPair = encryptionManager.generateECCKeyPair();
      } else {
        keyPair = encryptionManager.generateRSAKeyPair();
      }

      // Store public key in database, set default TTL to 'never'
      await User.findByIdAndUpdate(userId, {
        publicKey: keyPair.publicKey,
        keyVersion: 1,
        'securitySettings.encryptionEnabled': true,
        'securitySettings.messageTTL': 'never',
      });

      // Return both keys (private key should be stored client-side only)
      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        keyType: keyPair.keyType,
        keyVersion: 1
      };
    } catch (error) {
      throw new Error(`Key generation failed: ${error.message}`);
    }
  }

  // Get user's public key
  async getUserPublicKey(userId) {
    try {
      const user = await User.findById(userId).select('publicKey keyVersion');
      if (!user || !user.publicKey) {
        throw new Error('User public key not found');
      }
      
      return {
        publicKey: user.publicKey,
        keyVersion: user.keyVersion
      };
    } catch (error) {
      throw new Error(`Failed to retrieve public key: ${error.message}`);
    }
  }

  // Get multiple users' public keys for group operations
  async getMultiplePublicKeys(userIds) {
    try {
      const users = await User.find({
        _id: { $in: userIds }
      }).select('_id publicKey keyVersion');

      const keyMap = {};
      users.forEach(user => {
        if (user.publicKey) {
          keyMap[user._id.toString()] = {
            publicKey: user.publicKey,
            keyVersion: user.keyVersion
          };
        }
      });

      return keyMap;
    } catch (error) {
      throw new Error(`Failed to retrieve multiple public keys: ${error.message}`);
    }
  }

  // Rotate user keys (for enhanced security)
  async rotateUserKeys(userId, newKeyType = 'ECC') {
    try {
      const currentUser = await User.findById(userId).select('keyVersion');
      if (!currentUser) {
        throw new Error('User not found');
      }

      let keyPair;
      if (newKeyType === 'ECC') {
        keyPair = encryptionManager.generateECCKeyPair();
      } else {
        keyPair = encryptionManager.generateRSAKeyPair();
      }

      const newKeyVersion = (currentUser.keyVersion || 1) + 1;

      // Update public key and version in database
      await User.findByIdAndUpdate(userId, {
        publicKey: keyPair.publicKey,
        keyVersion: newKeyVersion
      });

      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        keyType: keyPair.keyType,
        keyVersion: newKeyVersion,
        rotatedAt: new Date()
      };
    } catch (error) {
      throw new Error(`Key rotation failed: ${error.message}`);
    }
  }

  // Check if key rotation is needed
  async isKeyRotationNeeded(userId) {
    try {
      const user = await User.findById(userId).select('updatedAt keyVersion');
      if (!user) {
        return false;
      }

      const lastUpdate = new Date(user.updatedAt);
      const now = new Date();
      const timeDiff = now.getTime() - lastUpdate.getTime();

      return timeDiff > this.keyRotationInterval;
    } catch (error) {
      console.error('Key rotation check failed:', error);
      return false;
    }
  }

  // Validate key format
  validatePublicKey(publicKey, keyType = 'ECC') {
    try {
      if (keyType === 'ECC') {
        // Validate ECC key format (hex string)
        return /^[0-9a-fA-F]+$/.test(publicKey) && publicKey.length >= 64;
      } else {
        // Validate RSA key format (PEM)
        return publicKey.includes('-----BEGIN PUBLIC KEY-----') && 
               publicKey.includes('-----END PUBLIC KEY-----');
      }
    } catch (error) {
      return false;
    }
  }

  // Create key exchange session for new conversations
  async createKeyExchangeSession(senderId, receiverId) {
    try {
      const [senderKeys, receiverKeys] = await Promise.all([
        this.getUserPublicKey(senderId),
        this.getUserPublicKey(receiverId)
      ]);

      return {
        sessionId: encryptionManager.generateSecurePassword(16),
        senderPublicKey: senderKeys.publicKey,
        receiverPublicKey: receiverKeys.publicKey,
        senderKeyVersion: senderKeys.keyVersion,
        receiverKeyVersion: receiverKeys.keyVersion,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      };
    } catch (error) {
      throw new Error(`Key exchange session creation failed: ${error.message}`);
    }
  }

  // Get user's security settings
  async getUserSecuritySettings(userId) {
    try {
      const user = await User.findById(userId).select('securitySettings');
      if (!user) {
        throw new Error('User not found');
      }

      return user.securitySettings || {
        allowScreenshots: true,
        defaultMessageTTL: 0,
        encryptionEnabled: true,
        requireEncryption: false
      };
    } catch (error) {
      throw new Error(`Failed to retrieve security settings: ${error.message}`);
    }
  }

  // Update user's security settings
  async updateSecuritySettings(userId, settings) {
    try {
      const allowedSettings = [
        'allowScreenshots',
        'defaultMessageTTL',
        'encryptionEnabled',
        'requireEncryption'
      ];

      const updateData = {};
      for (const [key, value] of Object.entries(settings)) {
        if (allowedSettings.includes(key)) {
          updateData[`securitySettings.${key}`] = value;
        }
      }

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        updateData,
        { new: true }
      ).select('securitySettings');

      return updatedUser.securitySettings;
    } catch (error) {
      throw new Error(`Failed to update security settings: ${error.message}`);
    }
  }

  // Check if encryption is required for a conversation
  async isEncryptionRequired(senderId, receiverId) {
    try {
      const [senderSettings, receiverSettings] = await Promise.all([
        this.getUserSecuritySettings(senderId),
        this.getUserSecuritySettings(receiverId)
      ]);

      return senderSettings.requireEncryption || receiverSettings.requireEncryption;
    } catch (error) {
      console.error('Encryption requirement check failed:', error);
      return false;
    }
  }

  // Generate temporary keys for session-based encryption
  generateSessionKeys() {
    try {
      const sessionKey = encryptionManager.generateSecurePassword(32);
      const sessionId = encryptionManager.generateSecurePassword(16);
      
      return {
        sessionKey,
        sessionId,
        createdAt: Date.now(),
        expiresAt: Date.now() + (60 * 60 * 1000) // 1 hour
      };
    } catch (error) {
      throw new Error(`Session key generation failed: ${error.message}`);
    }
  }
}

// Export singleton instance
const keyManager = new KeyManager();
export default keyManager;

// Export class for testing
export { KeyManager };
