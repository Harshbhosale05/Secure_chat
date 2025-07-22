import { create } from 'zustand';
import { axiosInstance } from '../lib/axios.js';
import clientEncryption from '../lib/encryption.js';
import toast from 'react-hot-toast';

export const useEncryptionStore = create((set, get) => ({
  // State
  privateKey: null,
  publicKey: null,
  keyVersion: 1,
  keyType: 'ECC',
  hasKeys: false,
  isLoading: false,
  securitySettings: {
    allowScreenshots: true,
    defaultMessageTTL: 0,
    encryptionEnabled: true,
    requireEncryption: false
  },
  encryptionStatus: {},

  // Initialize encryption from stored data
  initializeEncryption: async () => {
    try {
      const privateKey = clientEncryption.getPrivateKey();
      const keyVersion = clientEncryption.getKeyVersion();
      const securitySettings = clientEncryption.getSecuritySettings();
      let publicKey = get().publicKey;
      // If publicKey is missing, fetch from backend
      if (!publicKey) {
        try {
          const res = await axiosInstance.get('/encryption/public-key/me');
          publicKey = res.data.publicKey;
        } catch (err) {
          publicKey = '';
        }
      }
      set({
        privateKey,
        publicKey,
        keyVersion,
        hasKeys: !!privateKey,
        securitySettings
      });
    } catch (error) {
      console.error('Failed to initialize encryption:', error);
    }
  },

  // Store encryption keys (called after signup/key generation)
  storeKeys: (keyData) => {
    try {
      const { privateKey, publicKey, keyType, keyVersion } = keyData;
      
      // Store private key securely on client
      clientEncryption.storePrivateKey(privateKey, keyVersion);
      
      set({
        privateKey,
        publicKey,
        keyType,
        keyVersion,
        hasKeys: true
      });
      
      toast.success('Encryption keys stored securely');
    } catch (error) {
      console.error('Failed to store encryption keys:', error);
      toast.error('Failed to store encryption keys');
    }
  },

  // Generate new encryption keys
  generateKeys: async (keyType = 'ECC') => {
    set({ isLoading: true });
    try {
      const response = await axiosInstance.post('/encryption/generate-keys', { keyType });
      
      get().storeKeys(response.data.keys);
      
      return response.data.keys;
    } catch (error) {
      console.error('Failed to generate keys:', error);
      toast.error('Failed to generate encryption keys');
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },

  // Rotate encryption keys
  rotateKeys: async (keyType = 'ECC') => {
    set({ isLoading: true });
    try {
      const response = await axiosInstance.post('/encryption/rotate-keys', { keyType });
      
      get().storeKeys(response.data.keys);
      toast.success('Encryption keys rotated successfully');
      
      return response.data.keys;
    } catch (error) {
      console.error('Failed to rotate keys:', error);
      toast.error('Failed to rotate encryption keys');
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },

  // Get user's public key
  getUserPublicKey: async (userId) => {
    try {
      const response = await axiosInstance.get(`/encryption/public-key/${userId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to get public key:', error);
      return null;
    }
  },

  // Get multiple users' public keys
  getMultiplePublicKeys: async (userIds) => {
    try {
      const response = await axiosInstance.post('/encryption/public-keys', { userIds });
      return response.data;
    } catch (error) {
      console.error('Failed to get public keys:', error);
      return {};
    }
  },

  // Get security settings from server
  fetchSecuritySettings: async () => {
    set({ isLoading: true });
    try {
      const response = await axiosInstance.get('/encryption/security-settings');
      const settings = response.data;
      
      // Also store locally
      clientEncryption.storeSecuritySettings(settings);
      
      set({ securitySettings: settings });
      return settings;
    } catch (error) {
      console.error('Failed to fetch security settings:', error);
      // Use local settings as fallback
      const localSettings = clientEncryption.getSecuritySettings();
      set({ securitySettings: localSettings });
      return localSettings;
    } finally {
      set({ isLoading: false });
    }
  },

  // Update security settings
  updateSecuritySettings: async (newSettings) => {
    set({ isLoading: true });
    try {
      const response = await axiosInstance.put('/encryption/security-settings', newSettings);
      const updatedSettings = response.data.settings;
      
      // Store locally
      clientEncryption.storeSecuritySettings(updatedSettings);
      
      set({ securitySettings: updatedSettings });
      toast.success('Security settings updated');
      
      return updatedSettings;
    } catch (error) {
      console.error('Failed to update security settings:', error);
      toast.error('Failed to update security settings');
      throw error;
    } finally {
      set({ isLoading: false });
    }
  },

  // Check encryption status for a conversation
  checkEncryptionStatus: async (receiverId) => {
    try {
      const response = await axiosInstance.get(`/encryption/encryption-status/${receiverId}`);
      const status = response.data;
      
      set(state => ({
        encryptionStatus: {
          ...state.encryptionStatus,
          [receiverId]: status
        }
      }));
      
      return status;
    } catch (error) {
      console.error('Failed to check encryption status:', error);
      return {
        encryptionRequired: false,
        encryptionEnabled: false,
        receiverHasKeys: false,
        canEncrypt: false
      };
    }
  },

  // Check if key rotation is needed
  checkKeyRotation: async () => {
    try {
      const response = await axiosInstance.get('/encryption/check-rotation');
      return response.data.needsRotation;
    } catch (error) {
      console.error('Failed to check key rotation:', error);
      return false;
    }
  },

  // Create key exchange session
  createKeyExchange: async (receiverId) => {
    try {
      const response = await axiosInstance.post('/encryption/key-exchange', { receiverId });
      return response.data;
    } catch (error) {
      console.error('Failed to create key exchange:', error);
      throw error;
    }
  },

  // Test encryption (for development)
  testEncryption: async (message, receiverPublicKey) => {
    try {
      const privateKey = get().privateKey;
      if (!privateKey) {
        throw new Error('No private key available');
      }

      const response = await axiosInstance.post('/encryption/test-encryption', {
        message,
        receiverPublicKey,
        senderPrivateKey: privateKey
      });
      
      return response.data;
    } catch (error) {
      console.error('Encryption test failed:', error);
      throw error;
    }
  },

  // Clear encryption data (logout)
  clearEncryptionData: () => {
    clientEncryption.clearStoredData();
    set({
      privateKey: null,
      publicKey: null,
      keyVersion: 1,
      hasKeys: false,
      encryptionStatus: {},
      securitySettings: {
        allowScreenshots: true,
        defaultMessageTTL: 0,
        encryptionEnabled: true,
        requireEncryption: false
      }
    });
  },

  // Utility functions for message encryption/decryption
  encryptMessage: (message, receiverPublicKey) => {
    try {
      const privateKey = get().privateKey;
      if (!privateKey) {
        throw new Error('No private key available for encryption');
      }

      // For now, using client-side encryption as backup
      // In production, this would use the hybrid encryption system
      const sessionPassword = clientEncryption.generateSessionPassword();
      const encryptedMessage = clientEncryption.encryptMessageLocal(message, sessionPassword);
      
      return {
        encryptedContent: encryptedMessage,
        sessionKey: sessionPassword,
        algorithm: 'AES-256',
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('Failed to encrypt message:', error);
      throw error;
    }
  },

  decryptMessage: (encryptedData) => {
    try {
      const { encryptedContent, sessionKey } = encryptedData;
      return clientEncryption.decryptMessageLocal(encryptedContent, sessionKey);
    } catch (error) {
      console.error('Failed to decrypt message:', error);
      throw error;
    }
  },

  // Check if message is expired
  isMessageExpired: (expiresAt) => {
    return clientEncryption.isMessageExpired(expiresAt);
  },

  // Format expiration time
  formatExpirationTime: (expiresAt) => {
    return clientEncryption.formatExpirationTime(expiresAt);
  },

  // Create expiration time
  createExpirationTime: (ttlSeconds) => {
    return clientEncryption.createExpirationTime(ttlSeconds);
  }
}));
