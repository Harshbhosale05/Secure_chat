import express from "express";
import { protectRoute } from "../middleware/auth.middleware.js";
import keyManager from "../lib/keyManager.js";
import encryptionManager from "../lib/encryption.js";

const router = express.Router();

// Generate new encryption keys for user
router.post("/generate-keys", protectRoute, async (req, res) => {
  try {
    const { keyType = 'ECC' } = req.body;
    const userId = req.user._id;

    const userKeys = await keyManager.generateUserKeys(userId, keyType);

    res.status(200).json({
      message: "Encryption keys generated successfully",
      keys: {
        privateKey: userKeys.privateKey,
        publicKey: userKeys.publicKey,
        keyType: userKeys.keyType,
        keyVersion: userKeys.keyVersion
      }
    });
  } catch (error) {
    console.error("Error generating keys:", error.message);
    res.status(500).json({ message: "Failed to generate encryption keys" });
  }
});

// Get user's public key
router.get("/public-key/:userId", protectRoute, async (req, res) => {
  try {
    let { userId } = req.params;
    if (userId === 'me') {
      userId = req.user._id;
    }
    const publicKeyData = await keyManager.getUserPublicKey(userId);

    res.status(200).json(publicKeyData);
  } catch (error) {
    console.error("Error fetching public key:", error.message);
    res.status(404).json({ message: "Public key not found" });
  }
});

// Get multiple users' public keys
router.post("/public-keys", protectRoute, async (req, res) => {
  try {
    const { userIds } = req.body;
    if (!Array.isArray(userIds)) {
      return res.status(400).json({ message: "userIds must be an array" });
    }

    const publicKeys = await keyManager.getMultiplePublicKeys(userIds);
    res.status(200).json(publicKeys);
  } catch (error) {
    console.error("Error fetching public keys:", error.message);
    res.status(500).json({ message: "Failed to fetch public keys" });
  }
});

// Rotate user's encryption keys
router.post("/rotate-keys", protectRoute, async (req, res) => {
  try {
    const { keyType = 'ECC' } = req.body;
    const userId = req.user._id;

    const newKeys = await keyManager.rotateUserKeys(userId, keyType);

    res.status(200).json({
      message: "Keys rotated successfully",
      keys: {
        privateKey: newKeys.privateKey,
        publicKey: newKeys.publicKey,
        keyType: newKeys.keyType,
        keyVersion: newKeys.keyVersion,
        rotatedAt: newKeys.rotatedAt
      }
    });
  } catch (error) {
    console.error("Error rotating keys:", error.message);
    res.status(500).json({ message: "Failed to rotate encryption keys" });
  }
});

// Check if key rotation is needed
router.get("/check-rotation", protectRoute, async (req, res) => {
  try {
    const userId = req.user._id;
    const needsRotation = await keyManager.isKeyRotationNeeded(userId);

    res.status(200).json({ needsRotation });
  } catch (error) {
    console.error("Error checking key rotation:", error.message);
    res.status(500).json({ message: "Failed to check key rotation status" });
  }
});

// Get user's security settings
router.get("/security-settings", protectRoute, async (req, res) => {
  try {
    const userId = req.user._id;
    const settings = await keyManager.getUserSecuritySettings(userId);

    res.status(200).json(settings);
  } catch (error) {
    console.error("Error fetching security settings:", error.message);
    res.status(500).json({ message: "Failed to fetch security settings" });
  }
});

// Update user's security settings
router.put("/security-settings", protectRoute, async (req, res) => {
  try {
    const userId = req.user._id;
    const settings = req.body;

    // Validate TTL value
    const allowedTTLs = ['10s', '30s', '1m', '2m', 'never'];
    if (settings.messageTTL && !allowedTTLs.includes(settings.messageTTL)) {
      return res.status(400).json({ message: "Invalid TTL value" });
    }

    const updatedSettings = await keyManager.updateSecuritySettings(userId, settings);

    res.status(200).json({
      message: "Security settings updated successfully",
      settings: updatedSettings
    });
  } catch (error) {
    console.error("Error updating security settings:", error.message);
    res.status(500).json({ message: "Failed to update security settings" });
  }
});

// Create key exchange session for new conversation
router.post("/key-exchange", protectRoute, async (req, res) => {
  try {
    const { receiverId } = req.body;
    const senderId = req.user._id;

    if (!receiverId) {
      return res.status(400).json({ message: "receiverId is required" });
    }

    const keyExchange = await keyManager.createKeyExchangeSession(senderId, receiverId);

    res.status(200).json(keyExchange);
  } catch (error) {
    console.error("Error creating key exchange:", error.message);
    res.status(500).json({ message: "Failed to create key exchange session" });
  }
});

// Test encryption/decryption (for development/testing)
router.post("/test-encryption", protectRoute, async (req, res) => {
  try {
    const { message, receiverPublicKey, senderPrivateKey } = req.body;

    if (!message || !receiverPublicKey || !senderPrivateKey) {
      return res.status(400).json({ 
        message: "message, receiverPublicKey, and senderPrivateKey are required" 
      });
    }

    // Encrypt message
    const encrypted = encryptionManager.encryptMessage(message, receiverPublicKey, senderPrivateKey);
    
    // Test decryption (in real app, this would be done by receiver)
    const decrypted = encryptionManager.decryptMessage(encrypted, receiverPublicKey, senderPrivateKey);

    res.status(200).json({
      original: message,
      encrypted,
      decrypted,
      success: message === decrypted
    });
  } catch (error) {
    console.error("Error testing encryption:", error.message);
    res.status(500).json({ message: "Encryption test failed", error: error.message });
  }
});

// Get encryption status for conversation
router.get("/encryption-status/:receiverId", protectRoute, async (req, res) => {
  try {
    const senderId = req.user._id;
    const { receiverId } = req.params;

    const [isRequired, senderSettings, receiverPublicKey] = await Promise.all([
      keyManager.isEncryptionRequired(senderId, receiverId),
      keyManager.getUserSecuritySettings(senderId),
      keyManager.getUserPublicKey(receiverId).catch(() => null)
    ]);

    res.status(200).json({
      encryptionRequired: isRequired,
      encryptionEnabled: senderSettings.encryptionEnabled,
      receiverHasKeys: !!receiverPublicKey,
      canEncrypt: !!(senderSettings.encryptionEnabled && receiverPublicKey)
    });
  } catch (error) {
    console.error("Error checking encryption status:", error.message);
    res.status(500).json({ message: "Failed to check encryption status" });
  }
});

export default router;
