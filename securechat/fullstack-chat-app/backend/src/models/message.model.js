import mongoose from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    // Only store encrypted content
    encryptedContent: {
      type: String,
      required: true,
      description: 'Encrypted message content (text/image/file)',
    },
    image: {
      type: String,
    },
    // Encryption & Security Fields
    isEncrypted: {
      type: Boolean,
      default: false,
    },
    encryptedContent: {
      type: String, // Will store encrypted text/image data
    },
    keyVersion: {
      type: Number,
      default: 1,
    },
    expiresAt: {
      type: Date,
      default: null, // null = no expiration
    },
    messageType: {
      type: String,
      enum: ['text', 'image', 'file'],
      default: 'text',
    },
    isVerified: {
      type: Boolean,
    isEncrypted: {
      type: Boolean,
      default: true,
      description: 'Always true, as only encrypted messages are stored',
    },
    },
    senderPublicKey: {
      type: String,
      default: '',
      description: 'Sender ECC public key for decryption',
    },
  },
  { timestamps: true }
);

// TTL Index for automatic message deletion
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Message = mongoose.model("Message", messageSchema);

export default Message;
