import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    fullName: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    profilePic: {
      type: String,
      default: "",
    },
    // Encryption & Security Fields
    publicKey: {
      type: String,
      default: "",
    },
    keyVersion: {
      type: Number,
      default: 1,
    },
    securitySettings: {
      allowScreenshots: {
        type: Boolean,
        default: true,
      },
      messageTTL: {
        type: String,
        default: '30s', // Default to 30 seconds
      },
      encryptionEnabled: {
        type: Boolean,
        default: true,
      },
      requireEncryption: {
        type: Boolean,
        default: false,
      },
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

export default User;
