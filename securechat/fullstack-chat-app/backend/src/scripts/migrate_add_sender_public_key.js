// Usage: node migrate_add_sender_public_key.js
import mongoose from 'mongoose';
import Message from '../models/message.model.js';
import User from '../models/user.model.js';
import dotenv from 'dotenv';

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/your-db';

async function migrate() {
  await mongoose.connect(MONGO_URI);
  console.log('Connected to MongoDB');

  const now = new Date();
  const messages = await Message.find({ $or: [ { senderPublicKey: { $exists: false } }, { senderPublicKey: '' } ] });
  console.log(`Found ${messages.length} messages to update.`);

  let updated = 0;
  for (const msg of messages) {
    const sender = await User.findById(msg.senderId);
    if (sender && sender.publicKey) {
      msg.senderPublicKey = sender.publicKey;
      // Set expiresAt to 30 seconds from now if not already set
      if (!msg.expiresAt) {
        msg.expiresAt = new Date(now.getTime() + 30 * 1000);
      }
      await msg.save();
      updated++;
      console.log(`Updated message ${msg._id}`);
    } else {
      console.log(`Could not find public key for sender ${msg.senderId} (message ${msg._id})`);
    }
  }

  console.log(`Migration complete! Updated ${updated} messages.`);
  process.exit();
}

migrate().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
}); 