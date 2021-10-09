const mongoose = require('mongoose');

const { Schema } = mongoose;

const emailValidSchema = new Schema({
  userId: { type: String, required: true },
  token: { type: String, required: true, unique: true },
}, { timestamps: true });

emailValidSchema.index({ createdAt: 1 }, { expireAfterSeconds: 1800 });

const EmailValid = mongoose.model('EmailValid', emailValidSchema);

module.exports = EmailValid;
