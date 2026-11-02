const mongoose = require('mongoose');

const MEMBERSHIP_TYPES = ['none', 'demo', 'paid'];
const SECRET_KEY_TYPES = ['demo', 'paid'];

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
    },
    mobile: {
      type: String,
      required: [true, 'Mobile number is required'],
      unique: true,
      trim: true,
    },
    passwordHash: {
      type: String,
      required: [true, 'Password hash is required'],
    },
    deviceId: {
      type: String,
      default: null,
    },
    loginedAt: {
      type: Date,
      default: null,
    },
    flagged: {
      type: Boolean,
      default: false, // > = 3 logins within 5 days from the same device (reinstall farming)
    },
    loginHistory: {
      type: [Date],
      default: [], // last ~10 login timestamps (no scan count stored — abuse detection only)
    },
    accessToken: {
      type: String,
      default: null,
    },
    accessTokenExpiresAt: {
      type: Date,
      default: null,
    },
    secretKey: {
      type: String,
      default: null,
    },
    secretKeyType: {
      type: String,
      enum: [...SECRET_KEY_TYPES, null],
      default: null,
    },
    secretKeyExpiresAt: {
      type: Date,
      default: null, // null for demo; 30-day expiry for paid
    },
    demoCompleted: {
      type: Boolean,
      default: false, // set true when the app reports the 20 demo scans are used up
    },
    membershipType: {
      type: String,
      enum: MEMBERSHIP_TYPES,
      default: 'none',
    },
    membershipExpiresAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('User', userSchema);
