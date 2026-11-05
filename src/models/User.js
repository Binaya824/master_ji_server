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
      default: false, // legacy reinstall-farming flag; nothing sets this anymore
    },
    loginHistory: {
      type: [Date],
      default: [], // legacy; unused
    },
    nullKeyLoginCount: {
      type: Number,
      default: 0, // consecutive non-first logins with no cached secret_key/membership_type — a wiped device re-logging in to farm a fresh demo count
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
    resetDemo: {
      type: Boolean,
      default: false, // admin-set: next login gives a demo account a fresh 20-scan count and skips the device-binding/ban checks once; consumed (reset to false) after use
    },
    resendSecretKey: {
      type: Boolean,
      default: false, // admin-set: next login's secret_key/membership_type resend to the device isn't counted toward the demo-farming guard; consumed (reset to false) after use
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('User', userSchema);
