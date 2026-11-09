const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const User = require('../models/User');
const { signToken, verifyToken } = require('../utils/token');

const router = express.Router();

// Constant-time string compare, used so a mismatching secret_key can't be
// distinguished from a matching one by response-time (same reasoning as
// comparing passwords/tokens: short-circuiting `===` leaks a timing signal).
function secretsEqual(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Rate limiter: max 10 login attempts per 15 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'too_many_requests',
    message: 'Too many login attempts. Please try again after 15 minutes.',
  },
});

// ---------------------------------------------------------------------------
// POST /api/auth/register
// ---------------------------------------------------------------------------
router.post('/register', async (req, res) => {
  try {
    const { name, mobile, password } = req.body;

    // --- Validation ---
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: 'validation_error', message: 'Name is required.' });
    }

    if (!mobile || !/^\d{10}$/.test(mobile.trim())) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'Mobile must be exactly 10 digits.' });
    }

    if (!password || password.length < 6) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'Password must be at least 6 characters.' });
    }

    // --- Duplicate check ---
    const existing = await User.findOne({ mobile: mobile.trim() });
    if (existing) {
      return res
        .status(409)
        .json({ error: 'mobile_exists', message: 'An account with this mobile number already exists.' });
    }

    // --- Hash password ---
    const passwordHash = await bcrypt.hash(password, 10);

    // --- Generate a demo secret key for the new user ---
    // Every new registration defaults to membershipType 'demo' with a demo
    // secret key (sk_demo_<uuid>) valid for 30 days. The 20-scan limit is
    // tracked on-device; once done, the app reports it and the key is cleared
    // server-side (see POST /api/auth/demo-completed).
    const secretKey = `sk_demo_${uuidv4()}`;
    const demoExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // +30 days

    // --- Create user ---
    await User.create({
      name: name.trim(),
      mobile: mobile.trim(),
      passwordHash,
      membershipType: 'demo',
      secretKey,
      secretKeyType: 'demo',
      secretKeyExpiresAt: demoExpiresAt,
      demoCompleted: false,
    });

    return res.status(201).json({ success: true, message: 'Registered successfully.' });
  } catch (err) {
    console.error('[Register]', err);
    return res.status(500).json({ error: 'server_error', message: 'Registration failed.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const mobile = req.body.mobile;
    const password = req.body.password;
    const deviceId = req.body.deviceId || req.body.device_id;

    if (!mobile || !password || !deviceId) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'mobile, password, and deviceId are required.' });
    }

    const user = await User.findOne({ mobile: mobile.trim() });
    if (!user) {
      return res
        .status(401)
        .json({ error: 'invalid_credentials', message: 'Invalid mobile or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res
        .status(401)
        .json({ error: 'invalid_credentials', message: 'Invalid mobile or password.' });
    }

    // An admin-triggered demo reset on a demo account is a deliberate
    // override (e.g. "let them back in on their new phone, give them a
    // fresh demo run") - it skips the device-binding and ban checks below
    // for this one login. Read before either check runs; consumed further
    // down once the reset is actually applied.
    const resetDemoOverride = user.resetDemo && user.membershipType === 'demo';

    // --- Device binding ---
    if (!resetDemoOverride && user.deviceId && user.deviceId !== deviceId) {
      return res.status(403).json({
        error: 'device_mismatch',
        message: 'This account is linked to another device. Contact admin.',
      });
    }

    // Bind device if not yet set, or unconditionally when the override
    // above means this may be a new device for the account.
    if (!user.deviceId || resetDemoOverride) {
      user.deviceId = deviceId;
    }

    // Already-banned accounts stay banned. Nothing sets `flagged` anymore
    // (the login-history/time-window check that used to is gone, per the
    // new guard below), but an account flagged before this change — or by
    // an admin — must not quietly regain access just because the
    // mechanism that originally flagged it was removed. The reset override
    // still bypasses this, same as the device check above.
    if (user.flagged && !resetDemoOverride) {
      return res.status(403).json({
        error: 'account_violation',
        message: 'Your account has been flagged for violating app usage rules. Please contact admin.',
      });
    }

    const now = new Date();
    const isFirstLogin = user.loginedAt == null;

    // --- Demo-scan-farming guard ---------------------------------------------
    // The app sends whatever secret_key/membership_type it currently has
    // cached on-device with every login. A legitimate user always has one
    // after their first login; both coming back null on a LATER login means
    // local storage was wiped (reinstall, cleared app data, ...) — the
    // classic way to farm a fresh 20-scan demo count. Track consecutive
    // occurrences and zero out the demo count once it happens too often,
    // instead of blocking on a login-history time window.
    const clientSecretKey = req.body.secret_key || req.body.secretKey || null;
    const clientMembershipType =
      req.body.membership_type || req.body.membershipType || null;
    let forceDemoScansZero = false;

    // An admin-triggered resend means the device is *expected* to show up
    // with nothing cached (that's the whole point) — this login's null
    // key/membership shouldn't count as a farming attempt.
    const skipFarmingGuard = resetDemoOverride || user.resendSecretKey;

    // Only a key that actually matches what's on file resets the streak -
    // anything else (absent, or present-but-wrong) is treated the same way,
    // so sending fabricated non-null junk can't dodge detection any better
    // than sending null outright.
    const keyMatches =
      Boolean(clientSecretKey) &&
      Boolean(clientMembershipType) &&
      secretsEqual(clientSecretKey, user.secretKey) &&
      clientMembershipType === user.membershipType;

    if (keyMatches) {
      user.nullKeyLoginCount = 0;
    } else if (!isFirstLogin && !skipFarmingGuard) {
      user.nullKeyLoginCount = (user.nullKeyLoginCount || 0) + 1;
      if (user.nullKeyLoginCount > 3 && user.membershipType === 'demo') {
        forceDemoScansZero = true;
      }
    }

    // --- Backfill / demo handling: legacy users created before demo keys
    // existed get a fresh demo key.

    const demoExpired =
      user.secretKeyType === 'demo' &&
      user.secretKeyExpiresAt != null &&
      now > user.secretKeyExpiresAt;

    if (user.demoCompleted || demoExpired) {
      // Mark demo as finished in the DB so it stays finished on future logins.
      if (!user.demoCompleted) {
        user.demoCompleted = true;
      }
      user.secretKey = null;
      user.secretKeyType = null;
      user.secretKeyExpiresAt = null;
      user.membershipType = 'none';
    } else if (!user.secretKey || !user.secretKeyType) {
      user.secretKey = `sk_demo_${uuidv4()}`;
      user.secretKeyType = 'demo';
      user.secretKeyExpiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      user.membershipType = 'demo';
    }

    // --- Consume the one-shot admin flags -------------------------------------
    // Both were only read above (resetDemoOverride, skipFarmingGuard); clear
    // them now so they fire exactly once, on this login.
    const applyDemoReset = resetDemoOverride; // already required membershipType === 'demo'
    if (user.resetDemo) user.resetDemo = false;
    if (user.resendSecretKey) user.resendSecretKey = false;

    // --- Generate JWT ---
    // First-ever login? Then the server hands the demo scan count to the app
    // once; after that the count lives purely on-device and is never sent.
    const { token, expiresAt } = signToken(user, deviceId);

    // --- Persist session info ---
    user.accessToken = token;
    user.accessTokenExpiresAt = expiresAt;
    user.loginedAt = now;
    await user.save();

    // Resolve the one demo_scans_remaining value to send, if any - an
    // explicit admin reset always wins over the automatic farming-guard
    // zero-out, which in turn only applies on later (non-first) logins.
    let demoScansOverride = null;
    if (isFirstLogin && user.secretKeyType === 'demo') demoScansOverride = 20;
    if (forceDemoScansZero) demoScansOverride = 0;
    if (applyDemoReset) demoScansOverride = 20;

    // Response uses snake_case to match the Flutter client's _saveAuthData parser.
    return res.status(200).json({
      access_token: token,
      expires_at: expiresAt.toISOString(),
      secret_key: user.secretKey,
      secret_key_type: user.secretKeyType,
      secret_key_expiry: user.secretKeyExpiresAt ? user.secretKeyExpiresAt.toISOString() : null,
      ...(demoScansOverride !== null
          ? { demo_scans_remaining: demoScansOverride }
          : {}),
      membership_type: user.membershipType,
      name: user.name,
      mobile: user.mobile,
      user: {
        name: user.name,
        mobile: user.mobile,
      },
    });
  } catch (err) {
    console.error('[Login]', err);
    return res.status(500).json({ error: 'server_error', message: 'Login failed.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/demo-completed
// ---------------------------------------------------------------------------
// The app tracks the 20 demo scans purely on-device. When the local count
// reaches 0, the app calls this endpoint once so the server can mark that
// account's demo as finished (clearing the key server-side too). Auth is the
// device's already-issued access token — no extra credentials needed.
const demoAuth = (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
  if (!token) {
    return res.status(401).json({ error: 'unauthorized', message: 'Access token required.' });
  }
  try {
    const decoded = verifyToken(token);
    req.userId = decoded.sub;
    req.payload = decoded;
    next();
  } catch (_err) {
    return res
      .status(401)
      .json({ error: 'unauthorized', message: 'Access token invalid or expired.' });
  }
};

router.post('/demo-completed', demoAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'No user found.' });
    }

    // Optional device check: token was bound to one deviceId at login.
    if (user.deviceId && req.payload.deviceId && user.deviceId !== req.payload.deviceId) {
      return res.status(403).json({ error: 'device_mismatch', message: 'Device mismatch.' });
    }

    user.demoCompleted = true;
    user.secretKey = null;
    user.secretKeyType = null;
    user.secretKeyExpiresAt = null;
    user.membershipType = 'none';
    await user.save();

    return res.status(200).json({ success: true, message: 'Demo marked as completed.' });
  } catch (err) {
    console.error('[DemoCompleted]', err);
    return res.status(500).json({ error: 'server_error', message: 'Failed to mark demo completed.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/delete-account
// DELETE /api/auth/delete-account
// ---------------------------------------------------------------------------
// Play Store policy requirement: permanently deletes the user account & data.
const handleDeleteAccount = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res
        .status(404)
        .json({ error: 'not_found', message: 'Account not found or already deleted.' });
    }

    await User.findByIdAndDelete(req.userId);
    console.log(`[DeleteAccount] Permanently deleted user: ${user.mobile} (${user._id})`);

    return res
      .status(200)
      .json({ success: true, message: 'Account deleted successfully.' });
  } catch (err) {
    console.error('[DeleteAccount]', err);
    return res.status(500).json({ error: 'server_error', message: 'Failed to delete account.' });
  }
};

router.post('/delete-account', demoAuth, handleDeleteAccount);
router.delete('/delete-account', demoAuth, handleDeleteAccount);

module.exports = router;
