const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const User = require('../models/User');
const { signToken, verifyToken } = require('../utils/token');

const router = express.Router();

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

    // --- Device binding ---
    if (user.deviceId && user.deviceId !== deviceId) {
      return res.status(403).json({
        error: 'device_mismatch',
        message: 'This account is linked to another device. Contact admin.',
      });
    }

    // Bind device if not yet set
    if (!user.deviceId) {
      user.deviceId = deviceId;
    }

    const now = new Date();

    // --- Anti-reinstall-flagging (Option B) ----------------------------------
    // The access token lives exactly 5 days and the app has no manual logout,
    // so a legitimate user logs in at most once every ~5 days — meaning at most
    // 2 logins can fall inside any 5-day window. A 3rd login from the same
    // device inside 5 days is only possible via uninstall/reinstall loops
    // (fresh token after every reinstall), so the account gets flagged.
    const WINDOW_MS = 5 * 24 * 60 * 60 * 1000;

    user.loginHistory = [now, ...user.loginHistory].slice(0, 10);
    const recentLogins = user.loginHistory.filter(
      (t) => t.getTime() > now.getTime() - WINDOW_MS
    );

    if (user.flagged) {
      await user.save();
      return res.status(403).json({
        error: 'account_violation',
        message: 'Your account has been flagged for violating app usage rules. Please contact admin.',
      });
    }

    if (recentLogins.length >= 3) {
      user.flagged = true;
      user.secretKey = null;
      user.secretKeyType = null;
      user.secretKeyExpiresAt = null;
      user.membershipType = 'none';
      await user.save();
      return res.status(403).json({
        error: 'account_violation',
        message: 'Your account has been flagged for violating app usage rules. Please contact admin.',
      });
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

    // --- Generate JWT ---
    // First-ever login? Then the server hands the demo scan count to the app
    // once; after that the count lives purely on-device and is never sent.
    const isFirstLogin = user.loginedAt == null;
    const { token, expiresAt } = signToken(user, deviceId);

    // --- Persist session info ---
    user.accessToken = token;
    user.accessTokenExpiresAt = expiresAt;
    user.loginedAt = now;
    await user.save();

    // Response uses snake_case to match the Flutter client's _saveAuthData parser.
    // demo_scans_remaining is sent ONLY on the first login (new users pick up
    // the starting 20 from the server); on later logins the field is absent
    // and the device-local count takes over.
    return res.status(200).json({
      access_token: token,
      expires_at: expiresAt.toISOString(),
      secret_key: user.secretKey,
      secret_key_type: user.secretKeyType,
      secret_key_expiry: user.secretKeyExpiresAt ? user.secretKeyExpiresAt.toISOString() : null,
      ...(isFirstLogin && user.secretKeyType === 'demo'
          ? { demo_scans_remaining: 20 }
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

module.exports = router;
