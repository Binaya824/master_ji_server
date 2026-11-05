const express = require('express');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');

const router = express.Router();

/**
 * Middleware: validates the x-admin-secret header.
 */
function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'];

  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'Invalid or missing admin secret.',
    });
  }

  next();
}

// ---------------------------------------------------------------------------
// POST /api/admin/issue-key
// ---------------------------------------------------------------------------
router.post('/issue-key', adminAuth, async (req, res) => {
  try {
    const { mobile, type } = req.body;

    if (!mobile || !type) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'mobile and type are required.' });
    }

    if (!['demo', 'paid'].includes(type)) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'type must be "demo" or "paid".' });
    }

    const user = await User.findOne({ mobile: mobile.trim() });
    if (!user) {
      return res
        .status(404)
        .json({ error: 'not_found', message: 'No user found with that mobile number.' });
    }

    const keyId = uuidv4();
    const secretKey = type === 'demo' ? `sk_demo_${keyId}` : `sk_paid_${keyId}`;
    const now = new Date();

    user.secretKey = secretKey;
    user.secretKeyType = type;

    if (type === 'demo') {
      user.secretKeyExpiresAt = null;
      user.demoCompleted = false;
      user.membershipType = 'demo';
      user.membershipExpiresAt = null;
    } else {
      // paid
      const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // +30 days
      user.secretKeyExpiresAt = expiresAt;
      user.demoCompleted = false;
      user.membershipType = 'paid';
      user.membershipExpiresAt = expiresAt;
    }

    await user.save();

    return res.status(200).json({
      secretKey: user.secretKey,
      secretKeyType: user.secretKeyType,
      secretKeyExpiresAt: user.secretKeyExpiresAt,
      membershipType: user.membershipType,
    });
  } catch (err) {
    console.error('[AdminIssueKey]', err);
    return res.status(500).json({ error: 'server_error', message: 'Failed to issue key.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/admin/clear-flag
// ---------------------------------------------------------------------------
// Un-flags an account that was auto-flagged for reinstall farming, after the
// admin has decided it is a legitimate user. Also wipes login history so the
// count starts clean.
router.post('/clear-flag', adminAuth, async (req, res) => {
  try {
    const { mobile } = req.body;
    if (!mobile) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'mobile is required.' });
    }

    const user = await User.findOne({ mobile: mobile.trim() });
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'No user found.' });
    }

    user.flagged = false;
    user.loginHistory = [];
    await user.save();

    return res.status(200).json({ success: true, message: 'Flag cleared.' });
  } catch (err) {
    console.error('[AdminClearFlag]', err);
    return res.status(500).json({ error: 'server_error', message: 'Failed to clear flag.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/admin/reset-demo
// ---------------------------------------------------------------------------
// Schedules a one-shot demo-scan reset: on the account's next login (while
// still membershipType 'demo'), the device gets a fresh 20-scan count and
// that login skips the device-binding/ban checks once. Consumed automatically
// on that next login - no need to clear it manually.
router.post('/reset-demo', adminAuth, async (req, res) => {
  try {
    const { mobile } = req.body;
    if (!mobile) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'mobile is required.' });
    }

    const user = await User.findOne({ mobile: mobile.trim() });
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'No user found.' });
    }

    user.resetDemo = true;
    await user.save();

    return res
      .status(200)
      .json({ success: true, message: 'Demo reset scheduled for next login.' });
  } catch (err) {
    console.error('[AdminResetDemo]', err);
    return res.status(500).json({ error: 'server_error', message: 'Failed to schedule demo reset.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/admin/resend-secret-key
// ---------------------------------------------------------------------------
// Schedules a one-shot secret-key resend: on the account's next login, that
// login isn't counted toward the demo-farming guard even if the device shows
// up with nothing cached (expected, since that's usually why this was asked
// for). The account's current secret_key/membership_type go out in the
// response as usual. Consumed automatically on that next login.
router.post('/resend-secret-key', adminAuth, async (req, res) => {
  try {
    const { mobile } = req.body;
    if (!mobile) {
      return res
        .status(400)
        .json({ error: 'validation_error', message: 'mobile is required.' });
    }

    const user = await User.findOne({ mobile: mobile.trim() });
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'No user found.' });
    }

    user.resendSecretKey = true;
    await user.save();

    return res
      .status(200)
      .json({ success: true, message: 'Secret key resend scheduled for next login.' });
  } catch (err) {
    console.error('[AdminResendSecretKey]', err);
    return res.status(500).json({ error: 'server_error', message: 'Failed to schedule secret key resend.' });
  }
});

module.exports = router;
