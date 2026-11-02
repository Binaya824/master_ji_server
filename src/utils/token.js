const jwt = require('jsonwebtoken');

const JWT_TTL_DAYS = 5;

/**
 * Signs a JWT for the given user.
 * @param {object} user - Mongoose User document
 * @param {string} deviceId
 * @returns {{ token: string, expiresAt: Date }}
 */
function signToken(user, deviceId) {
  const payload = {
    sub: user._id.toString(),
    mobile: user.mobile,
    membershipType: user.membershipType,
    deviceId,
  };

  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: `${JWT_TTL_DAYS}d`,
  });

  const expiresAt = new Date(Date.now() + JWT_TTL_DAYS * 24 * 60 * 60 * 1000);

  return { token, expiresAt };
}

/**
 * Verifies a JWT and returns the decoded payload.
 * Throws if invalid or expired.
 * @param {string} token
 * @returns {object} decoded payload
 */
function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

module.exports = { signToken, verifyToken };
