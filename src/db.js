const mongoose = require('mongoose');

/**
 * Connects to MongoDB using the MONGODB_URI from environment variables.
 * Exits the process if the connection fails.
 */
async function connectDB() {
  const uri = process.env.MONGODB_URI;

  if (!uri) {
    console.error('[DB] MONGODB_URI is not set in environment variables.');
    process.exit(1);
  }

  try {
    await mongoose.connect(uri);
    console.log('[DB] Connected to MongoDB:', mongoose.connection.host);
  } catch (err) {
    console.error('[DB] Connection error:', err.message);
    process.exit(1);
  }
}

module.exports = connectDB;
