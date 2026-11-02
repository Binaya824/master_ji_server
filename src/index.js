require('dotenv').config();

const express = require('express');
const cors = require('cors');

const connectDB = require('./db');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();

// ---------------------------------------------------------------------------
// Global Middleware
// ---------------------------------------------------------------------------
app.use(cors());
app.use(express.json());

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);

// Health check
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'not_found', message: 'Route not found.' });
});

// Global error handler
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[Unhandled Error]', err);
  res.status(500).json({ error: 'server_error', message: 'An unexpected error occurred.' });
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;

(async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`[Server] MasterJi API running on http://localhost:${PORT}`);
  });
})();
