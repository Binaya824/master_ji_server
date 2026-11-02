# MasterJi OMR Scanner — Server

A Node.js + Express + MongoDB REST API for the MasterJi OMR scanner app.

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express
- **Database**: MongoDB via Mongoose
- **Auth**: JWT (jsonwebtoken) + bcryptjs
- **Security**: express-rate-limit, cors

---

## Setup

### 1. Install dependencies

```bash
cd server
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in real values:

| Variable        | Description                                  |
|-----------------|----------------------------------------------|
| `PORT`          | Port the server listens on (default `3000`)  |
| `MONGODB_URI`   | MongoDB connection string                    |
| `JWT_SECRET`    | Long random string used to sign JWTs         |
| `ADMIN_SECRET`  | Secret header value for admin endpoints      |

### 3. Start the server

**Development (auto-reload):**
```bash
npm run dev
```

**Production:**
```bash
npm start
```

---

## API Reference

All routes are prefixed with `/api`.

### Auth

| Method | Endpoint            | Auth     | Description              |
|--------|---------------------|----------|--------------------------|
| POST   | `/api/auth/register`| None     | Register a new user      |
| POST   | `/api/auth/login`   | None     | Login (rate-limited)     |

### Admin

| Method | Endpoint                | Auth           | Description            |
|--------|-------------------------|----------------|------------------------|
| POST   | `/api/admin/issue-key`  | x-admin-secret | Issue a demo/paid key  |

---

## Membership Types

| Type   | Secret Key Prefix | Scans      | Expiry       |
|--------|-------------------|------------|--------------|
| `demo` | `sk_demo_`        | 20 scans   | None         |
| `paid` | `sk_paid_`        | Unlimited  | 30 days      |
| `none` | —                 | —          | —            |

---

## Device Binding

A user account is bound to the first device that logs in. Subsequent logins from a different `deviceId` are rejected with a `403 device_mismatch` error until an admin resets the device.
