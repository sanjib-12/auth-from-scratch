# Phase 1 — Password Authentication

## What This Phase Covers

Building a complete signup/login system from scratch using **password hashing** — no frameworks, no libraries (except Node.js built-ins). The goal is to understand _why_ each piece exists before moving on to sessions, tokens, and beyond.

---

## Architecture Overview

```
Frontend (Vanilla TS)              Backend (Node.js HTTP)
┌─────────────┐                    ┌──────────────────────┐
│ signup.html  │──── POST /signup ──▶│  server.ts           │
│ login.html   │──── POST /login  ──▶│    ↓                 │
│ dashboard.html│                    │  routers/auth.ts     │
│              │                    │    ↓                 │
│ src/api.ts   │◀── JSON response ──│  services/           │
│ src/login.ts │                    │    auth-service.ts   │
│ src/signup.ts│                    │    password-service.ts│
│ src/types/   │                    │  utils/              │
│   user.ts    │                    │    bodyParser.ts     │
└─────────────┘                    │    readWrite.ts      │
                                   │  db/users.json       │
                                   └──────────────────────┘
```

---

## Key Concepts Learned

### 1. Why Hash Passwords?

Storing passwords in plain text means a single database breach exposes every user's password. Hashing is a **one-way function** — you can turn a password into a hash, but you can't turn a hash back into a password. Even if the database leaks, attackers only get hashes.

### 2. Why Not SHA256 / MD5?

These are **fast** hash functions — designed for file integrity, not passwords. An attacker with a GPU can compute billions of SHA256 hashes per second. Password hashing must be **deliberately slow** to make brute-forcing impractical.

### 3. PBKDF2 (Password-Based Key Derivation Function 2)

We use `crypto.pbkdf2` from Node.js. It works by applying a hash function (SHA-512) **hundreds of thousands of times** in a loop.

```typescript
// password-service.ts
const HASH_CONFIG = {
   saltBytes: 16,
   iterations: 600_000, // OWASP 2026 recommendation
   keyLength: 64,
   digest: "sha512",
} as const;
```

- **`iterations: 600_000`** — Each hash computation runs SHA-512 600K times. This makes each attempt take ~200-500ms, which is fine for legitimate login but catastrophic for brute-forcing.
- **`keyLength: 64`** — Output is 64 bytes (512 bits) of derived key.
- **`digest: "sha512"`** — The underlying hash function used per iteration.

### 4. Per-User Salt

A **salt** is a random value mixed into the hash. Without a salt, two users with the password `"password123"` would have identical hashes — attackers could use precomputed **rainbow tables** to look them up instantly.

```typescript
const salt = crypto.randomBytes(16).toString("hex");
const hash = await pbkdf2Async(password, salt, ...);
return `${salt}:${hash.toString("hex")}`;
// Stored as: "a1b2c3d4...:e5f6a7b8..."
```

Each user gets a unique random salt, so identical passwords produce completely different hashes.

### 5. Timing-Safe Comparison

```typescript
crypto.timingSafeEqual(hash, originBuffer);
```

Normal `===` comparison returns `false` as soon as it finds the first mismatched byte. An attacker could measure response times to figure out how many bytes matched — this is called a **timing attack**. `timingSafeEqual` always takes the same amount of time regardless of where the mismatch is.

### 6. Password Validation

```typescript
function validatePassword(password: string): string | null {
   if (password.length < 8) return "Password must be at least 8 characters";
   if (password.length > 72) return "Password must not exceed 72 characters";
   return null;
}
```

- **Min 8 chars** — Short passwords are trivially guessable even with strong hashing.
- **Max 72 chars** — Extremely long passwords add no real security but can cause performance issues with key derivation. The upper bound is a practical limit.
- **No character class rules** — Modern research (NIST SP 800-63B) shows that forcing uppercase/symbols leads to predictable patterns (`Password1!`). Length matters more than complexity.

### 7. Email Validation & Normalization

```typescript
// Validation — reject obviously invalid input
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Normalization — prevent duplicate accounts from case differences
const normalizedEmail = email.trim().toLowerCase();
```

The backend **never trusts the client**. The HTML `type="email"` is a convenience for users, not a security measure. An attacker can send any string via `curl`.

### 8. Preventing User Enumeration

Both "user not found" and "wrong password" return the same response:

```typescript
return { statusCode: 401, statusMsg: "Invalid credentials!" };
```

If login returned "User not found" vs "Wrong password", an attacker could probe which emails are registered. By returning an identical message, we reveal nothing.

---

## Request Flow

### Signup (`POST /signup`)

```
1. Client sends { email, password } as JSON
2. server.ts → routes to handleAuthRouter
3. auth.ts  → validates Content-Type is application/json
4. auth.ts  → parses body via bodyParser (with 1MB size limit)
5. auth.ts  → validates shape via isAuthPayload (type guard + email regex)
6. auth-service.ts → normalizes email to lowercase
7. auth-service.ts → validates password length (8-72 chars)
8. auth-service.ts → checks if email already exists → 409 if duplicate
9. password-service.ts → generates random salt + hashes password (PBKDF2, 600K iterations)
10. readWrite.ts → appends user to users.json
11. Returns 201 "Signup Successful"
```

### Login (`POST /login`)

```
1. Client sends { email, password } as JSON
2. server.ts → routes to handleAuthRouter
3. auth.ts  → validates Content-Type + parses + validates shape
4. auth-service.ts → normalizes email to lowercase
5. auth-service.ts → looks up user by email → 401 if not found
6. password-service.ts → re-derives hash from input password + stored salt
7. password-service.ts → timing-safe comparison of hashes
8. Returns 200 "Login Successful" or 401 "Invalid credentials!"
```

---

## Security Measures Implemented

| Measure                        | Where                 | What It Prevents                     |
| ------------------------------ | --------------------- | ------------------------------------ |
| PBKDF2 with 600K iterations    | `password-service.ts` | Brute-force attacks                  |
| Per-user random salt           | `password-service.ts` | Rainbow table attacks                |
| `crypto.timingSafeEqual`       | `password-service.ts` | Timing attacks                       |
| Password length validation     | `password-service.ts` | Weak passwords                       |
| Email regex validation         | `types/user.ts`       | Malformed input                      |
| Email case normalization       | `auth-service.ts`     | Duplicate accounts                   |
| Identical error messages       | `auth-service.ts`     | User enumeration                     |
| Content-Type check             | `routers/auth.ts`     | Invalid content parsing              |
| Body size limit (1MB)          | `bodyParser.ts`       | Denial-of-service via large payloads |
| Method enforcement (POST only) | `server.ts`           | Unintended HTTP methods              |

---

## File Reference

| File                                       | Purpose                                                |
| ------------------------------------------ | ------------------------------------------------------ |
| `Frontend/public/signup.html`              | Signup form UI                                         |
| `Frontend/public/login.html`               | Login form UI                                          |
| `Frontend/public/dashboard.html`           | Post-login placeholder page                            |
| `Frontend/src/api.ts`                      | `postRequest()` — generic fetch wrapper                |
| `Frontend/src/login.ts`                    | Login form submit handler                              |
| `Frontend/src/signup.ts`                   | Signup form submit handler                             |
| `Frontend/src/types/user.ts`               | `UserCredentials`, `ApiResponse` interfaces            |
| `Backend/src/server.ts`                    | HTTP server, CORS, routing                             |
| `Backend/src/routers/auth.ts`              | Content-Type check, body parsing, input validation     |
| `Backend/src/services/auth-service.ts`     | Signup/login business logic                            |
| `Backend/src/services/password-service.ts` | Hashing, comparison, password validation               |
| `Backend/src/utils/bodyParser.ts`          | Stream-based JSON body parser with size limit          |
| `Backend/src/utils/readWrite.ts`           | File-based user storage (read/write JSON)              |
| `Backend/src/types/user.ts`                | `User`, `AuthPayload`, `isAuthPayload`, `isValidEmail` |
| `Backend/db/users.json`                    | User data store (flat file)                            |

---

## Known Limitations (Addressed in Later Phases)

- **No session management** — Login succeeds but there's no way to "stay logged in" → Phase 2 (Sessions)
- **No CSRF protection** — Forms are vulnerable to cross-site request forgery → Phase 3 (CSRF)
- **No token-based auth** — No stateless authentication for APIs → Phase 4 (JWT)
- **No token refresh** — No mechanism to renew expired tokens → Phase 5 (Refresh)
- **No multi-factor auth** — Password is the only authentication factor → Phase 6 (MFA)
- **No OAuth** — No third-party login (Google, GitHub, etc.) → Phase 7 (OAuth)
- **No WebAuthn** — No passwordless/biometric authentication → Phase 8 (WebAuthn)
- **File-based storage** — `users.json` has race conditions under concurrent writes. A real database solves this with atomic operations and locking.
