# Auth from Scratch

A hands-on project to learn authentication concepts by building them from scratch — no frameworks, no magic. Each phase adds one layer of real-world auth on top of the previous one.

## Phases

| Phase | Topic                                        | Status      |
| ----- | -------------------------------------------- | ----------- |
| 1     | [Password Hashing](docs/01-password-auth.md) | ✅ Done     |
| 2     | [Sessions](docs/02-session.md)               | ✅ Done     |
| 3     | [CSRF Protection](docs/03-csrf-protection.md) | ✅ Done     |
| 4     | [JWT](docs/04-jwt.md)                        | ✅ Done     |
| 5     | [Refresh Tokens](docs/05-refresh-token.md)   | ✅ Done     |
| 6     | MFA                                          | ⬜ Upcoming |
| 7     | OAuth                                        | ⬜ Upcoming |
| 8     | WebAuthn                                     | ⬜ Upcoming |

## Tech Stack

- **Frontend** — Vanilla TypeScript, plain HTML/CSS, no bundler
- **Backend** — Node.js `http` module (no Express), TypeScript
- **Storage** — Flat-file JSON (`db/users.json`)
- **Hashing** — Node.js `crypto` (PBKDF2-SHA512, 600K iterations)

## Project Structure

```
auth/
├── Frontend/
│   ├── public/
│   │   ├── login.html
│   │   ├── signup.html
│   │   └── dashboard.html
│   ├── src/
│   │   ├── api.ts            # Fetch wrapper + CSRF handling + silent refresh
│   │   ├── login.ts          # Login form handler
│   │   ├── signup.ts         # Signup form handler
│   │   ├── dashboard.ts      # Dashboard: profile loading + logout
│   │   └── types/user.ts     # Frontend interfaces
│   └── package.json
│
├── Backend/
│   ├── src/
│   │   ├── server.ts                          # HTTP server + CORS + routing
│   │   ├── routers/auth-route.ts              # Signup/login/logout routing
│   │   ├── routers/profile-route.ts           # Protected profile endpoint
│   │   ├── routers/refresh-route.ts           # Refresh token rotation endpoint
│   │   ├── services/auth-service.ts           # Signup/login logic + JWT + refresh issuance
│   │   ├── services/password-service.ts       # Hashing + validation
│   │   ├── services/refresh-token-service.ts  # Refresh token creation, rotation, revocation
│   │   ├── jwt/jwt-service.ts                 # JWT creation, verification (HMAC-SHA256)
│   │   ├── jwt/session-guard.ts               # Auth guard (JWT + CSRF validation)
│   │   ├── middleware/body-parser.ts          # JSON body parser (with size limit)
│   │   ├── middleware/cookie-parser.ts        # HTTP cookie parser
│   │   ├── middleware/require-json.ts         # Content-Type enforcement
│   │   ├── utils/cookie.ts                    # Cookie builder/clearer (JWT + CSRF + refresh)
│   │   ├── utils/csrf-token-verification.ts   # Timing-safe CSRF token comparison
│   │   ├── utils/read-write.ts                # File-based user storage
│   │   └── types/auth-types.ts                # Backend interfaces + type guards
│   ├── db/
│   │   ├── users.json                         # User data store
│   │   └── refresh-tokens.json                # Hashed refresh token store
│   └── package.json
│
└── docs/
    ├── 01-password-auth.md    # Phase 1 — Password Authentication
    ├── 02-session.md          # Phase 2 — Sessions
    ├── 03-csrf-protection.md  # Phase 3 — CSRF Protection
    ├── 04-jwt.md              # Phase 4 — JSON Web Tokens
    └── 05-refresh-token.md    # Phase 5 — Refresh Tokens
```

## Getting Started

### Prerequisites

- Node.js (v18+)

### Setup

```bash
# Install backend dependencies
cd Backend
npm install

# No frontend dependencies to install (vanilla TS)
```

### Running

Open two terminals:

```bash
# Terminal 1 — Compile backend (watch mode)
cd Backend
npm run dev

# Terminal 2 — Run backend server (auto-restarts on changes)
cd Backend
npm run dev:server
```

For the frontend:

```bash
# Terminal 3 — Compile frontend (watch mode)
cd Frontend
npm run dev
```

Then open `Frontend/public/login.html` or `signup.html` in a browser.

### Endpoints

| Method | Path       | Description                        | Auth Required |
| ------ | ---------- | ---------------------------------- | ------------- |
| `POST` | `/signup`  | Create a new account               | No            |
| `POST` | `/login`   | Authenticate with email + password | No            |
| `GET`  | `/profile` | Get authenticated user profile     | JWT + CSRF    |
| `POST` | `/logout`  | End session and clear cookies      | JWT + CSRF    |
| `POST` | `/refresh` | Rotate refresh token + issue new JWT | Refresh cookie |

`/signup` and `/login` expect `Content-Type: application/json` with body:

```json
{ "email": "user@example.com", "password": "your-password" }
```

## Documentation

Each phase has a detailed doc explaining **what** was built and **why** each decision was made:

- [Phase 1 — Password Authentication](docs/01-password-auth.md)
- [Phase 2 — Sessions](docs/02-session.md)
- [Phase 3 — CSRF Protection](docs/03-csrf-protection.md)
- [Phase 4 — JSON Web Tokens](docs/04-jwt.md)
- [Phase 5 — Refresh Tokens](docs/05-refresh-token.md)
