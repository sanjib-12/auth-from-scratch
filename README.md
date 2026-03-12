# Auth from Scratch

A hands-on project to learn authentication concepts by building them from scratch — no frameworks, no magic. Each phase adds one layer of real-world auth on top of the previous one.

## Phases

| Phase | Topic                                        | Status      |
| ----- | -------------------------------------------- | ----------- |
| 1     | [Password Hashing](docs/01-password-auth.md) | ✅ Done     |
| 2     | [Sessions](docs/02-session.md)               | ✅ Done     |
| 3     | CSRF Protection                              | ⬜ Upcoming |
| 4     | JWT                                          | ⬜ Upcoming |
| 5     | Refresh Tokens                               | ⬜ Upcoming |
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
│   │   ├── api.ts            # Fetch wrapper
│   │   ├── login.ts          # Login form handler
│   │   ├── signup.ts         # Signup form handler
│   │   └── types/user.ts     # Frontend interfaces
│   └── package.json
│
├── Backend/
│   ├── src/
│   │   ├── server.ts                  # HTTP server + CORS + routing
│   │   ├── routers/auth.ts            # Input validation + routing
│   │   ├── services/auth-service.ts   # Signup/login logic
│   │   ├── services/password-service.ts # Hashing + validation
│   │   ├── utils/bodyParser.ts        # JSON body parser (with size limit)
│   │   ├── utils/readWrite.ts         # File-based user storage
│   │   └── types/user.ts             # Backend interfaces + type guards
│   ├── db/users.json
│   └── package.json
│
└── docs/
    └── 01-password-auth.md   # Phase 1 documentation
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

| Method | Path      | Description                        |
| ------ | --------- | ---------------------------------- |
| `POST` | `/signup` | Create a new account               |
| `POST` | `/login`  | Authenticate with email + password |

Both expect `Content-Type: application/json` with body:

```json
{ "email": "user@example.com", "password": "your-password" }
```

## Documentation

Each phase has a detailed doc explaining **what** was built and **why** each decision was made:

- [Phase 1 — Password Authentication](docs/01-password-auth.md)
- [Phase 2 — Sessions](docs/02-session.md)
