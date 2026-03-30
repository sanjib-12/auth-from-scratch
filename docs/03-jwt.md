# Phase 4 — JSON Web Tokens (JWT)

## The Problem: The Server Remembers Too Much

In Phases 2 and 3, we built a session system. On login, the server generates a random Session ID, stores it in an in-memory `Map`, and hands the ID to the browser as a cookie. Every subsequent request, the server looks up that ID in its `Map` to figure out who you are.

This works. But it has a fundamental limitation: **the server is stateful**.

Picture a popular coffee chain. When you buy a loyalty card at one store, they write your name in a ledger behind the counter. Next time you visit that same store, they look you up. But walk into a different branch? They have no idea who you are — their ledger is separate.

This is exactly what happens with in-memory sessions:

- **Server crashes?** The `Map` is wiped. Every user is logged out.
- **Two servers behind a load balancer?** Server A created your session, but Server B has never seen it. Your request fails.
- **Memory pressure?** Every active session consumes server memory. A million concurrent users means a million entries in your `Map`.

The solution: stop making the server remember anything. Instead, give the user a **self-contained proof of identity** — a digitally signed document that carries all the information the server needs, and that the server can verify without looking anything up.

That document is a **JSON Web Token (JWT)**.

---

## What Is a JWT?

A JWT is a compact, URL-safe string made of three parts separated by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiY3NyZiI6ImFiYzEyMyIsImlhdCI6MTcxMjAwMDAwMCwiZXhwIjoxNzEyMDAwMzAwfQ.s5rQ_K3m7X...
|_____________HEADER______________|.__________________PAYLOAD___________________|._SIGNATURE_|
```

Each part is **Base64URL-encoded** (a URL-safe variant of Base64 — no `+`, `/`, or `=` padding). When decoded:

### 1. Header — "How is this signed?"

```json
{ "alg": "HS256", "typ": "JWT" }
```

- `alg` — The signing algorithm. `HS256` means HMAC using SHA-256.
- `typ` — The token type. Always `"JWT"`.

### 2. Payload — "Who is this, and for how long?"

```json
{
  "sub": "user@example.com",
  "csrf": "a1b2c3d4e5f6...",
  "iat": 1712000000,
  "exp": 1712000300
}
```

| Claim | Full Name   | Purpose                                         |
| ----- | ----------- | ----------------------------------------------- |
| `sub` | Subject     | Who the token identifies (the user's email)     |
| `csrf`| —           | The CSRF token (our custom claim — more on this)|
| `iat` | Issued At   | Unix timestamp of when the token was created    |
| `exp` | Expiration  | Unix timestamp after which the token is invalid |

**The payload is NOT encrypted.** Anyone can decode it and read the claims. Never put secrets (passwords, API keys) in a JWT payload. The signature guarantees the payload hasn't been *tampered with*, not that it's *hidden*.

### 3. Signature — "Has this been tampered with?"

```
HMAC-SHA256(
  base64url(header) + "." + base64url(payload),
  SECRET_KEY
)
```

The server takes the encoded header and payload, concatenates them with a dot, and runs HMAC-SHA256 using a secret key that only the server knows. The result is the signature.

When verifying, the server re-computes this signature from the header and payload in the incoming token. If the re-computed signature matches the one attached to the token, the payload is authentic. If even a single character of the payload was changed, the signatures won't match — the token is rejected.

---

## The Mental Model: A Signed Letter vs. A Coat Check Ticket

**Sessions (Phase 2-3)** were like a coat check ticket. The ticket itself is meaningless — just a number. The value is in the ledger behind the counter that maps the number to your coat. Lose the ledger, lose everything.

**JWT** is like a signed letter from the manager. The letter says "This person is user@example.com, and they're allowed in until 3:05 PM." It's stamped with the manager's unique seal. Any guard can read the letter, verify the seal, and let you in — no need to call the manager or check a ledger. But if someone tries to alter the letter (change the email, extend the time), the seal won't match, and the guard knows it's a forgery.

---

## Stateful vs. Stateless Authentication

| Aspect                | Sessions (Phase 2-3)                      | JWT (Phase 4)                              |
| --------------------- | ----------------------------------------- | ------------------------------------------ |
| **Where is auth data?**| Server memory (`Map`)                    | Inside the token itself                    |
| **Server stores**     | Session ID → { email, csrf, expiry }      | Nothing                                    |
| **Verification**      | Lookup in `Map`                           | Re-compute signature, check expiry         |
| **Scalability**       | Requires shared store (Redis) for multi-server | Any server with the secret key can verify |
| **Revocation**        | Delete from `Map` → instant               | Can't revoke until expiry (no server state)|
| **Server restart**    | All users logged out                      | Users stay authenticated                   |

The trade-off is clear: JWT gains **statelessness** at the cost of **revocability**. Once issued, a JWT is valid until it expires. There's no server-side "delete" button. This is why JWT expiration times are kept short (we use 5 minutes), and why Phase 5 (Refresh Tokens) will introduce a mechanism to renew them.

---

## HMAC-SHA256: The Signing Algorithm

HMAC (Hash-based Message Authentication Code) combines a hash function with a secret key to produce a signature. Here's the intuition:

1. **SHA-256 alone** produces a hash of any input. But anyone can compute it — there's no secret. An attacker could modify the payload and recompute the hash.
2. **HMAC-SHA256** mixes a **secret key** into the hashing process. Only someone who knows the key can produce a valid signature. Only someone who knows the key can verify one.

```
HMAC(key, message) = SHA256((key ⊕ opad) || SHA256((key ⊕ ipad) || message))
```

You don't need to memorize this formula. The key insight: **HMAC makes the hash unforgeable without the secret key.** It's the digital equivalent of the manager's unique seal on the signed letter.

### Why HMAC (Symmetric) and Not RSA (Asymmetric)?

- **HMAC (HS256)**: One secret key for both signing and verifying. Simple. Fast. Perfect when the same server that issues the token also verifies it.
- **RSA (RS256)**: A private key signs, a public key verifies. Useful when a central auth server issues tokens, and many downstream services verify them without needing the private key.

We use HMAC because our system is a single server — the same process that creates the JWT also verifies it. No need for the complexity of asymmetric cryptography.

---

## Architecture Overview

```mermaid
sequenceDiagram
    participant Browser
    participant Server

    Note over Browser,Server: 1. Login (Token Issuance)
    Browser->>Server: POST /login { email, password }
    Server-->>Server: Verify credentials (Phase 1)
    Server-->>Server: Generate csrfToken (32 random bytes → hex)
    Server-->>Server: Create JWT { sub: email, csrf: csrfToken, iat, exp }
    Server-->>Server: Sign JWT with HMAC-SHA256 (SECRET_KEY)
    Server->>Browser: 200 OK + Set-Cookie: jwt=... (HttpOnly) + Set-Cookie: csrfToken=... (JS-readable)

    Note over Browser,Server: 2. Protected Request (Token Verification)
    Browser-->>Browser: Read csrfToken from cookie via JS
    Browser->>Server: GET /profile + Cookie: jwt=... + Header: X-CSRF-Token: <token>
    Server-->>Server: Extract JWT from cookie
    Server-->>Server: Split into header.payload.signature
    Server-->>Server: Re-compute signature → timing-safe compare
    Server-->>Server: Decode payload → check exp > now
    Server-->>Server: Compare payload.csrf vs X-CSRF-Token header
    alt All checks pass
        Server->>Browser: 200 OK (Profile Data)
    else Signature invalid / Expired / CSRF mismatch
        Server->>Browser: 401 Unauthorized
    end

    Note over Browser,Server: 3. Logout (Client-Side Cleanup)
    Browser->>Server: POST /logout + Cookie: jwt=... + X-CSRF-Token header
    Server-->>Server: Verify JWT + CSRF (same checks)
    Server->>Browser: 204 No Content + Clear both cookies (Max-Age=0)
    Note over Server: No server-side state to delete!
```

---

## Key Concepts Learned

### 1. Building a JWT by Hand

We don't use any JWT library. Every step is explicit in `jwt-service.ts`:

```typescript
// jwt-service.ts
export function createToken(email: string, csrfToken: string): string {
   const header = { alg: "HS256", typ: "JWT" };
   const now = Math.floor(Date.now() / 1000);
   const payload: JwtPayload = {
      sub: email,
      csrf: csrfToken,
      iat: now,
      exp: now + TokenDurationSeconds, // 300 seconds = 5 minutes
   };

   const headerB64 = base64url(JSON.stringify(header));
   const payloadB64 = base64url(JSON.stringify(payload));
   const signature = createSignature(headerB64, payloadB64);

   return `${headerB64}.${payloadB64}.${signature}`;
}
```

Step by step:
1. **Serialize** the header and payload to JSON strings.
2. **Encode** each with Base64URL.
3. **Sign** the concatenation `headerB64.payloadB64` using HMAC-SHA256.
4. **Concatenate** all three parts with dots.

Why build it by hand? Because JWT libraries are black boxes. Understanding the three-part structure, the encoding, and the signing makes you a better engineer — and lets you debug token issues without guessing.

### 2. Base64URL Encoding

Standard Base64 uses `+`, `/`, and `=` (padding). These characters have special meanings in URLs and HTTP headers. Base64URL replaces them:

| Standard Base64 | Base64URL |
| --------------- | --------- |
| `+`             | `-`       |
| `/`             | `_`       |
| `=` (padding)   | removed   |

Node.js supports this natively:

```typescript
function base64url(input: Buffer | string): string {
   const buf = typeof input === "string" ? Buffer.from(input) : input;
   return buf.toString("base64url");
}
```

### 3. The Secret Key

```typescript
const SECRET_KEY = crypto.randomBytes(64).toString("hex");
```

- **64 random bytes** → 128-character hex string → 512 bits of entropy.
- Generated once when the server starts using the OS cryptographic random number generator.
- This key is the only thing preventing token forgery. If an attacker learns the key, they can mint valid JWTs for any user.

**Current limitation:** Because the key is generated at startup, restarting the server invalidates all existing JWTs (the new key won't match signatures created with the old one). In production, the key would be loaded from an environment variable or a secrets manager so it persists across restarts.

### 4. Token Verification — Trust Nothing

Verification is the most security-critical function:

```typescript
// jwt-service.ts
export function verifyToken(token: string): JwtPayload | null {
   const parts = token.split(".");
   if (parts.length !== 3) return null;

   const [headerB64, payloadB64, signatureB64] = parts;

   // Re-compute the expected signature
   const expectedSignature = createSignature(headerB64, payloadB64);

   // Timing-safe comparison
   const sigBuffer = Buffer.from(signatureB64, "base64url");
   const expectedBuffer = Buffer.from(expectedSignature, "base64url");
   if (sigBuffer.length !== expectedBuffer.length) return null;
   if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) return null;

   // Only AFTER signature is verified, parse the payload
   let payload: JwtPayload;
   try {
      const parsed = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
      if (!isJwtPayload(parsed)) return null;
      payload = parsed;
   } catch {
      return null;
   }

   // Check expiration
   const now = Math.floor(Date.now() / 1000);
   if (payload.exp <= now) return null;

   return payload;
}
```

The order matters:

1. **Structure check** — Must have exactly 3 dot-separated parts.
2. **Signature verification** — Re-compute and compare. Uses `timingSafeEqual` to prevent timing attacks (same reason as Phase 1's password comparison).
3. **Payload parsing** — Only parse the JSON *after* the signature is verified. Parsing untrusted data before verifying the signature opens the door to injection attacks.
4. **Expiration check** — The `exp` claim is a Unix timestamp. If the current time is past it, reject.
5. **Type guard** — `isJwtPayload` ensures the parsed object has the expected shape with correct types.

Every failure returns `null` — no error messages, no hints. The caller gets "valid payload" or "nothing."

### 5. CSRF Protection Inside the JWT

This is where Phase 4 gets clever. In Phase 3, the CSRF token lived in the server-side session store. Now there's no server-side store. So where does the CSRF token go?

**Inside the JWT payload.**

```typescript
// auth-service.ts (login)
const csrfToken = crypto.randomBytes(32).toString("hex");
const jwt = createToken(normalizedEmail, csrfToken);

return {
   statusCode: 200,
   statusMsg: "Login Successful",
   token: jwt,        // Contains the CSRF token, signed and sealed
   csrfToken,         // Also sent as a JS-readable cookie
};
```

The flow:
1. On login, the server generates a random CSRF token.
2. The CSRF token is embedded in the JWT payload (`csrf` claim) and signed.
3. The JWT goes into an `HttpOnly` cookie (JavaScript can't read it).
4. The same CSRF token goes into a separate, JS-readable cookie.

On every protected request:
1. The browser sends the JWT cookie automatically.
2. The frontend reads the CSRF cookie and sends it as an `X-CSRF-Token` header.
3. The server verifies the JWT, extracts the `csrf` claim, and compares it to the header.

This is a variation of the **Double Submit Cookie** pattern. But unlike the classic version (where both cookies are compared directly), our server-side "copy" of the CSRF token is **tamper-proof** — it's locked inside a signed JWT. An attacker can't modify the JWT's `csrf` claim without invalidating the signature.

### 6. Why Deliver JWT in a Cookie (Not the Authorization Header)?

You'll often see tutorials that send JWTs in the `Authorization: Bearer <token>` header, with the token stored in `localStorage`. We deliberately chose cookies. Here's why:

| Delivery Method         | XSS Risk                                  | CSRF Risk                      |
| ----------------------- | ----------------------------------------- | ------------------------------ |
| `localStorage` + Header | **High** — JS can read `localStorage`     | None (not sent automatically)  |
| `HttpOnly` Cookie       | **Low** — JS cannot read `HttpOnly` cookies| Exists (sent automatically)    |

- With `localStorage`, a single XSS vulnerability (injected `<script>` tag) can steal the JWT and send it to an attacker's server. Game over.
- With an `HttpOnly` cookie, XSS *cannot* read the token. The trade-off is that cookies are sent automatically, creating CSRF risk — but we mitigate that with the CSRF token pattern from Phase 3.

**We chose the attack surface we can defend.** CSRF is preventable with a well-implemented token pattern. Preventing all XSS in a complex application is much harder.

### 7. Stateless Logout

In Phase 2-3, logout meant deleting the session from the server's `Map`. With JWT, there's no server-side state to delete:

```typescript
// auth-route.ts
export function handleLogout(req: IncomingMessage, res: ServerResponse) {
   const auth = requireAuth(req, res);
   if (auth === null) return;

   res.setHeader("Set-Cookie", [clearJwtCookie(), clearCsrfCookie()]);
   res.writeHead(204);
   res.end();
}
```

Logout simply clears the cookies on the client. The JWT still technically "exists" and would be valid if someone had copied it — but it's removed from the browser, and it expires in at most 5 minutes anyway.

This is an inherent limitation of stateless auth: **you can't truly revoke a JWT before its expiration**. In production, techniques like short expiry times (done), token denylist (adds back state), or refresh token rotation (Phase 5) mitigate this.

### 8. The Refactored Session Guard

The guard moved from `sessions/session-guard.ts` to `jwt/session-guard.ts` and now works entirely without server-side lookups:

```typescript
// jwt/session-guard.ts
export function requireAuth(req: IncomingMessage, res: ServerResponse): SessionInfo | null {
   // 1. Is the X-CSRF-Token header present?
   const tokenFromHeader = req.headers["x-csrf-token"];
   if (typeof tokenFromHeader !== "string") { /* 401 */ }

   // 2. Is there a valid JWT in the cookie?
   const cookies = parseCookies(req.headers.cookie);
   const token = cookies.jwt;
   if (!token) { /* 401 */ }

   // 3. Does the JWT's signature check out? Is it unexpired?
   const payload = verifyToken(token);
   if (!payload) { /* 401 */ }

   // 4. Does the CSRF token in the JWT match the one in the header?
   const isTokenValid = compareCsrfToken(payload.csrf, tokenFromHeader);
   if (!isTokenValid) { /* 401 */ }

   return { email: payload.sub };
}
```

Four checks, zero database/store lookups:
1. CSRF header present?
2. JWT cookie present?
3. JWT signature valid + not expired?
4. CSRF token in JWT matches CSRF token in header?

All failures return the same `401 Unauthorized`. No information leakage.

---

## What Changed from Phase 3

| Component                          | Phase 3 (Sessions)                           | Phase 4 (JWT)                                |
| ---------------------------------- | -------------------------------------------- | -------------------------------------------- |
| **Auth data storage**              | `sessions/session-store.ts` (in-memory `Map`)| No server-side storage                       |
| **Session guard**                  | `sessions/session-guard.ts`                  | `jwt/session-guard.ts`                       |
| **Token creation**                 | `crypto.randomUUID()` (opaque session ID)    | `jwt-service.ts` (signed JWT)                |
| **CSRF token storage**             | Inside the session `Map` entry               | Inside the JWT payload (`csrf` claim)        |
| **CSRF verification**              | Compare header vs. session store lookup      | Compare header vs. JWT payload claim         |
| **Cookie name**                    | `sessionId`                                  | `jwt`                                        |
| **Login response**                 | Sets `sessionId` + `csrfToken` cookies       | Sets `jwt` + `csrfToken` cookies             |
| **Logout**                         | Deletes session from `Map` + clears cookies  | Clears cookies only (nothing to delete)      |
| **Server restart impact**          | All sessions lost                            | JWTs invalid (key regenerated at startup)    |

**Files removed:**
- `Backend/src/sessions/session-store.ts` — the in-memory `Map` store is gone
- `Backend/src/sessions/session-guard.ts` — replaced by `jwt/session-guard.ts`

**Files added:**
- `Backend/src/jwt/jwt-service.ts` — JWT creation, verification, and type guard
- `Backend/src/jwt/session-guard.ts` — auth guard using JWT verification

---

## Request Flow

### Login (`POST /login`) — JWT Issuance

```
1. Client sends { email, password }
2. Server verifies credentials (Phase 1 logic)
3. Server generates csrfToken (32 random bytes → hex)
4. Server creates JWT:
   - Header: { alg: "HS256", typ: "JWT" }
   - Payload: { sub: email, csrf: csrfToken, iat: now, exp: now + 300 }
   - Signature: HMAC-SHA256(header.payload, SECRET_KEY)
5. Server responds with two Set-Cookie headers:
   - jwt=<signed-token> ; HttpOnly; Path=/; SameSite=Strict
   - csrfToken=<token>  ; Path=/; SameSite=Strict  ← JS-readable
6. Returns 200 "Login Successful"
```

### Protected Request (`GET /profile`) — JWT Verification

```
1. Frontend reads csrfToken from document.cookie
2. Frontend sends GET /profile with:
   - Cookie: jwt=... (automatic)
   - Header: X-CSRF-Token: <token> (explicit)
3. session-guard.ts → checks X-CSRF-Token header exists
4. session-guard.ts → parses jwt from cookie
5. jwt-service.ts → splits token into 3 parts
6. jwt-service.ts → re-computes signature, timing-safe compares
7. jwt-service.ts → decodes payload, validates shape via type guard
8. jwt-service.ts → checks exp > now
9. session-guard.ts → timing-safe compares payload.csrf vs header token
10. If all pass → returns profile data ({ email })
11. If any fail → 401 Unauthorized
```

### Logout (`POST /logout`) — Cookie Cleanup

```
1. Frontend reads csrfToken, sends POST /logout with Cookie + X-CSRF-Token header
2. session-guard.ts → verifies JWT + CSRF (same checks as above)
3. Server clears both cookies (Max-Age=0)
4. Returns 204 No Content
   (No server-side state to clean up — JWT is simply discarded)
```

---

## Security Measures Implemented

| Measure                           | Where                          | What It Prevents                             |
| --------------------------------- | ------------------------------ | -------------------------------------------- |
| HMAC-SHA256 signing               | `jwt-service.ts`               | Token forgery / payload tampering            |
| `crypto.timingSafeEqual`          | `jwt-service.ts`               | Timing attacks on signature comparison       |
| 5-minute token expiration         | `jwt-service.ts`               | Stolen tokens usable indefinitely            |
| Signature-first verification      | `jwt-service.ts`               | Parsing untrusted payloads before validation |
| Type guard on payload             | `jwt-service.ts`               | Malformed or injected payload claims         |
| 512-bit random secret key         | `jwt-service.ts`               | Key brute-forcing                            |
| CSRF token in JWT payload         | `jwt-service.ts`, `auth-service.ts` | CSRF without server-side state          |
| `crypto.timingSafeEqual` (CSRF)   | `csrf-token-verification.ts`   | Timing attacks on CSRF comparison            |
| HttpOnly JWT cookie               | `cookie.ts`                    | XSS stealing the JWT                         |
| Non-HttpOnly CSRF cookie          | `cookie.ts`                    | Allows JS to read token for header echo      |
| `SameSite=Strict` on both         | `cookie.ts`                    | Cross-site cookie leakage                    |
| Identical 401 for all failures    | `session-guard.ts`             | Information leakage about failure reason      |

---

## File Reference

| File                                              | Phase 4 Role                                          |
| ------------------------------------------------- | ----------------------------------------------------- |
| `Backend/src/jwt/jwt-service.ts`                  | JWT creation (sign), verification, type guard         |
| `Backend/src/jwt/session-guard.ts`                | Auth guard — verifies JWT + CSRF on protected routes  |
| `Backend/src/services/auth-service.ts`            | Generates CSRF token, creates JWT on login            |
| `Backend/src/utils/csrf-token-verification.ts`    | Timing-safe CSRF token comparison                     |
| `Backend/src/utils/cookie.ts`                     | Builds/clears JWT and CSRF cookies                    |
| `Backend/src/routers/auth-route.ts`               | Sets both cookies on login, clears both on logout     |
| `Backend/src/routers/profile-route.ts`            | Uses `requireAuth` (JWT + CSRF) for protection        |
| `Backend/src/server.ts`                           | CORS headers, routing                                 |
| `Backend/src/types/auth-types.ts`                 | `ServiceResult` includes `token` + `csrfToken` fields |
| `Frontend/src/api.ts`                             | Reads CSRF cookie, sends `X-CSRF-Token` header        |

---

## Known Limitations (Addressed in Later Phases)

- **No token refresh** — JWTs expire after 5 minutes with no renewal mechanism. The user must re-login. → Phase 5 (Refresh Tokens)
- **No true revocation** — A stolen JWT is valid until it expires. There's no server-side denylist. → Phase 5 partially addresses this with refresh token rotation.
- **Secret key regenerated on restart** — Restarting the server invalidates all existing JWTs. In production, the key should be loaded from an environment variable or secrets manager.
- **No multi-factor auth** — Password is still the only authentication factor. → Phase 6 (MFA)
- **No `Secure` flag on cookies** — We're running over HTTP in development. In production, cookies must include `Secure` to prevent transmission over unencrypted connections.
- **No `alg: none` protection** — Our hand-rolled implementation doesn't accept an `alg` field from the incoming token (we always re-compute with HS256), so we're naturally immune. But this is a notorious JWT vulnerability worth knowing: some libraries accept `alg: "none"` and skip signature verification entirely.
