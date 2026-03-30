import crypto from "crypto";

const SECRET_KEY = crypto.randomBytes(64).toString("hex");
const TokenDurationSeconds = 300;

interface JwtPayload {
   sub: string;
   csrf: string;
   iat: number;
   exp: number;
}

function base64url(input: Buffer | string): string {
   const buf = typeof input === "string" ? Buffer.from(input) : input;
   return buf.toString("base64url");
}

function createSignature(headerB64: string, payloadB64: string): string {
   return crypto.createHmac("sha256", SECRET_KEY).update(`${headerB64}.${payloadB64}`).digest("base64url");
}

export function createToken(email: string, csrfToken: string): string {
   const header = { alg: "HS256", typ: "JWT" };
   const now = Math.floor(Date.now() / 1000);
   const payload: JwtPayload = {
      sub: email,
      csrf: csrfToken,
      iat: now,
      exp: now + TokenDurationSeconds,
   };

   const headerB64 = base64url(JSON.stringify(header));
   const payloadB64 = base64url(JSON.stringify(payload));
   const signature = createSignature(headerB64, payloadB64);

   return `${headerB64}.${payloadB64}.${signature}`;
}

export function verifyToken(token: string): JwtPayload | null {
   const parts = token.split(".");

   if (parts.length !== 3) return null;

   const [headerB64, payloadB64, signatureB64] = parts;

   const expectedSignature = createSignature(headerB64, payloadB64);

   const sigBuffer = Buffer.from(signatureB64, "base64url");
   const expectedBuffer = Buffer.from(expectedSignature, "base64url");

   if (sigBuffer.length !== expectedBuffer.length) return null;
   if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) return null;

   let payload: JwtPayload;

   try {
      const parsed = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
      if (!isJwtPayload(parsed)) return null;
      payload = parsed;
   } catch {
      return null;
   }

   const now = Math.floor(Date.now() / 1000);
   if (payload.exp <= now) return null;

   return payload;
}

function isJwtPayload(obj: unknown): obj is JwtPayload {
   return (
      typeof obj === "object" &&
      obj !== null &&
      typeof (obj as any).sub === "string" &&
      typeof (obj as any).csrf === "string" &&
      typeof (obj as any).iat === "number" &&
      typeof (obj as any).exp === "number"
   );
}
