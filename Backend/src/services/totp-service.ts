import crypto from "crypto";

const TOTP_CONFIG = {
   secretBytes: 20,
   digits: 6,
   stepSeconds: 30,
   window: 1,
} as const;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buffer: Buffer): string {
   let bits = "";
   for (const byte of buffer) {
      bits += byte.toString(2).padStart(8, "0");
   }

   while (bits.length % 5 !== 0) bits += "0";

   let result = "";
   for (let i = 0; i < bits.length; i += 5) {
      const index = parseInt(bits.slice(i, i + 5), 2);
      result += BASE32_ALPHABET[index];
   }
   return result;
}

export function base32Decode(encoded: string): Buffer {
   let bits = "";
   for (const char of encoded.toUpperCase()) {
      const index = BASE32_ALPHABET.indexOf(char);
      if (index === -1) continue;
      bits += index.toString(2).padStart(5, "0");
   }
   const bytes: number[] = [];
   for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
   }
   return Buffer.from(bytes);
}

export function generateTotpSecret(): string {
   return base32Encode(crypto.randomBytes(TOTP_CONFIG.secretBytes));
}

function generateHotp(secret: Buffer, counter: number): string {
   const counterBuffer = Buffer.alloc(8, 0);
   counterBuffer.writeUInt32BE(counter, 4);
   const hmac = crypto.createHmac("sha1", secret).update(counterBuffer).digest();
   const offset = hmac[hmac.length - 1] & 0x0f;
   const code =
      ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
   return (code % 10 ** TOTP_CONFIG.digits).toString().padStart(TOTP_CONFIG.digits, "0");
}

export function verifyTotp(secretBase32: string, code: string): boolean {
   if (!/^\d{6}$/.test(code)) return false;

   const secret = base32Decode(secretBase32);
   const currentStep = Math.floor(Date.now() / 1000 / TOTP_CONFIG.stepSeconds);

   for (let i = -TOTP_CONFIG.window; i <= TOTP_CONFIG.window; i++) {
      const expected = generateHotp(secret, currentStep + i);
      if (timingSafeCompare(expected, code)) return true;
   }
   return false;
}

function timingSafeCompare(a: string, b: string): boolean {
   if (a.length !== b.length) return false;
   return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function buildOtpauthUri(email: string, secretBase32: string): string{
   const issuer = "AuthFromScratch";
   return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_CONFIG.digits}&period=${TOTP_CONFIG.stepSeconds}`;
}
