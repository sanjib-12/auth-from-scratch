import crypto from "crypto";
import { readEmailOtps, writeEmailOtps, readUsers, writeUsers } from "../utils/read-write";
import { sendOtpEmail } from "./email-service";
import { timingSafeEqual } from "../utils/csrf-token-verification";

const OTP_TTL_MS = 10 * 60 * 1000;

const OTP_RESEND_COOLDOWN_MS = 60 * 1000;

function hashCode(code: string): string {
   return crypto.createHash("sha256").update(code).digest("hex");
}

export async function enableEmailOtp(email: string): Promise<boolean> {
   const users = await readUsers();
   const user = users.find((u) => u.email === email);
   if (!user) return false;
   if (user.emailOtpEnabled) return false;

   user.emailOtpEnabled = true;

   user.mfaEnabled = false;
   user.totpSecret = undefined;
   user.recoveryCodes = [];

   await writeUsers(users);
   return true;
}


export async function generateAndSendEmailOtp(email: string): Promise<{ rateLimited: boolean }> {
   const otps = await readEmailOtps();

   const existing = otps.find((o) => o.email === email && !o.used && new Date(o.expiresAt) > new Date());
   if (existing) {
      const elapsed = Date.now() - (new Date(existing.expiresAt).getTime() - OTP_TTL_MS);
      if (elapsed < OTP_RESEND_COOLDOWN_MS) {
         return { rateLimited: true };
      }
   }

   const cleaned = otps.filter((o) => o.email !== email);
   const code = String(crypto.randomInt(100000, 1000000));

   cleaned.push({
      email,
      codeHash: hashCode(code),
      expiresAt: new Date(Date.now() + OTP_TTL_MS).toISOString(),
      used: false,
      attempts: 0,
   });

   await writeEmailOtps(cleaned);
   await sendOtpEmail(email, code);
   return { rateLimited: false };
}

export async function verifyEmailOtp(email: string, code: string): Promise<boolean> {
   const otps = await readEmailOtps();

   const index = otps.findIndex((o) => o.email === email && !o.used && new Date(o.expiresAt) > new Date());
   if (index === -1) return false;

   if (otps[index].attempts >= 5) return false;

   otps[index].attempts += 1;

   const valid = timingSafeEqual(otps[index].codeHash, hashCode(code));
   if (!valid) {
      await writeEmailOtps(otps);
      return false;
   }

   otps[index].used = true;
   const pruned = otps.filter((o) => !o.used && new Date(o.expiresAt) > new Date());
   await writeEmailOtps(pruned);
   return true;
}

export async function disableEmailOtp(email: string): Promise<boolean> {
   const users = await readUsers();
   const user = users.find((u) => u.email === email);
   if (!user) return false;
   if (!user.emailOtpEnabled) return false;

   user.emailOtpEnabled = false;
   await writeUsers(users);
   return true;
}
