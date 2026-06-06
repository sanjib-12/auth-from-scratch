import crypto from "crypto";
import { readUsers, writeUsers } from "../utils/read-write";
import { generateTotpSecret, verifyTotp, buildOtpauthUri } from "./totp-service";

const RECOVERY_CODE_COUNT = 8;

function hashRecoveryCode(code: string): string {
   return crypto.createHash("sha256").update(code).digest("hex");
}

function generateRecoveryCodes(): { raw: string[]; hashed: string[] } {
   const raw: string[] = [];
   const hashed: string[] = [];

   for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
      const code = crypto.randomBytes(5).toString("hex");
      raw.push(code);
      hashed.push(hashRecoveryCode(code));
   }
   return { raw, hashed };
}

export async function setupMfa(email: string): Promise<{ secret: string; otpauthUri: string } | null> {
   const users = await readUsers();
   const user = users.find((u) => u.email === email);
   if (!user) return null;

   if (user.mfaEnabled || user.emailOtpEnabled) return null;

   const secret = generateTotpSecret();
   user.totpSecret = secret;
   user.mfaEnabled = false;
   await writeUsers(users);

   return {
      secret,
      otpauthUri: buildOtpauthUri(email, secret),
   };
}

export async function verifyMfaSetup(email: string, code: string): Promise<{ recoveryCodes: string[] } | null> {
   const users = await readUsers();
   const user = users.find((u) => u.email === email);
   if (!user || !user.totpSecret) return null;

   if (!verifyTotp(user.totpSecret, code)) return null;

   const { raw, hashed } = generateRecoveryCodes();
   user.mfaEnabled = true;
   user.recoveryCodes = hashed;

   await writeUsers(users);

   return { recoveryCodes: raw };
}

export async function verifyMfaLogin(email: string, code: string): Promise<boolean> {
   const users = await readUsers();
   const user = users.find((u) => u.email === email);
   if (!user || !user.mfaEnabled || !user.totpSecret) return false;
   const normalized = code.replace(/-/g, "").trim();

   if (/^\d{6}$/.test(normalized)) {
      return verifyTotp(user.totpSecret, normalized);
   }

   if (/^[0-9a-f]{10}$/i.test(normalized) && user.recoveryCodes) {
      const hash = hashRecoveryCode(normalized.toLowerCase());
      const index = user.recoveryCodes.indexOf(hash);
      if (index === -1) return false;
      user.recoveryCodes.splice(index, 1);
      await writeUsers(users);
      return true;
   }

   return false;
}

export async function disableMfa(email: string): Promise<boolean> {
   const users = await readUsers();
   const user = users.find((u) => u.email === email);
   if (!user) return false;

   if (!user.mfaEnabled) return false;

   user.mfaEnabled = false;
   user.recoveryCodes = [];
   user.totpSecret = undefined;
   await writeUsers(users);

   return true;
}