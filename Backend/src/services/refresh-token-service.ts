import crypto from "crypto";
import fs from "fs/promises";
import path from "path";

interface StoredRefreshToken {
   tokenHash: string;
   email: string;
   familyId: string;
   expiresAt: number;
   used: boolean;
}

const REFRESH_EXPIRY_SECONDS = 7 * 24 * 60 * 60;
const DB_PATH = path.resolve(__dirname, "../../db/refresh-tokens.json");

async function readToken(): Promise<StoredRefreshToken[]> {
   try {
      const raw = await fs.readFile(DB_PATH, "utf-8");
      return JSON.parse(raw) as StoredRefreshToken[];
   } catch {
      return [];
   }
}

async function writeToken(tokens: StoredRefreshToken[]): Promise<void> {
   await fs.writeFile(DB_PATH, JSON.stringify(tokens, null, 2));
}

function hashToken(raw: string): string {
   return crypto.createHash("sha256").update(raw).digest("hex");
}

function purgeExpired(tokens: StoredRefreshToken[]): StoredRefreshToken[] {
   const now = Math.floor(Date.now() / 1000);
   return tokens.filter((t) => t.expiresAt > now);
}

export async function createRefreshToken(email: string): Promise<string> {
   const raw = crypto.randomBytes(48).toString("hex");
   const now = Math.floor(Date.now() / 1000);

   const entry: StoredRefreshToken = {
      tokenHash: hashToken(raw),
      email,
      familyId: crypto.randomUUID(),
      expiresAt: now + REFRESH_EXPIRY_SECONDS,
      used: false,
   };

   const tokens = purgeExpired(await readToken());
   tokens.push(entry);
   await writeToken(tokens);

   return raw;
}

export async function rotateRefreshToken(raw: string): Promise<{ newtoken: string; email: string } | null> {
   const hash = hashToken(raw);
   let tokens = purgeExpired(await readToken());

   const entry = tokens.find((t) => t.tokenHash === hash);
   if (!entry) return null;

   //Reuse detected: someone is replaying a consumed token.
   if (entry.used) {
      tokens = tokens.filter((t) => t.familyId !== entry.familyId);
      await writeToken(tokens);
      return null;
   }
   //Mark old token as consumed.
   entry.used = true;

   const newRaw = crypto.randomBytes(48).toString("hex");
   const now = Math.floor(Date.now() / 1000);

   tokens.push({
      tokenHash: hashToken(newRaw),
      email: entry.email,
      familyId: entry.familyId,
      expiresAt: now + REFRESH_EXPIRY_SECONDS,
      used: false,
   });

   await writeToken(tokens);
   return { newtoken: newRaw, email: entry.email };
}

export async function revokeRefreshTokenFamily(raw: string): Promise<void>{
   const hash = hashToken(raw);
   const tokens = await readToken();
   const entry = tokens.find((t) => t.tokenHash === hash);
   if(!entry) return;

   const remaining = tokens.filter((t) => t.familyId !== entry.familyId);
   await writeToken(remaining);
}