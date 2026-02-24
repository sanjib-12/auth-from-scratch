import crypto from "crypto";
import { promisify } from 'util';

const pbkdf2Async = promisify(crypto.pbkdf2);

const HASH_CONFIG = {
   saltBytes: 16,
   iterations: 10000,
   keyLength: 64,
   digest: "sha512",
} as const;

async function hashedPassword(password: string): Promise<string> {
   const salt = crypto.randomBytes(HASH_CONFIG.saltBytes).toString("hex");

   const hash = await pbkdf2Async(password, salt, HASH_CONFIG.iterations, HASH_CONFIG.keyLength, HASH_CONFIG.digest);
   return `${salt}:${hash.toString("hex")}`;
}

async function compareHashedPassword(password: string, stored: string): Promise<boolean> {
   const [salt, originHash] = stored.split(":");

   if (!salt || !originHash) return false;

   const hash =await pbkdf2Async(password, salt, HASH_CONFIG.iterations, HASH_CONFIG.keyLength, HASH_CONFIG.digest);

   const originBuffer = Buffer.from(originHash, "hex");

   if (hash.length !== originBuffer.length) return false;

   return crypto.timingSafeEqual(hash, originBuffer);
}

export { hashedPassword, compareHashedPassword };
