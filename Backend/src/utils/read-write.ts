import fs from "fs/promises";
import path from "path";
import { User, EmailOtp } from "../types/auth-types";
const dbPath = path.resolve(__dirname, "../../db/users.json");
const otpDbPath = path.resolve(__dirname, "../../db/email-otps.json");

export async function readUsers(): Promise<User[]> {
   try {
      const raw = await fs.readFile(dbPath, "utf8");
      return JSON.parse(raw) as User[];
   } catch {
      return [];
   }
}

export async function writeUsers(users: User[]): Promise<void> {
   await fs.writeFile(dbPath, JSON.stringify(users, null, 2));
}

export async function readEmailOtps(): Promise<EmailOtp[]> {
   try {
      const raw = await fs.readFile(otpDbPath, "utf8");
      return JSON.parse(raw) as EmailOtp[];
   } catch {
      return [];
   }
}

export async function writeEmailOtps(otps: EmailOtp[]): Promise<void> {
   await fs.writeFile(otpDbPath, JSON.stringify(otps, null, 2));
}

