import fs from "fs/promises";
import path from "path";
import { User } from "../types/auth-types";
const dbPath = path.resolve(__dirname, "../../db/users.json");

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

