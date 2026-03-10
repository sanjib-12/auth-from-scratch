import fs from "fs/promises";
import path from "path";
import { User } from "../types/user";
const dbPath = path.resolve(__dirname, "../../db/users.json");

async function readUser(): Promise<User[]> {
   try {
      const raw = await fs.readFile(dbPath, "utf8");
      return JSON.parse(raw) as User[];
   } catch {
      return [];
   }
}

async function writeUser(users: User[]): Promise<void> {
   await fs.writeFile(dbPath, JSON.stringify(users, null, 2));
}

export { readUser, writeUser };
