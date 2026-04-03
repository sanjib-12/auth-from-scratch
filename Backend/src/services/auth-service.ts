import crypto from "crypto";
import { readUsers, writeUsers } from "../utils/read-write";
import { hashPassword, verifyPassword, validatePassword } from "./password-service";
import { ServiceResult } from "../types/auth-types";
import { createToken } from "../jwt/jwt-service";
import { createRefreshToken } from "./refresh-token-service";

export async function signUpUser(email: string, password: string): Promise<ServiceResult> {
   try {
      const normalizedEmail = email.trim().toLowerCase();

      const passwordError = validatePassword(password);
      if (passwordError) {
         return {
            statusCode: 400,
            statusMsg: passwordError,
         };
      }

      const users = await readUsers();

      if (users.find((u) => u.email === normalizedEmail)) {
         return {
            statusCode: 409,
            statusMsg: "User already exists",
         };
      }

      users.push({
         id: crypto.randomUUID(),
         email: normalizedEmail,
         password: await hashPassword(password),
      });

      await writeUsers(users);

      return {
         statusCode: 201,
         statusMsg: "Signup Successful",
      };
   } catch (error) {
      console.error(error);
      return {
         statusCode: 500,
         statusMsg: "Internal Server Error",
      };
   }
}

export async function loginUser(email: string, password: string): Promise<ServiceResult> {
   try {
      const normalizedEmail = email.trim().toLowerCase();

      const users = await readUsers();
      const user = users.find((u) => u.email === normalizedEmail);

      if (!user) {
         return {
            statusCode: 401,
            statusMsg: "Invalid credentials!",
         };
      }

      const valid = await verifyPassword(password, user.password);

      if (!valid) {
         return {
            statusCode: 401,
            statusMsg: "Invalid credentials!",
         };
      }

      const csrfToken = crypto.randomBytes(32).toString("hex");
      const jwt = createToken(normalizedEmail, csrfToken);
      const refreshToken = await createRefreshToken(normalizedEmail);

      return {
         statusCode: 200,
         statusMsg: "Login Successful",
         token: jwt,
         csrfToken,
         refreshToken,
      };
   } catch (error) {
      console.error(error);
      return {
         statusCode: 500,
         statusMsg: "Internal Server Error",
      };
   }
}
