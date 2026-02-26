import { readUser, writeUser } from "../utils/readWrite";
import { hashedPassword, compareHashedPassword, validatePassword } from "./password-service";

interface ServiceResult {
   statusCode: number;
   statusMsg: string;
}

async function signUpUser(email: string, password: string): Promise<ServiceResult> {
   try {
      const normalizedEmail = email.trim().toLowerCase();

      const passwordError = validatePassword(password);
      if (passwordError) {
         return {
            statusCode: 400,
            statusMsg: passwordError,
         };
      }

      const users = await readUser();

      if (users.find((user) => user.email === normalizedEmail)) {
         return {
            statusCode: 409,
            statusMsg: "User already exists",
         };
      }

      users.push({
         id: Date.now().toString(),
         email: normalizedEmail,
         password: await hashedPassword(password),
      });

      await writeUser(users);

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

async function loginUser(email: string, password: string): Promise<ServiceResult> {
   try {
      const normalizedEmail = email.trim().toLowerCase();

      const users = await readUser();
      const user = users.find((user) => user.email === normalizedEmail);

      if (!user) {
         return {
            statusCode: 401,
            statusMsg: "Invalid credentials!",
         };
      }

      const valid = await compareHashedPassword(password, user.password);

      if (!valid) {
         return {
            statusCode: 401,
            statusMsg: "Invalid credentials!",
         };
      }

      return {
         statusCode: 200,
         statusMsg: "Login Successful",
      };
   } catch (error) {
      console.error(error);
      return {
         statusCode: 500,
         statusMsg: "Internal Server Error",
      };
   }
}

export { signUpUser, loginUser };
export { ServiceResult };
