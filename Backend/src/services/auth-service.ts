import { readUser, writeUser } from "../utils/readWrite";
import { hashedPassword, compareHashedPassword } from "./password-service";

interface ServiceResult {
   statusCode: number;
   statusMsg: string;
}

async function signUpUser(email: string, password: string): Promise<ServiceResult> {
   try {
      const users = await readUser();

      if (users.find((user) => user.email === email)) {
         return {
            statusCode: 409,
            statusMsg: "user already exists",
         };
      }

      users.push({
         id: Date.now().toString(),
         email: email,
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
      const users = await readUser();
      const user = users.find((user) => user.email === email);

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
            statusMsg: "invalid Credentials!",
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
