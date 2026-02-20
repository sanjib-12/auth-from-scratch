import fs from 'fs/promises';
import path from 'path';

import { hashedPassword, compareHashedPassword } from './password.service';

const dbPath = path.join(process.cwd(),"db/users.json");

async function readUser(): Promise<any[]> {
   const raw = await fs.readFile(dbPath,"utf8");
   return JSON.parse(raw);
}

async function writeUser(users: any[]): Promise<void> {
   await fs.writeFile(dbPath, JSON.stringify(users, null, 2));
}

async function singUpUser(email: string, password: string){

   const users = await readUser();

   if(users.find((user) => user.email === email)){
      return {
         statusCode: 400,
         statusMsg: "user already exists"
      }
   }

   users.push({
      id: Date.now().toString(),
      email: email,
      password: hashedPassword(password)
   })

   await writeUser(users);

   return {
      statusCode: 201,
      statusMsg: "Signup Successful"
   };
};

async function loginUser(email: string, password: string){
   const users = await readUser();

   const user = users.find(user => user.email === email);

   if(!user){
      return{
         statusCode: 401,
         statusMessage: "User Not Found!"
      }
   }

   const valid = compareHashedPassword(password, user.password);

   if(!valid){
      return{
         statusCode: 401,
         statusMessage: "User Not Found!"
      }
   }

   return {
      statusCode: 200,
      statusMsg: "Login Successful"
   };
};

export { singUpUser, loginUser };
