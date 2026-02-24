export interface User{
   id: string;
   email: string;
   password: string;
}

export interface AuthPayload{
   email: string;
   password:string;
}

export function isAuthPayload(value: unknown): value is AuthPayload {
   if(typeof value !== "object" || value === null){
      return false;
   }

   const body = value as Record<string, unknown>;

   return(

      typeof body.email === "string" &&
      typeof body.password === "string" &&
      body.email.trim().length > 0 &&
      body.password.length > 0
   );

}