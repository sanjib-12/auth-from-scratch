export interface User {
   id: string;
   email: string;
   password: string;
}

export interface AuthPayload {
   email: string;
   password: string;
}

export interface ServiceResult {
   statusCode: number;
   statusMsg: string;
   sessionId?: string;
   csrfToken?: string;
}

export interface SessionInfo {
   sessionId: string;
   email: string;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
   return EMAIL_REGEX.test(email);
}

export function isAuthPayload(value: unknown): value is AuthPayload {
   if (typeof value !== "object" || value === null) {
      return false;
   }

   const body = value as Record<string, unknown>;

   return (
      typeof body.email === "string" &&
      typeof body.password === "string" &&
      body.email.trim().length > 0 &&
      body.password.length > 0 &&
      isValidEmail(body.email.trim())
   );
}
