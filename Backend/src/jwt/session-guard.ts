import { IncomingMessage, ServerResponse } from "http";
import { parseCookies } from "../middleware/cookie-parser";
import { compareCsrfToken } from "../utils/csrf-token-verification";
import { SessionInfo } from "../types/auth-types";
import { verifyToken } from "./jwt-service";

export function requireAuth(req: IncomingMessage, res: ServerResponse): SessionInfo | null {
   const tokenFromHeader = req.headers["x-csrf-token"];
   if (typeof tokenFromHeader !== "string") {
      res.writeHead(401);
      res.end("Unauthorized");
      return null;
   }

   const cookies = parseCookies(req.headers.cookie);
   const token = cookies.jwt;

   if (!token) {
      res.writeHead(401);
      res.end("Unauthorized");
      return null;
   }

   const payload = verifyToken(token);

   if (!payload) {
      res.writeHead(401);
      res.end("Unauthorized");
      return null;
   }

   const isTokenValid = compareCsrfToken(payload.csrf, tokenFromHeader);
   if (!isTokenValid) {
      res.writeHead(401);
      res.end("Unauthorized");
      return null;
   }
   return { email: payload.sub };
}
