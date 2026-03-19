import { IncomingMessage, ServerResponse } from "http";
import { parseCookies } from "../middleware/cookie-parser";
import { getSession } from "./session-store";
import { compareCsrfToken } from "../utils/csrf-token-verification";
import { SessionInfo } from "../types/auth-types";

export function requireAuth(req: IncomingMessage, res: ServerResponse): SessionInfo | null {
   const tokenFromHeader = req.headers["x-csrf-token"];
   if (typeof tokenFromHeader !== "string") {
      res.writeHead(401);
      res.end("Unauthorized");
      return null;
   }

   const session = requireSession(req, res);

   if (!session) return null;

   const sessionId = session.sessionId;
   const isTokenValid = compareCsrfToken(sessionId, tokenFromHeader);
   if (!isTokenValid) {
      res.writeHead(401);
      res.end("Unauthorized");
      return null;
   }
   return session;
}

export function requireSession(req: IncomingMessage, res: ServerResponse): SessionInfo | null {
   const cookies = parseCookies(req.headers.cookie);
   const sessionId = cookies.sessionId;

   if (!sessionId) {
      res.writeHead(401);
      res.end("Unauthorized");
      return null;
   }

   const email = getSession(sessionId);

   if (!email) {
      res.writeHead(401);
      res.end("Invalid or expired session");
      return null;
   }

   return {
      sessionId,
      email,
   };
}
