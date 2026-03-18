import { IncomingMessage, ServerResponse } from "http";
import { requireSession } from "../sessions/session-guard";
import { compareCsrfToken } from "../utils/csrf-token-verification";

export function requireAuth(req: IncomingMessage, res: ServerResponse): { sessionId: string; email: string } | null  {
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
