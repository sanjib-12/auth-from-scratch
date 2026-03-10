import { IncomingMessage, ServerResponse } from "http";
import { parseCookies } from "../utils/cookieParser";
import { getSession } from "./session-store";

export function requireSession(req: IncomingMessage, res: ServerResponse): { sessionId: string; email: string } | null {
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
