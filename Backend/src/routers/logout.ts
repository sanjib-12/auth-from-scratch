import { IncomingMessage, ServerResponse } from "http";
import { deleteSession } from "../sessions/session-store";
import { clearCsrfToken, clearSessionCookie } from "../utils/cookie";
import { requireAuth } from "../middleware/session-csrf-verification";

export function handleLogout(req: IncomingMessage, res: ServerResponse) {
   const session = requireAuth(req, res);
   if(session === null) return;
   
   const sessionId = session.sessionId;
   deleteSession(sessionId);

   const clearCookie = clearSessionCookie();
   const clearToken = clearCsrfToken();

   res.setHeader("Set-Cookie", [clearCookie, clearToken]);
   res.writeHead(204);
   res.end();
}
