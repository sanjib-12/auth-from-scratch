import { IncomingMessage, ServerResponse } from "http";
import { deleteSession } from "../sessions/session-store";
import { clearSessionCookie } from "../utils/cookie";
import { requireSession } from "../sessions/session-guard";

export function handleLogout(req: IncomingMessage, res: ServerResponse) {
   const session = requireSession(req, res);

   if (!session) return;

   const sessionId = session.sessionId;

   deleteSession(sessionId);

   const clearCookie = clearSessionCookie();

   res.setHeader("Set-Cookie", clearCookie);
   res.writeHead(204);
   res.end();
}
