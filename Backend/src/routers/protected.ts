import { IncomingMessage, ServerResponse } from "http";
import { requireSession } from "../sessions/session-guard";

export function handleProtectedRoute(req: IncomingMessage, res: ServerResponse) {
   const session = requireSession(req, res);

   if (!session) return;

   const email = session.email;

   res.writeHead(200, { "Content-type": "application/json" });
   res.end(JSON.stringify({ message: "Protected data", email }));
}
