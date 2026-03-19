import { IncomingMessage, ServerResponse } from "http";
import { requireAuth } from "../sessions/session-guard"

export function handleProfile(req: IncomingMessage, res: ServerResponse) {
   const session = requireAuth(req, res);
   if(session === null) return;

   const email = session.email;

   res.writeHead(200, { "Content-type": "application/json" });
   res.end(JSON.stringify({ message: "Protected data", email }));
}
