import { IncomingMessage, ServerResponse } from "http";
import { requireAuth } from "../jwt/session-guard"

export function handleProfile(req: IncomingMessage, res: ServerResponse) {
   const auth = requireAuth(req, res);
   if(auth === null) return;

   res.writeHead(200, { "Content-type": "application/json" });
   res.end(JSON.stringify({ message: "Protected data", email:auth.email }));
}
