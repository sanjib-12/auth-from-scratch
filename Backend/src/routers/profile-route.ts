import { IncomingMessage, ServerResponse } from "http";
import { requireAuth } from "../jwt/session-guard";
import { readUsers } from "../utils/read-write";

export async function handleProfile(req: IncomingMessage, res: ServerResponse) {
   const auth = requireAuth(req, res);
   if (auth === null) return;

   const users = await readUsers();
   const user = users.find((u) => u.email === auth.email);

   res.writeHead(200, { "Content-type": "application/json" });
   res.end(JSON.stringify({ message: "Protected data", email: auth.email, mfaEnabled: user?.mfaEnabled ?? false }));
}
