import { IncomingMessage, ServerResponse } from "http";
import { signUpUser, loginUser} from "../services/auth-service";
import { requireJson } from "../middleware/require-json";
import { bodyParser } from "../middleware/body-parser";
import { isAuthPayload } from "../types/auth-types";
import { buildSessionCookie, buildCsrfCookie, clearSessionCookie, clearCsrfCookie } from "../utils/cookie";
import { deleteSession } from "../sessions/session-store"
import { requireAuth } from "../sessions/session-guard";

export async function handleSignup(req: IncomingMessage, res: ServerResponse) {
   try {
      if (!requireJson(req, res)) return;

      const body = await bodyParser(req);

      if (!isAuthPayload(body)) {
         res.writeHead(400);
         res.end("Invalid request body");
         return;
      }

      const result = await signUpUser(body.email, body.password);

      res.writeHead(result.statusCode);
      res.end(result.statusMsg);
   } catch (error) {
      handleRouterError(error, res);
   }
}

export async function handleLogin(req: IncomingMessage, res: ServerResponse) {
   try {
      if (!requireJson(req, res)) return;

      const body = await bodyParser(req);

      if (!isAuthPayload(body)) {
         res.writeHead(400);
         res.end("Invalid request body");
         return;
      }

      const result = await loginUser(body.email, body.password);

      if (result.sessionId && result.csrfToken) {
         const sessionCookie = buildSessionCookie(result.sessionId);
         const csrfCookie = buildCsrfCookie(result.csrfToken);
         res.setHeader("Set-Cookie", [sessionCookie, csrfCookie]);
      }

      res.writeHead(result.statusCode);
      res.end(result.statusMsg);
   } catch (error) {
      handleRouterError(error, res);
   }
}

export function handleLogout(req: IncomingMessage, res: ServerResponse) {
   const session = requireAuth(req, res);
   if (session === null) return;

   deleteSession(session.sessionId);

   res.setHeader("Set-Cookie", [clearSessionCookie(), clearCsrfCookie()]);
   res.writeHead(204);
   res.end();
}

function handleRouterError(error: unknown, res: ServerResponse) {
   console.error(error);

   const isTooLarge = error instanceof Error && error.message.toLowerCase().includes("payload too large");
   if (isTooLarge) {
      res.writeHead(413);
      res.end("Payload too large");
      return;
   }
   res.writeHead(500);
   res.end("Internal Server Error");
}
