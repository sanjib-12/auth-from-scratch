import { IncomingMessage, ServerResponse } from "http";
import { signUpUser, loginUser} from "../services/auth-service";
import { requireJson } from "../middleware/require-json";
import { bodyParser } from "../middleware/body-parser";
import { isAuthPayload } from "../types/auth-types";
import { buildJwtCookie, buildCsrfCookie, clearJwtCookie, clearCsrfCookie } from "../utils/cookie";
import { requireAuth } from "../jwt/session-guard";

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

      if (result.token && result.csrfToken) {
         const jwtCookie = buildJwtCookie(result.token);
         const csrfCookie = buildCsrfCookie(result.csrfToken);
         res.setHeader("Set-Cookie", [jwtCookie, csrfCookie]);
      }

      res.writeHead(result.statusCode);
      res.end(result.statusMsg);
   } catch (error) {
      handleRouterError(error, res);
   }
}

export function handleLogout(req: IncomingMessage, res: ServerResponse) {
   const auth = requireAuth(req, res);
   if (auth === null) return;

   res.setHeader("Set-Cookie", [clearJwtCookie(), clearCsrfCookie()]);
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
