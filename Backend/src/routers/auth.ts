import { IncomingMessage, ServerResponse } from "http";
import { signUpUser, loginUser, ServiceResult } from "../services/auth-service";
import bodyParser from "../utils/bodyParser";
import { isAuthPayload } from "../types/user";
import { buildSessionCookie } from "../utils/cookie";

async function handleAuthRouter(req: IncomingMessage, res: ServerResponse, pathname: string) {
   try {
      const contentType = req.headers["content-type"];
      if (!contentType || !contentType.toLocaleLowerCase().startsWith("application/json")) {
         res.writeHead(415);
         res.end("Content-Type must be application/json");
         return;
      }

      const body = await bodyParser(req);

      if (!isAuthPayload(body)) {
         res.writeHead(400);
         res.end("Invalid request body");
         return;
      }

      let result: ServiceResult;

      if (pathname === "/login") {
         result = await loginUser(body.email, body.password);
      } else {
         result = await signUpUser(body.email, body.password);
      }

      if (result.sessionId) {
         const sessionCookie = buildSessionCookie(result.sessionId);
         res.setHeader("Set-Cookie", sessionCookie);
      }

      res.writeHead(result.statusCode);
      res.end(result.statusMsg);
   } catch (error) {
      console.error(error);

      const isTooLarge = error instanceof Error && error.message.toLowerCase().includes("payload too large");
      if (isTooLarge) {
         res.writeHead(413);
         res.end("Payload too large");
         return;
      }
      res.writeHead(500);
      res.end("Invalid request");
   }
}

export default handleAuthRouter;
