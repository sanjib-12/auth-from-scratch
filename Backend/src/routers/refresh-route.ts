import { IncomingMessage, ServerResponse } from "http";
import { parseCookies } from "../middleware/cookie-parser";
import { rotateRefreshToken } from "../services/refresh-token-service";
import { buildCsrfCookie, buildJwtCookie, buildRefreshCookie, clearCsrfCookie, clearJwtCookie, clearRefreshCookie } from "../utils/cookie";
import crypto from "crypto";
import { createToken } from "../jwt/jwt-service";
import { handleRouterError } from "./auth-route";

export async function handleRefresh(req: IncomingMessage, res: ServerResponse) {
   try {
   
      const cookies = parseCookies(req.headers.cookie);
      const refreshToken = cookies.refresh;
      
      if (!refreshToken) {
         res.writeHead(401);
         res.end("Unauthorized");
         return;
      }

      const result = await rotateRefreshToken(refreshToken);

      if (!result) {
         res.setHeader("Set-Cookie", [clearJwtCookie(), clearCsrfCookie(), clearRefreshCookie()]);
         res.writeHead(401);
         res.end("Unauthorized");
         return;
      }

      const csrfToken = crypto.randomBytes(32).toString("hex");
      const jwt = createToken(result.email, csrfToken);

      res.setHeader("Set-Cookie", [buildJwtCookie(jwt), buildCsrfCookie(csrfToken), buildRefreshCookie(result.newtoken)]);
      res.writeHead(200);
      res.end("Token refreshed");
   } catch (error) {
      handleRouterError(error, res);
   }
}
