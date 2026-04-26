import { IncomingMessage, ServerResponse } from "http";
import { requireAuth } from "../jwt/session-guard";
import { setupMfa, verifyMfaLogin, verifyMfaSetup, disableMfa } from "../services/mfa-service";
import { handleRouterError } from "./auth-route";
import { requireJson } from "../middleware/require-json";
import { bodyParser } from "../middleware/body-parser";
import { isMfaCodePayload } from "../types/auth-types";
import { parseCookies } from "../middleware/cookie-parser";
import { verifyMfaPendingToken } from "../jwt/jwt-service";
import { buildCsrfCookie, buildJwtCookie, buildRefreshCookie, clearMfaPendingCookie } from "../utils/cookie";
import crypto from "crypto";
import { createToken } from "../jwt/jwt-service";
import { createRefreshToken } from "../services/refresh-token-service";

export async function handleMfaSetup(req: IncomingMessage, res: ServerResponse) {
   try {
      const auth = requireAuth(req, res);
      if (auth === null) return;

      const result = await setupMfa(auth.email);
      if (!result) {
         res.writeHead(400, { "Content-Type": "application/json" });
         res.end(JSON.stringify({ error: "MFA setup failed or already enabled" }));
         return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ secret: result.secret, otpauthUri: result.otpauthUri }));
   } catch (error) {
      handleRouterError(error, res);
   }
}

export async function handleMfaVerifySetup(req: IncomingMessage, res: ServerResponse) {
   try {
      const auth = requireAuth(req, res);
      if (auth === null) return;

      if (!requireJson(req, res)) return;
      const body = await bodyParser(req);
      if (!isMfaCodePayload(body)) {
         res.writeHead(400);
         res.end("Invalid request body");
         return;
      }

      const result = await verifyMfaSetup(auth.email, body.code);

      if (!result) {
         res.writeHead(401, { "Content-Type": "application/json" });
         res.end(JSON.stringify({ error: "Invalid code" }));
         return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ recoveryCodes: result.recoveryCodes }));
   } catch (error) {
      handleRouterError(error, res);
   }
}

export async function handleMfaVerify(req: IncomingMessage, res: ServerResponse) {
   try {
      if (!requireJson(req, res)) return;

      const cookies = parseCookies(req.headers.cookie);
      const pendingToken = cookies.mfa_pending;

      if (!pendingToken) {
         res.writeHead(401);
         res.end("Unauthorized");
         return;
      }

      const email = verifyMfaPendingToken(pendingToken);
      if (!email) {
         res.setHeader("Set-Cookie", [clearMfaPendingCookie()]);
         res.writeHead(401);
         res.end("Unauthorized");
         return;
      }

      const body = await bodyParser(req);
      if (!isMfaCodePayload(body)) {
         res.writeHead(400);
         res.end("Invalid request body");
         return;
      }

      const valid = await verifyMfaLogin(email, body.code);
      if (!valid) {
         res.writeHead(401);
         res.end("Invalid MFA code");
         return;
      }

      const csrfToken = crypto.randomBytes(32).toString("hex");
      const jwt = createToken(email, csrfToken);
      const refreshToken = await createRefreshToken(email);

      res.setHeader("Set-Cookie", [
         buildJwtCookie(jwt),
         buildCsrfCookie(csrfToken),
         buildRefreshCookie(refreshToken),
         clearMfaPendingCookie(),
      ]);

      res.writeHead(200);
      res.end("Login Successful");
   } catch (error) {
      handleRouterError(error, res);
   }
}


export async function handleMfaDisable(req: IncomingMessage, res: ServerResponse) {
   try {
      const auth = requireAuth(req, res);
      if (auth === null) return;

      const result = await disableMfa(auth.email);
      if (!result) {
         res.writeHead(400);
         res.end("MFA Disable failed or already Disabled");
         return;
      }

      res.writeHead(204);
      res.end();
   } catch (error) {
      handleRouterError(error, res);
   }
}