import { IncomingMessage, ServerResponse } from "http";
import { requireJson } from "../middleware/require-json";
import { bodyParser } from "../middleware/body-parser";
import { parseCookies } from "../middleware/cookie-parser";
import { verifyMfaPendingToken } from "../jwt/jwt-service";
import { createToken } from "../jwt/jwt-service";
import { buildCsrfCookie, buildJwtCookie, buildRefreshCookie, clearMfaPendingCookie } from "../utils/cookie";
import { createRefreshToken } from "../services/refresh-token-service";
import { disableEmailOtp, enableEmailOtp, generateAndSendEmailOtp, verifyEmailOtp } from "../services/email-otp-service";
import { isMfaCodePayload } from "../types/auth-types";
import { handleRouterError } from "./auth-route";
import crypto from "crypto";
import { requireAuth } from "../jwt/session-guard";

export async function handleEmailOtpRequest(req: IncomingMessage, res: ServerResponse) {
   try {
      const cookies = parseCookies(req.headers.cookie);
      const pendingToken = cookies.mfa_pending;
      let email: string | null = null;

      if (pendingToken) {
         // MFA login flow — not authenticated yet
         email = verifyMfaPendingToken(pendingToken);
         if (!email) {
            res.setHeader("Set-Cookie", [clearMfaPendingCookie()]);
            res.writeHead(401);
            res.end("Unauthorized");
            return;
         }
      } else {
         // Already-authenticated user requesting a new OTP
         const auth = requireAuth(req, res);
         if (!auth) return; // requireAuth already wrote the 401 response
         email = auth.email;
      }

      const { rateLimited } = await generateAndSendEmailOtp(email);
      if (rateLimited) {
         res.writeHead(429, { "content-type": "application/json" });
         res.end(JSON.stringify({ message: "Please wait before requesting a new code" }));
         return;
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "Code sent" }));
   } catch (error) {
      handleRouterError(error, res);
   }
}

export async function handleEmailOtpVerify(req: IncomingMessage, res: ServerResponse) {
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

      const valid = await verifyEmailOtp(email, body.code);
      if (!valid) {
         res.writeHead(401);
         res.end("Invalid or expired code");
         return;
      }

      const csrfToken = crypto.randomBytes(32).toString("hex");
      const jwt = createToken(email, csrfToken);
      const refreshToken = await createRefreshToken(email);

      res.setHeader("Set-Cookie", [buildJwtCookie(jwt), buildCsrfCookie(csrfToken), buildRefreshCookie(refreshToken), clearMfaPendingCookie()]);

      res.writeHead(200);
      res.end("Login Successful");
   } catch (error) {
      handleRouterError(error, res);
   }
}

export async function handleEmailOtpEnable(req: IncomingMessage, res: ServerResponse) {
   try {
      const auth = requireAuth(req, res);
      if (auth === null) return;

      const { rateLimited } = await generateAndSendEmailOtp(auth.email);
      if (rateLimited) {
         res.writeHead(429, { "content-type": "application/json" });
         res.end(JSON.stringify({ message: "Please wait before requesting a new code" }));
         return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Verification code sent" }));
   } catch (error) {
      handleRouterError(error, res);
   }
}

export async function handleEmailOtpConfirmEnable(req: IncomingMessage, res: ServerResponse) {
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

      const valid = await verifyEmailOtp(auth.email, body.code);
      if (!valid) {
         res.writeHead(401);
         res.end("Invalid or expired Code");
         return;
      }

      const enabled = await enableEmailOtp(auth.email);
      if (!enabled) {
         res.writeHead(400);
         res.end("Email OTP already enabled");
         return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Email OTP enabled" }));
   } catch (error) {
      handleRouterError(error, res);
   }
}

export async function handleEmailOtpDisable(req: IncomingMessage, res: ServerResponse) {
   try {
      const auth = requireAuth(req, res);
      if (auth === null) return;

      const disabled = await disableEmailOtp(auth.email);
      if (!disabled) {
         res.writeHead(400);
         res.end("Email OTP not enabled");
         return;
      }

      res.writeHead(204);
      res.end();
   } catch (error) {
      handleRouterError(error, res);
   }
}
