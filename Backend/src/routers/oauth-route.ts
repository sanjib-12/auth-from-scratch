import http from "http";
import crypto from "crypto";
import { createOAuthState, consumeOAuthState } from "../utils/oauth-state";
import { buildGoogleAuthUrl, exchangeCodeForAccessToken, getGoogleUserInfo, findOrCreateOAuthUser } from "../services/oauth-service";
import { createMfaPendingToken, createToken } from "../jwt/jwt-service";
import { buildJwtCookie, buildCsrfCookie, buildRefreshCookie, buildMfaPendingCookie } from "../utils/cookie";
import { createRefreshToken } from "../services/refresh-token-service";
import { generateAndSendEmailOtp } from "../services/email-otp-service";

const FRONTEND_URL = "http://127.0.0.1:5500/Frontend/public";

export function handleGoogleStart(_req: http.IncomingMessage, res: http.ServerResponse): void {
   const { state, codeChallenge } = createOAuthState();
   const authUrl = buildGoogleAuthUrl(state, codeChallenge);
   res.writeHead(302, { location: authUrl });
   res.end();
}

export async function handleGoogleCallback(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
   const url = new URL(req.url!, `http://127.0.0.1:5000`);
   const code = url.searchParams.get("code");
   const state = url.searchParams.get("state");
   const error = url.searchParams.get("error");
   
   if (error || !code || !state) {
      res.writeHead(302, {
         Location: `${FRONTEND_URL}/login.html?error=oauth_denied`,
      });
      res.end();
      return;
   }
   
   const codeVerifier = consumeOAuthState(state);
   if (!codeVerifier) {
      res.writeHead(302, {
         Location: `${FRONTEND_URL}/login.html?error=invalid_state`,
      });
      res.end();
      return;
   }
   
   try {
      const accessToken = await exchangeCodeForAccessToken(code, codeVerifier);
      const googleUser = await getGoogleUserInfo(accessToken);
      const user = await findOrCreateOAuthUser(googleUser);
      
      if (user.mfaEnabled || user.emailOtpEnabled) {
         let mfaPendingToken: string;
         let mfaType: string;
         if (user.emailOtpEnabled) {
            await generateAndSendEmailOtp(user.email);
            mfaPendingToken = createMfaPendingToken(user.email);
            mfaType = "email-otp";
         } else {
            mfaPendingToken = createMfaPendingToken(user.email);
            mfaType = "totp";
         }
         res.setHeader("Set-Cookie", [buildMfaPendingCookie(mfaPendingToken)]);
         res.writeHead(302, { Location: `${FRONTEND_URL}/mfa-verify.html?mfaType=${mfaType}` });
         res.end();
      } else {
         const csrfToken = crypto.randomBytes(32).toString("hex");
         const jwt = createToken(user.email, csrfToken);
         const refreshToken = await createRefreshToken(user.email);
         
         res.writeHead(302, {
            Location: `${FRONTEND_URL}/dashboard.html`,
            "Set-Cookie": [buildJwtCookie(jwt), buildCsrfCookie(csrfToken), buildRefreshCookie(refreshToken)],
         });
         res.end();
      }
   } catch (err) {
      console.error("OAuth callback error:", err);
      res.writeHead(302, {
         Location: `${FRONTEND_URL}/login.html?error=oauth_failed`,
      });
      res.end();
   }
}
