import 'dotenv/config';
console.log('SMTP_HOST:', process.env.SMTP_HOST);
import http, { IncomingMessage, ServerResponse } from "http";
import { handleSignup, handleLogin, handleLogout } from "./routers/auth-route";
import { handleProfile } from "./routers/profile-route";
import { handleRefresh } from "./routers/refresh-route";
import { handleMfaSetup, handleMfaVerifySetup, handleMfaVerify, handleMfaDisable } from "./routers/mfa-route";
import {
   handleEmailOtpRequest,
   handleEmailOtpVerify,
   handleEmailOtpEnable,
   handleEmailOtpConfirmEnable,
   handleEmailOtpDisable,
} from "./routers/email-otp-route";

const PORT = 5000;

const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
   if (!req.url) {
      res.writeHead(400);
      res.end("Missing request URL");
      return;
   }

   res.setHeader("Access-Control-Allow-Origin", "http://127.0.0.1:5500");
   res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
   res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
   res.setHeader("Access-Control-Allow-Credentials", "true");

   if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
   }

   const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
   const pathname = url.pathname;

   console.log(pathname);

   if (pathname === "/signup") {
      if (rejectIfNot("POST", req, res)) return;
      handleSignup(req, res);
   } else if (pathname === "/login") {
      if (rejectIfNot("POST", req, res)) return;
      handleLogin(req, res);
   } else if (pathname === "/profile") {
      if (rejectIfNot("GET", req, res)) return;
      handleProfile(req, res);
   } else if (pathname === "/logout") {
      if (rejectIfNot("POST", req, res)) return;
      handleLogout(req, res);
   } else if (pathname === "/refresh") {
      if (rejectIfNot("POST", req, res)) return;
      handleRefresh(req, res);
   } else if (pathname === "/mfa/setup") {
      if (rejectIfNot("POST", req, res)) return;
      handleMfaSetup(req, res);
   } else if (pathname === "/mfa/verify-setup") {
      if (rejectIfNot("POST", req, res)) return;
      handleMfaVerifySetup(req, res);
   } else if (pathname === "/mfa/verify") {
      if (rejectIfNot("POST", req, res)) return;
      handleMfaVerify(req, res);
   } else if (pathname === "/mfa/disable") {
      if (rejectIfNot("POST", req, res)) return;
      handleMfaDisable(req, res);
   } else if (pathname === "/mfa/email/setup") {
      if (rejectIfNot("POST", req, res)) return;
      handleEmailOtpEnable(req, res);
   } else if (pathname === "/mfa/email/verify-setup") {
      if (rejectIfNot("POST", req, res)) return;
      handleEmailOtpConfirmEnable(req, res);
   } else if (pathname === "/mfa/email/request") {
      if (rejectIfNot("POST", req, res)) return;
      handleEmailOtpRequest(req, res);
   } else if (pathname === "/mfa/email/verify") {
      if (rejectIfNot("POST", req, res)) return;
      handleEmailOtpVerify(req, res);
   } else if (pathname === "/mfa/email/disable") {
      if (rejectIfNot("POST", req, res)) return;
      handleEmailOtpDisable(req, res);
   } else {
      res.writeHead(404);
      res.end("Not Found");
   }
});

function rejectIfNot(method: string, req: IncomingMessage, res: ServerResponse) {
   if (req.method !== method) {
      res.setHeader("Allow", `${method}, OPTIONS`);
      res.writeHead(405);
      res.end("Method Not Allowed");
      return true;
   }
   return false;
}

server.on("error", (err: NodeJS.ErrnoException) => {
   if (err.code === "EADDRINUSE") {
      console.error(`port ${PORT} is already in use`);
      process.exit(1);
   }
   throw err;
});

server.listen(PORT, () => {
   console.log(`server running at http://localhost:${PORT}`);
});
