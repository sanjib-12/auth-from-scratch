import http, { IncomingMessage, ServerResponse } from "http";
import { handleSignup, handleLogin, handleLogout } from "./routers/auth-route";
import { handleProfile } from "./routers/profile-route";
import { handleRefresh } from "./routers/refresh-route";

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

   if (pathname === "/signup") {
      if (req.method !== "POST") {
         res.setHeader("Allow", "POST, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleSignup(req, res);
   } else if (pathname === "/login") {
      if (req.method !== "POST") {
         res.setHeader("Allow", "POST, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleLogin(req, res);
   } else if (pathname === "/profile") {
      if (req.method !== "GET") {
         res.setHeader("Allow", "GET, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleProfile(req, res);
   } else if (pathname === "/logout") {
      if (req.method !== "POST") {
         res.setHeader("Allow", "POST, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleLogout(req, res);
   } else if (pathname === "/refresh") {
      if (req.method !== "POST") {
         res.setHeader("Allow", "POST, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleRefresh(req, res);
   } else {
      res.writeHead(404);
      res.end("Not Found");
   }
});

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
