import http, { IncomingMessage, ServerResponse } from "http";
import handleAuthRouter from "./routers/auth";
import { handleProtectedRoute } from "./routers/protected";
import { handleLogout } from "./routers/logout";

const PORT = 5000;

const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
   if (!req.url) {
      res.writeHead(400);
      res.end("Missing request URL");
      return;
   }

   res.setHeader("Access-Control-Allow-Origin", "*");
   res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
   res.setHeader("Access-Control-Allow-Headers", "Content-Type");

   if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
   }

   const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
   const pathname = url.pathname;

   if (pathname === "/signup" || pathname === "/login") {
      if (req.method !== "POST") {
         res.setHeader("Allow", "POST, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleAuthRouter(req, res, pathname);
   } else if (pathname === "/profile") {
      if (req.method !== "GET") {
         res.setHeader("Allow", "GET, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleProtectedRoute(req, res);
   } else if (pathname === "/logout") {
      if (req.method !== "POST") {
         res.setHeader("Allow", "POST, OPTIONS");
         res.writeHead(405);
         res.end("Method Not Allowed");
         return;
      }
      handleLogout(req, res);
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
