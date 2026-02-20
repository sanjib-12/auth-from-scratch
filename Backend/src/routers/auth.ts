import { IncomingMessage, ServerResponse } from "node:http";

import { singUpUser, loginUser } from "../services/auth.service";
import bodyParser from "../utils/bodyParser";

async function handleAuthRouter(req: IncomingMessage, res: ServerResponse) {
   try {
      const body = await bodyParser(req);

      if (req.url === "/login") {
         const result = await loginUser(body.email, body.password);
         res.writeHead(result.statusCode);
         res.end(result.statusMsg);
      }

      if (req.url === "/signup") {
         const result = await singUpUser(body.email, body.password);
         res.writeHead(result.statusCode);
         res.end(result.statusMsg);
      }
   } catch (error) {
      console.log(error);
      res.writeHead(400);
      res.end("Invalid request");
   }
}

export default handleAuthRouter;
