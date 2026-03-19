import { IncomingMessage } from "http";

const MAX_BODY_SIZE = 1024 * 1024;

export function bodyParser(req: IncomingMessage): Promise<unknown> {
   return new Promise((resolve, reject) => {
      let body = "";
      let size = 0;

      req.on("data", (chunk) => {
         size += chunk.length;
         if (size > MAX_BODY_SIZE) {
            req.destroy();
            reject(new Error("payload too large"));
            return;
         }
         body += chunk.toString();
      });

      req.on("end", () => {
         try {
            const parsed = JSON.parse(body);
            resolve(parsed);
         } catch (error) {
            reject(new Error("Invalid JSON"));
         }
      });

      req.on("error", (err) => reject(err));
   });
};

