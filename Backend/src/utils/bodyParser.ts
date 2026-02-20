import { IncomingMessage } from "node:http";

const bodyParser = (req: IncomingMessage): Promise<any> => {
   return new Promise((resolve, reject) => {
      let body = "";

      req.on("data", (chunk) => {
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

export default bodyParser;
