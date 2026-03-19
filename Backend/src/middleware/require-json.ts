import { IncomingMessage, ServerResponse } from "http";

export function requireJson(req: IncomingMessage, res: ServerResponse): boolean{
    const contentType = req.headers["content-type"];
    if (!contentType || !contentType.toLocaleLowerCase().startsWith("application/json")) {
       res.writeHead(415);
       res.end("Content-Type must be application/json");
       return false;
    }
    return true;
}