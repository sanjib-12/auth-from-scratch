import crypto  from "crypto";
import { getCsrfToken } from "../sessions/session-store";

export function compareCsrfToken(sessionId: string, tokenFromHeader: string): boolean{
    const storedCsrfToken = getCsrfToken(sessionId);

    if(!storedCsrfToken) return false;

    const a = Buffer.from(storedCsrfToken, "hex");
    const b = Buffer.from(tokenFromHeader, "hex");

    if(a.length !== b.length) return false;

    return crypto.timingSafeEqual(a, b);
}