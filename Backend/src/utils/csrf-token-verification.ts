import crypto  from "crypto";

export function compareCsrfToken(tokenFromPayload: string, tokenFromHeader: string): boolean{

    const a = Buffer.from(tokenFromPayload, "hex");
    const b = Buffer.from(tokenFromHeader, "hex");

    if(a.length !== b.length) return false;

    return crypto.timingSafeEqual(a, b);
}