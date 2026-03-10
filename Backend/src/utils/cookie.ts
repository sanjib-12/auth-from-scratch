const COOKIE_OPTIONS = "HttpOnly; Path=/; SameSite=Strict" as const;

export function buildSessionCookie(sessionId: string): string {
   return `sessionId=${sessionId}; ${COOKIE_OPTIONS}`;
}

export function clearSessionCookie(): string {
   return `sessionId=; ${COOKIE_OPTIONS}; Max-Age=0`;
}
