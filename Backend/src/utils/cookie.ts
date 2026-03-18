const COOKIE_OPTIONS = "HttpOnly; Path=/; SameSite=Strict" as const;

const CSRF_COOKIE_OPTIONS = "Path=/; SameSite=Strict" as const;

export function buildSessionCookie(sessionId: string): string {
   return `sessionId=${sessionId}; ${COOKIE_OPTIONS}`;
}

export function clearSessionCookie(): string {
   return `sessionId=; ${COOKIE_OPTIONS}; Max-Age=0`;
}

export function buildCsrfToken(csrfToken: string): string{
   return `csrfToken=${csrfToken}; ${CSRF_COOKIE_OPTIONS}`;
}

export function clearCsrfToken(): string{
   return `csrfToken=; ${CSRF_COOKIE_OPTIONS}; Max-Age=0`;
}