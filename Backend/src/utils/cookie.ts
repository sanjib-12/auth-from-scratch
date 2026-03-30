const JWT_COOKIE_OPTIONS = "HttpOnly; Path=/; SameSite=Strict" as const;
const CSRF_COOKIE_OPTIONS = "Path=/; SameSite=Strict" as const;

export function buildJwtCookie(jwt: string): string {
   return `jwt=${jwt}; ${JWT_COOKIE_OPTIONS}`;
}

export function clearJwtCookie(): string {
   return `jwt=; ${JWT_COOKIE_OPTIONS}; Max-Age=0`;
}

export function buildCsrfCookie(csrfToken: string): string{
   return `csrfToken=${csrfToken}; ${CSRF_COOKIE_OPTIONS}`;
}

export function clearCsrfCookie(): string{
   return `csrfToken=; ${CSRF_COOKIE_OPTIONS}; Max-Age=0`;
}