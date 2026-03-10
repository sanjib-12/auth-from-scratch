export function parseCookies(cookieHeader?: string) {
   const cookies: Record<string, string> = {};

   if (!cookieHeader) return cookies;

   cookieHeader.split(";").forEach((cookie) => {
      const eqIndex = cookie.indexOf("=");
      if (eqIndex === -1) return;
      const key = cookie.slice(0, eqIndex).trim();
      const value = cookie.slice(eqIndex + 1).trim();
      cookies[key] = value;
   });
   return cookies;
}
