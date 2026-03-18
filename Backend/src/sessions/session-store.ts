import crypto from "crypto";
interface Session {
  email: string;
  csrfToken: string;
  expireAt: number;
}

const sessions = new Map<string, Session>();

const SESSION_DURATION_MS = 1000 * 60 * 5; // 5min

export function createSession(sessionId: string, csrfToken: string,  email: string): void {
  sessions.set(sessionId, {
    email,
    csrfToken,
    expireAt: Date.now() + SESSION_DURATION_MS,
  });
}

export function getSession(sessionId: string): string | undefined {
  const session = sessions.get(sessionId);

  if (!session) return undefined;

  if (Date.now() > session.expireAt) {
    deleteSession(sessionId);
    return undefined;
  }

  return session.email;
}

export function deleteSession(sessionId: string): void {
  sessions.delete(sessionId);
}

export function getCsrfToken(sessionId: string): string | undefined {
  const session = sessions.get(sessionId);

  if (!session) return undefined;

  if (Date.now() > session.expireAt) {
    deleteSession(sessionId);
    return undefined;
  }

  return session.csrfToken;
}
