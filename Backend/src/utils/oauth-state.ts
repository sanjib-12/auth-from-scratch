import crypto from "crypto";

interface OAuthState{
    codeVerifier: string;
    createdAt: number;
}

const stateStore = new Map<string, OAuthState>();
const STATE_TTL_MS = 5 * 60 * 1000;

export function createOAuthState():{state: string; codeChallenge: string }{
    const now = Date.now();
    for(const [key, val] of stateStore){
        if(now - val.createdAt > STATE_TTL_MS) stateStore.delete(key);
    }

    const state = crypto.randomBytes(32).toString("base64url");
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    stateStore.set(state, {codeVerifier, createdAt: Date.now()});
    return {state, codeChallenge}; 
}

export function consumeOAuthState(state: string): string | null{
    const entry = stateStore.get(state);
    if(!entry) return null;
    if(Date.now() - entry.createdAt > STATE_TTL_MS){
        stateStore.delete(state);
        return null;
    }

    stateStore.delete(state);
    return entry.codeVerifier;
}