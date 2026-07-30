import https from "https";
import crypto from "crypto";
import { readUsers,writeUsers } from "../utils/read-write";
import { User, OAuthProvider} from "../types/auth-types";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const REDIRECT_URL = "http://127.0.0.1:5000/oauth/google/callback";

export function buildGoogleAuthUrl(state: string, codeChallenge: string): string{
    const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: REDIRECT_URL,
        response_type: "code",
        scope: "openid email profile",
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        prompt: "select_account",
    })
    return `https://accounts.google.com/o/oauth2/v2/auth?${params}`
}

function httpsPost(hostname: string, path: string, body: string): Promise<string>{
    return new Promise((resolve, reject) => { 
        const req = https.request(
            {
                hostname,
                path,
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": Buffer.byteLength(body),
                },
            },
            (res) => {
                let data = "";
                res.on("data", (chunk) => (data += chunk));
                res.on("end", () => resolve(data));
            }
        );
        req.on("error", reject);
        req.write(body);
        req.end();
    });
}

function httpsGet(hostname: string, path: string, accessToken: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const req = https.request(
            {
                hostname,
                path,
                method: "GET",
                headers: { Authorization: `Bearer ${accessToken}`},
            },
            (res) => {
                let data = "";
                res.on("data", (chunk) => (data += chunk));
                res.on("end", () => resolve(data));
            }
        );
        req.on("error", reject);
        req.end();
    });
}

export async function exchangeCodeForAccessToken(code: string , codeVerifier: string): Promise<string> {
    const body = new URLSearchParams({
        code, 
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: REDIRECT_URL,
        grant_type: "authorization_code",
        code_verifier: codeVerifier,
    }).toString();

    const raw = await httpsPost("oauth2.googleapis.com", "/token", body);
    const data = JSON.parse(raw);
    if ( !data.access_token ) throw new Error(`Token exchange failed: ${raw}`);
    return data.access_token as string;
}

export interface GoogleUser {
    id: string;
    email: string;
    name: string;
    picture: string;
}

export async function getGoogleUserInfo(accessToken: string): Promise<GoogleUser> {
    const raw = await httpsGet("www.googleapis.com", "/oauth2/v2/userinfo", accessToken);
    const data = JSON.parse(raw);
    if(!data.id || !data.email) throw new Error(`Invalid userinfo response: ${raw}`);
    return { id: data.id, email: data.email, name: data.name, picture: data.picture};
}

export async function findOrCreateOAuthUser(googleUser: GoogleUser): Promise<User>{
    const users = await readUsers();

    const byId = users.find((u) => u.oauthProviders?.some((p) => p.provider === "google" && p.providerId === googleUser.id));

    if(byId) return byId;

    const newProvider: OAuthProvider = {
        provider: "google",
        providerId: googleUser.id,
        linkedAt: new Date().toISOString(),
    };

    const byEmail = users.find((u) => u.email === googleUser.email.trim().toLocaleLowerCase());

    if(byEmail){
        byEmail.oauthProviders = [...(byEmail.oauthProviders ??[]), newProvider];
        await writeUsers(users);
        return byEmail;
    }

    const newUser: User = {
        id: crypto.randomUUID(),
        email: googleUser.email.trim().toLocaleLowerCase(),
        oauthProviders: [newProvider],
    }
    users.push(newUser);
    await writeUsers(users);
    return newUser;
}
