import { UserCredentials, ApiResponse } from "./types/user";

const BASE_URL = "http://127.0.0.1:5000";

const DEFAULT_HEADERS = { "content-type": "application/json" };

let refreshPromise: Promise<boolean> | null = null;

async function attemptTokenRefresh(): Promise<boolean> {
   try {
      const res = await fetch(`${BASE_URL}/refresh`, {
         method: "POST",
         credentials: "include",
      });
      return res.ok;
   } catch {
      return false;
   }
}

function refreshOnce(): Promise<boolean> {
   if (!refreshPromise) {
      refreshPromise = attemptTokenRefresh().finally(() => {
         refreshPromise = null;
      });
   }
   return refreshPromise;
}

export async function postRequest(endpoint: string, data: UserCredentials): Promise<ApiResponse> {
   try {
      const response = await fetch(`${BASE_URL}${endpoint}`, {
         method: "POST",
         headers: DEFAULT_HEADERS,
         credentials: "include",
         body: JSON.stringify(data),
      });
      console.log(response)

      const message = await response.text();
      return {
         status: response.status,
         message,
      };
   } catch (error) {
      console.log("postRequest failed: ", error);
      return {
         status: 0,
         message: "Unable to reach server. Please try again.",
      };
   }
}

export async function postRequestNoBody(endpoint: string): Promise<ApiResponse> {
   const doFetch = () => {
      const csrfToken = getCsrfToken();
      const headers: Record<string, string> = {};
      if (csrfToken) {
         headers["X-CSRF-Token"] = csrfToken;
      }
      return fetch(`${BASE_URL}${endpoint}`, {
         method: "POST",
         credentials: "include",
         headers,
      });
   };

   try {
      let response = await doFetch();
      if (response.status === 401) {
         const refreshed = await refreshOnce();
         if (refreshed) {
            response = await doFetch();
         }
      }
      const message = await response.text();
      return {
         status: response.status,
         message,
      };
   } catch (error) {
      console.log("postRequest failed: ", error);
      return {
         status: 0,
         message: "Unable to reach server. Please try again.",
      };
   }
}

export async function postAuthJson<T>(endpoint: string, data?: object): Promise<ApiResponse & { data?: T }> {
   const doFetch = () => {
      const csrfToken = getCsrfToken();
      const headers: Record<string, string> = {};
      if (csrfToken) {
         headers["X-CSRF-Token"] = csrfToken;
      }
      if (data) {
         headers["Content-Type"] = "application/json";
      }
      return fetch(`${BASE_URL}${endpoint}`, {
         method: "POST",
         credentials: "include",
         headers,
         body: data ? JSON.stringify(data) : undefined,
      });
   };

   try {
      let response = await doFetch();
      console.log(response)
      if (response.status === 401) {
         const refreshed = await refreshOnce();
         if (refreshed) {
            response = await doFetch();
         }
      }

      const text = await response.text();
      if (!response.ok) {
         return { status: response.status, message: text };
      }

      let parsed: T | undefined;
      try {
         parsed = JSON.parse(text) as T;
      } catch {
         parsed = undefined;
      }

      return { status: response.status, message: text, data: parsed };
   } catch (error) {
      console.log("postAuthJson failed:", error);
      return { status: 0, message: "Unable to reach server. Please try again." };
   }
}

export async function postMfaVerify(code: string): Promise<ApiResponse> {
   const mfaType = sessionStorage.getItem("mfaType");
   const endpoint = mfaType === "email-otp" ? "/mfa/email/verify" : "/mfa/verify";
   try {
      const response = await fetch(`${BASE_URL}${endpoint}`, {
         method: "POST",
         headers: DEFAULT_HEADERS,
         credentials: "include",
         body: JSON.stringify({ code }),
      });
      const message = await response.text();
      return { status: response.status, message };
   } catch (error) {
      console.log("postMfaVerify failed:", error);
      return { status: 0, message: "Unable to reach server. Please try again" };
   }
}

export async function getRequest<T>(endpoint: string): Promise<ApiResponse & { data?: T }> {
   const doFetch = () => {
      const csrfToken = getCsrfToken();
      const headers: Record<string, string> = {};
      if (csrfToken) {
         headers["X-CSRF-Token"] = csrfToken;
      }
      return fetch(`${BASE_URL}${endpoint}`, {
         method: "GET",
         credentials: "include",
         headers,
      });
   };

   let response;
   try {
      response = await doFetch();
      if (response.status === 401) {
         const refreshed = await refreshOnce();
         if (refreshed) {
            response = await doFetch();
         }
      }
   } catch (error) {
      console.log("getRequest failed: ", error);
      return {
         status: 0,
         message: "Unable to reach server. Please try again.",
      };
   }

   const text = await response.text();
   if (!response.ok) {
      return {
         status: response.status,
         message: text,
      };
   }
   let data: T | undefined;
   try {
      data = JSON.parse(text) as T;
   } catch {
      data = undefined;
   }
   return {
      status: response.status,
      message: data ? "Ok" : "data unknown",
      data,
   };
}

function getCsrfToken(): string | undefined {
   const match = document.cookie.split("; ").find((row) => row.startsWith("csrfToken="));
   return match?.split("=").slice(1).join("=");
}

