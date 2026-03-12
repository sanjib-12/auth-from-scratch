import { UserCredentials, ApiResponse, ProfileData } from "./types/user";

const BASE_URL = "http://127.0.0.1:5000";

const DEFAULT_HEADERS = { "content-type": "application/json" };

export async function postRequest(endpoint: string, data: UserCredentials): Promise<ApiResponse> {
   try {
      const response = await fetch(`${BASE_URL}${endpoint}`, {
         method: "POST",
         headers: DEFAULT_HEADERS,
         credentials: "include",
         body: JSON.stringify(data),
      });

      const message = await response.text();
      return {
         status: response.status,
         message,
      };
   } catch (error) {
      console.log("postRequest failed: ", error);
      return {
         status: 0,
         message: "unable to reach server. Please try again.",
      };
   }
}

export async function postRequestNoBody(endpoint: string): Promise<ApiResponse> {
   try {
      const response = await fetch(`${BASE_URL}${endpoint}`, {
         method: "POST",
         credentials: "include",
      });

      const message = await response.text();
      return {
         status: response.status,
         message,
      };
   } catch (error) {
      console.log("postRequest failed: ", error);
      return {
         status: 0,
         message: "unable to reach server. Please try again.",
      };
   }
}

export async function getRequest<T>(endpoint: string): Promise<ApiResponse & { data?: T }> {
   let response;
   try {
      response = await fetch(`${BASE_URL}${endpoint}`, {
         method: "GET",
         credentials: "include",
      });
   } catch (error) {
      console.log("getRequest failed: ", error);
      return {
         status: 0,
         message: "unable to reach server. Please try again.",
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
