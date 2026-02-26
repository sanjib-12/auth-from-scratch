import { UserCredentials, ApiResponse } from "./types/user";

const BASE_URL = "http://localhost:5000";

export async function postRequest(endpoint: string, data:UserCredentials): Promise<ApiResponse>{
   try {
      
      const response = await fetch(`${BASE_URL}${endpoint}`, {
         method: 'POST',
         headers:{
            "Content-Type": "application/json"
         },
         body: JSON.stringify(data)
      });
   
      const message = await response.text();
      return {
         status:response.status,
         message
      }
   } catch (error) {
      console.log("postRequest failed: ",error );
      return{
         status: 0,
         message: "unable to reach server. Please try again."
      }
   }
}

