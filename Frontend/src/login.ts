import { postRequest } from "./api.js";

const form = document.getElementById("login-form") as HTMLFormElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const btnLogin = document.getElementById("btn-login") as HTMLButtonElement;
const params = new URLSearchParams(window.location.search);
const err = params.get("error");

if(err){
   const el = document.getElementById("oauthError")as HTMLDivElement;
   const messages : Record<string, string> = {
      oauth_denied: "Google sign-in was cancelled.",
      invalid_state: "Sign-in session expired. Please try again.",
      oauth_failed: "Google sign-in failed. Please try again."
   };
   el.textContent = messages[err] ?? "sign-in error. Please try again.";
   el.style.display = "block";
}

const endpoint = "/login";

form.addEventListener("submit", async (event) => {
   event.preventDefault();
   btnLogin.disabled = true;
   try {
      const email = (document.getElementById("email") as HTMLInputElement).value.trim();
      const password = (document.getElementById("password") as HTMLInputElement).value;

      const response = await postRequest(endpoint, { email, password });

      if (response.status === 200) {
         messageBox.style.color = "green";
         const msg = JSON.parse(response.message);
         messageBox.textContent = msg.message;
         setTimeout(() => {
            window.location.href = "dashboard.html";
         }, 800);
      } else if (response.status === 202) {
         const body = JSON.parse(response.message);
         sessionStorage.setItem("mfaType", body.mfaType);
         messageBox.style.color = "green";
         messageBox.textContent = "MFA required, redirecting...";
         setTimeout(() => {
            window.location.href = "mfa-verify.html";
         }, 800);
      } else {
         messageBox.style.color = "red";
         btnLogin.disabled = false;
      }
   } catch (error) {
      console.error("Error in login:", error);
      messageBox.textContent = "Something went wrong!";
      messageBox.style.color = "red";
      btnLogin.disabled = false;
   }
});
