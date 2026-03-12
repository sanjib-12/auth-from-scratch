import { postRequest } from "./api.js";

const form = document.getElementById("login-form") as HTMLFormElement;
const messageBox = document.getElementById("message") as HTMLDivElement;

const endpoint = "/login";

form.addEventListener("submit", async (event) => {
   event.preventDefault();
   try {
      const email = (document.getElementById("email") as HTMLInputElement).value;
      const password = (document.getElementById("password") as HTMLInputElement).value;

      const response = await postRequest(endpoint, { email, password });

      messageBox.textContent = response.message;
      if (response.status === 200) {
         messageBox.style.color = "green";
         setTimeout(() => {
            window.location.href = "dashboard.html";
         }, 800);
      } else {
         messageBox.style.color = "red";
      }
   } catch (error) {
      console.error("Error in login:", error);
      messageBox.textContent = "Something went wrong!";
      messageBox.style.color = "red";
   }
});
