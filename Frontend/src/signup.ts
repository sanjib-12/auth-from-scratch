import { postRequest } from "./api.js";

const form = document.getElementById("signup-form") as HTMLFormElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const btnSignup = document.getElementById("btn-signup") as HTMLButtonElement;

const endpoint = "/signup";

form.addEventListener("submit", async (event) => {
   event.preventDefault();
   btnSignup.disabled = true;
   try {
      const email = (document.getElementById("email") as HTMLInputElement).value.trim();
      const password = (document.getElementById("password") as HTMLInputElement).value;

      const data = {
         email,
         password,
      };
      const response = await postRequest(endpoint, data);

      messageBox.textContent = response.message;
      if (response.status === 201) {
         messageBox.style.color = "green";
         setTimeout(() => {
            window.location.href = "login.html";
         }, 1000);
      } else {
         messageBox.style.color = "red";
         btnSignup.disabled = false;
      }
   } catch (error) {
      messageBox.textContent = "Something went wrong";
      messageBox.style.color = "red";
      btnSignup.disabled = false;
   }
});
