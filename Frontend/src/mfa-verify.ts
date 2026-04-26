import { postMfaVerify } from "./api.js";

const form = document.getElementById("mfa-form") as HTMLFormElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const btnMfaVerifySubmit = document.getElementById("btn-mfa-verify") as HTMLButtonElement;

form.addEventListener("submit", async (event) => {
   event.preventDefault();
   btnMfaVerifySubmit.disabled = true;
   const code = (document.getElementById("mfa-code") as HTMLInputElement).value.trim();
   const response = await postMfaVerify(code);
   messageBox.textContent = response.message;
   if (response.status === 200) {
      messageBox.style.color = "green";
      setTimeout(() => {
         window.location.href = "dashboard.html";
      }, 800);
   } else {
      messageBox.style.color = "red";
      btnMfaVerifySubmit.disabled = false;
   }
});
