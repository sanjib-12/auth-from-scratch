import { postMfaVerify, postAuthJson } from "./api.js";

const form = document.getElementById("mfa-form") as HTMLFormElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const btnMfaVerifySubmit = document.getElementById("btn-mfa-verify") as HTMLButtonElement;
const resendBtn = document.getElementById("btn-mfa-resend") as HTMLButtonElement;
const instructions = document.getElementById("mfa-instructions") as HTMLParagraphElement;

const mfaType = sessionStorage.getItem("mfaType");
instructions.textContent = mfaType === "email-otp"
   ? "Enter the code sent to your email."
   : "Enter the 6-digit code from your authenticator app, or a recovery code.";

function loadMfaVerify() {
   if (mfaType === "email-otp"){
      resendBtn.style.display = "block";
   }

}

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

resendBtn.addEventListener("click", async()=>{
   resendBtn.disabled = true;
   const response = await postAuthJson("/mfa/email/request");
   console.log(response)
   if(response.status === 200){
      const res = JSON.parse(response.message);
      messageBox.textContent = res.message;
      resendBtn.disabled = false;
   }else{
      resendBtn.disabled = false;
      messageBox.textContent = "Wait for a few moment and try again.";
   }
})

loadMfaVerify()