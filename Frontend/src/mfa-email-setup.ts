import {postAuthJson} from './api.js';

const enableEmailOtpBtn = document.getElementById("enable-email-otp") as HTMLButtonElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const successMessageBox = document.getElementById("success-message") as HTMLDivElement;
const formSection = document.getElementById("mfa-form") as HTMLFormElement;
const submitBtn = document.getElementById("btn-mfa-verify") as HTMLButtonElement;
const resendBtn = document.getElementById("btn-mfa-resend") as HTMLButtonElement

enableEmailOtpBtn.addEventListener("click", async ()=>{
   enableEmailOtpBtn.disabled = true;
   const response = await postAuthJson("/mfa/email/setup");
   
   if (response.status === 401) {
      window.location.href = "login.html";
      return;
   }
   
   if( response.status === 0 ){
      messageBox.textContent = response.message;
      messageBox.style.color = "red";
   }

   if (response.status === 200) {
      formSection.style.display = "block";
      const res = JSON.parse(response.message);
      successMessageBox.textContent = res.message
      messageBox.textContent = "The email based MFA is active. Please enter the OTP for verification"
      messageBox.style.color = "green";
   } else {
      enableEmailOtpBtn.disabled = false;
      messageBox.textContent = response.message;
      messageBox.style.color = "red";
   }
})

formSection.addEventListener("submit", async (event)=>{
   event.preventDefault();
   messageBox.textContent = "";
   submitBtn.disabled = true;
   
   const code = (document.getElementById("otp-code") as HTMLInputElement).value.trim();
   
   const response = await postAuthJson("/mfa/email/verify-setup", { code });
   
   if (response.status === 200) {
      const res = JSON.parse(response.message);
      successMessageBox.textContent = res.message
      messageBox.textContent = "The email based MFA is activated."
      messageBox.style.color = "green";
   } else {
      messageBox.textContent = "Invalid code. Please try again.";
      messageBox.style.color = "red";
      submitBtn.disabled = false;
   }
})


resendBtn.addEventListener("click", async()=>{
   resendBtn.disabled = true;
   const response = await postAuthJson("/mfa/email/request");
   if(response.status === 200){
      const res = JSON.parse(response.message);
      successMessageBox.textContent = res.message;
      resendBtn.disabled = false;
   }else{
      const res = JSON.parse(response.message);
      successMessageBox.textContent = res.message;
      resendBtn.disabled = false;
   }
})
