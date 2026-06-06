const totpBtn = document.getElementById("totp-btn") as HTMLButtonElement;
const emailOtpBtn = document.getElementById("email-otp-btn") as HTMLButtonElement;

totpBtn.addEventListener("click", ()=>{
   window.location.href="mfa-setup.html"
})
emailOtpBtn.addEventListener("click", ()=>{
   window.location.href="mfa-email-setup.html"
})