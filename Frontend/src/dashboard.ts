import { getRequest, postRequestNoBody } from "./api.js";
import { ProfileData } from "./types/user.js";

const emailDisplay = document.getElementById("user-email") as HTMLSpanElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const logoutBtn = document.getElementById("logout-btn") as HTMLButtonElement;
const mfaSection = document.getElementById("mfa-section") as HTMLDivElement;
const mfaStatus = document.getElementById("mfa-status") as HTMLSpanElement;
const mfaTypeStatus = document.getElementById("mfa-type-status") as HTMLSpanElement;
const mfaTypelabel = document.getElementById("mfa-type-label") as HTMLParagraphElement;
const mfaToggleBtn = document.getElementById("mfa-enable-btn") as HTMLButtonElement;

let mfaCurrentlyEnabled = false;
let mfaEnableType: string;

function setEnabledUi(): void {
   mfaCurrentlyEnabled = true;
   mfaStatus.textContent = "Enabled";
   mfaTypelabel.style.display = 'block';
   mfaTypeStatus.textContent = mfaEnableType;
   mfaStatus.classList.add("mfa-on");
   mfaStatus.classList.remove("mfa-off");
   mfaToggleBtn.classList.add("mfa-btn-disable");
   mfaToggleBtn.classList.remove("mfa-btn-enable");
   mfaToggleBtn.textContent = "Disable MFA";
   mfaToggleBtn.disabled = false;
}

function setDisabledUi(): void {
   mfaCurrentlyEnabled = false;
   mfaTypelabel.style.display = 'none';
   mfaStatus.textContent = "Disabled";
   mfaStatus.classList.add("mfa-off");
   mfaStatus.classList.remove("mfa-on");
   mfaToggleBtn.classList.add("mfa-btn-enable");
   mfaToggleBtn.classList.remove("mfa-btn-disable");
   mfaToggleBtn.textContent = "Enable MFA";
   mfaToggleBtn.disabled = false;
}

mfaToggleBtn.addEventListener("click", async () => {
   if (!mfaCurrentlyEnabled) {
      window.location.href = "mfa-options.html";
      return;
   }

   mfaToggleBtn.disabled = true;
   messageBox.style.color = "";
   messageBox.textContent = "Disabling MFA...";

   const endpoint:string = mfaEnableType === "totp"? "/mfa/disable" : "/mfa/email/disable";

   const response = await postRequestNoBody(endpoint);
   if (response.status === 204) {
      setDisabledUi();
      showMessage("MFA disabled");
   } else if (response.status === 400) {
      setDisabledUi();
      showMessage(response.message, "red");
   } else {
      mfaToggleBtn.disabled = false;
      showMessage("MFA disable failed. Please try again", "red");
   }
});

function showMessage(text: string, color: string = ""): void {
   messageBox.style.color = color;
   messageBox.textContent = text;
   setTimeout(() => {
      messageBox.textContent = "";
   }, 7000);
}

async function loadProfile(): Promise<void> {
   try {
      const response = await getRequest<ProfileData>("/profile");
      console.log(response)

      if (response.status === 401) {
         window.location.href = "login.html";
         return;
      }

      if (response.status !== 200) {
         messageBox.textContent = "Something went wrong loading your profile.";
         messageBox.style.color = "red";
         return;
      }

      const profile = response.data;
      if (!profile) {
         messageBox.textContent = "Something went wrong loading your profile.";
         messageBox.style.color = "red";
         return;
      }

      emailDisplay.textContent = profile.email;
      console.log(profile.mfaEnabled)
      console.log(profile.emailOtpEnable)
     

      if (profile.mfaEnabled || profile.emailOtpEnable) {
         mfaEnableType = profile.mfaEnabled ? "totp" : "email-otp";
         console.log(mfaEnableType)
         setEnabledUi();
      } else {
         setDisabledUi();
      }

      mfaSection.style.display = "block";
   } catch (error) {
      console.error("error loading profile", error);
   }
}

logoutBtn.addEventListener("click", async () => {
   logoutBtn.disabled = true;
   messageBox.style.color = "";
   messageBox.textContent = "Logging out...";

   const response = await postRequestNoBody("/logout");
   if (response.status === 204) {
      window.location.href = "login.html";
   } else {
      messageBox.textContent = "Logout failed. Please try again";
      messageBox.style.color = "red";
      logoutBtn.disabled = false;
   }
});

loadProfile();
