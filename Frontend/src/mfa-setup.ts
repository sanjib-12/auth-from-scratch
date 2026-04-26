import { postAuthJson } from "./api.js";
import { MfaSetupData, MfaSetupResult } from "./types/user.js";

const qrContainer = document.getElementById("qr-container") as HTMLDivElement;
const manualKey = document.getElementById("manual-key") as HTMLElement;
const verifyForm = document.getElementById("verify-form") as HTMLFormElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const stepQr = document.getElementById("step-qr") as HTMLDivElement;
const stepRecovery = document.getElementById("step-recovery") as HTMLDivElement;
const recoveryList = document.getElementById("recovery-list") as HTMLUListElement;
const doneBtn = document.getElementById("done-btn") as HTMLButtonElement;
const submitBtn = document.getElementById("btn-mfa-setup-submit") as HTMLButtonElement;

async function initSetup(): Promise<void> {
   const response = await postAuthJson<MfaSetupData>("/mfa/setup");

   if (response.status === 401) {
      window.location.href = "login.html";
      return;
   }

   if (!response.data) {
      messageBox.textContent = "Failed to start MFA setup. MFA may already be enabled.";
      messageBox.style.color = "red";
      return;
   }

   const { secret, otpauthUri } = response.data;

   if (!("QRCode" in window)) {
      messageBox.textContent = "QR code library failed to load. Use the manual key below.";
      messageBox.style.color = "red";
   } else {
      const canvas = document.createElement("canvas");
      qrContainer.appendChild(canvas);
      try {
         (window as any).QRCode.toCanvas(canvas, otpauthUri, { width: 200 });
      } catch {
         qrContainer.removeChild(canvas);
         messageBox.textContent = "could not render QR code. Use the manual key below.";
         messageBox.style.color = "red";
      }
   }

   manualKey.textContent = secret;
}

verifyForm.addEventListener("submit", async (event) => {
   event.preventDefault();
   messageBox.textContent = "";
   submitBtn.disabled = true;

   const code = (document.getElementById("totp-code") as HTMLInputElement).value.trim();

   const response = await postAuthJson<MfaSetupResult>("/mfa/verify-setup", { code });

   if (response.status === 200 && response.data) {
      stepQr.style.display = "none";
      stepRecovery.style.display = "block";

      for (const recoveryCode of response.data.recoveryCodes) {
         const li = document.createElement("li");
         li.textContent = `${recoveryCode.slice(0, 5)} -${recoveryCode.slice(5)}`;
         recoveryList.appendChild(li);
      }
   } else {
      messageBox.textContent = "Invalid code. Please try again.";
      messageBox.style.color = "red";
      submitBtn.disabled = false;
   }
});

doneBtn.addEventListener("click", () => {
   window.location.href = "dashboard.html";
});

initSetup().catch(()=>{
   messageBox.textContent = "Network error during setup. Please refresh.";
   messageBox.style.color = "red";
});
