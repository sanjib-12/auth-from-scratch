import { getRequest, postRequestNoBody } from "./api.js";
import { ProfileData } from "./types/user.js";

const emailDisplay = document.getElementById("user-email") as HTMLSpanElement;
const messageBox = document.getElementById("message") as HTMLDivElement;
const logoutBtn = document.getElementById("logout-btn") as HTMLButtonElement;

async function loadProfile(): Promise<void> {
   try {
      const response = await getRequest<ProfileData>("/profile");

      if (response.status === 401) {
         window.location.href = "login.html";
         return;
      }

      if (response.status !== 200) {
         messageBox.textContent = "Something went wrong loading your profile.";
         messageBox.style.color = "red";
         return;
      }

      const profile = response.data as ProfileData;

      emailDisplay.textContent = profile.email;
   } catch (error) {
      console.error("error loading profile", error);
   }
}

logoutBtn.addEventListener("click", async () => {
   logoutBtn.disabled = true;
   messageBox.textContent = "logging out...";

   const response = await postRequestNoBody("/logout");
   if (response.status === 204) {
      window.location.href = "login.html";
   } else {
      messageBox.textContent = "Logout failed. please try again";
      messageBox.style.color = "red";
      logoutBtn.disabled = false;
   }
});

loadProfile();
