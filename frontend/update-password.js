const getAuth = () => window.netarmorAuth;
const form = document.getElementById("updatePasswordForm");
const message = document.getElementById("updateMessage");
const button = document.getElementById("updatePasswordBtn");

const urlParams = new URLSearchParams(window.location.search);
const oobCode = urlParams.get("oobCode");
let resetActionVerified = false;

function showMessage(text, success = false) {
  if (!message) return;
  message.textContent = text;
  message.style.display = "block";
  message.style.color = success ? "#00ff88" : "#ff6b81";
}

async function init() {
  const auth = getAuth();
  if (!auth) {
    showMessage("Firebase is not initialized. Check firebase-config.js.");
    return;
  }

  // Check if we arrived via a Firebase password-reset email link (contains oobCode)
  if (oobCode) {
    try {
      const email = await auth.verifyPasswordResetCode(oobCode);
      resetActionVerified = true;
      showMessage(`Password recovery verified for ${email}. Enter your new password below.`, true);
      return;
    } catch (err) {
      console.error("Code verification error:", err);
      showMessage("This password-reset link is invalid or has expired. Please request a new link.");
      return;
    }
  }

  // Otherwise, check if user is currently signed in
  const user = await window.netarmorAuthReady();
  if (!user && !resetActionVerified) {
    showMessage("No password reset code found and no active session. Please request a reset link from the login portal.");
  }
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = document.getElementById("newPassword").value;
  const confirm = document.getElementById("confirmPassword").value;

  if (password.length < 8) return showMessage("Password must contain at least 8 characters.");
  if (password !== confirm) return showMessage("Passwords do not match.");

  const auth = getAuth();
  if (!auth) return showMessage("Firebase is not configured correctly.");

  button.disabled = true;
  button.textContent = "Updating...";

  try {
    if (oobCode) {
      // 1. Reset password using email action code
      await auth.confirmPasswordReset(oobCode, password);
    } else if (auth.currentUser) {
      // 2. Active session password update
      await auth.currentUser.updatePassword(password);
    } else {
      throw new Error("Session expired or reset code is missing.");
    }

    showMessage("Password updated successfully! Redirecting to login...", true);
    setTimeout(async () => {
      try {
        await auth.signOut();
      } catch (_) {}
      sessionStorage.removeItem("netarmor_profile");
      window.location.replace("login.html");
    }, 1500);
  } catch (error) {
    console.error("Password update error:", error);
    showMessage(error.message || "Unable to update password.");
  } finally {
    button.disabled = false;
    button.textContent = "Update Password";
  }
});

document.addEventListener("DOMContentLoaded", init);
