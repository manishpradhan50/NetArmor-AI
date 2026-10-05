const sb = window.netarmorSupabase;
const form = document.getElementById("updatePasswordForm");
const message = document.getElementById("updateMessage");
const button = document.getElementById("updatePasswordBtn");

let recoveryReady = false;

function showMessage(text, success = false) {
  if (!message) return;
  message.textContent = text;
  message.style.display = "block";
  message.style.color = success ? "#00ff88" : "#ff6b81";
}

if (sb) {
  sb.auth.onAuthStateChange((event, session) => {
    if (event === "PASSWORD_RECOVERY" || (session && (window.location.hash.includes("recovery") || window.location.hash.includes("access_token")))) {
      recoveryReady = true;
      showMessage("Password recovery session verified. Enter your new password below.", true);
    }
  });
}

async function init() {
  if (!sb) return showMessage("Supabase configuration missing. Check supabase-config.js.");

  // Allow Supabase JS a brief tick to parse tokens in URL hash
  if (window.location.hash.includes("access_token") || window.location.hash.includes("recovery") || window.location.search.includes("code")) {
    await new Promise((res) => setTimeout(res, 600));
  }

  const { data: { session } } = await sb.auth.getSession();
  if (!session && !recoveryReady) {
    showMessage("This password-reset link is missing or has expired. Please request a new one from the login portal.");
  }
}

form?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = document.getElementById("newPassword").value;
  const confirm = document.getElementById("confirmPassword").value;

  if (password.length < 8) return showMessage("Password must contain at least 8 characters.");
  if (password !== confirm) return showMessage("Passwords do not match.");
  if (!sb) return showMessage("Supabase is not configured correctly.");

  button.disabled = true;
  button.textContent = "Updating...";

  try {
    const { error } = await sb.auth.updateUser({ password });
    if (error) throw error;
    showMessage("Password updated successfully! Redirecting to login...", true);
    setTimeout(async () => {
      await sb.auth.signOut();
      sessionStorage.removeItem("netarmor_profile");
      window.location.replace("login.html");
    }, 1500);
  } catch (error) {
    showMessage(error.message || "Unable to update password.");
  } finally {
    button.disabled = false;
    button.textContent = "Update Password";
  }
});

init();
