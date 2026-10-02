const sb = window.netarmorSupabase;
const form = document.getElementById("updatePasswordForm");
const message = document.getElementById("updateMessage");
const button = document.getElementById("updatePasswordBtn");

function showMessage(text, success=false) {
  message.textContent = text;
  message.style.display = "block";
  message.style.color = success ? "#00ff88" : "#ff6b81";
}

async function init() {
  if (!sb) return showMessage("Supabase is not configured correctly.");
  const { data: { session } } = await sb.auth.getSession();
  if (!session) showMessage("This password-reset link is missing or has expired. Request a new one from the login page.");
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
    showMessage("Password updated successfully. Redirecting to login...", true);
    setTimeout(async () => { await sb.auth.signOut(); window.location.replace("login.html"); }, 1500);
  } catch (error) {
    showMessage(error.message || "Unable to update password.");
  } finally {
    button.disabled = false;
    button.textContent = "Update Password";
  }
});

sb?.auth.onAuthStateChange((event) => {
  if (event === "PASSWORD_RECOVERY") showMessage("Recovery session detected. You can now set a new password.", true);
});

init();
