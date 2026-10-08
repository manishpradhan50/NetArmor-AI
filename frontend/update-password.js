/* =========================================================
   NetArmor AI - Update Password & Security Controller
   Dual Mode: Email Reset (oobCode) & Active User Session
   ========================================================= */

const getAuth = () => window.netarmorAuth;
const form = document.getElementById("updatePasswordForm");
const messageBox = document.getElementById("updateMessage");
const submitBtn = document.getElementById("updatePasswordBtn");
const currentPasswordGroup = document.getElementById("currentPasswordGroup");
const sessionBanner = document.getElementById("sessionBanner");
const sessionBannerText = document.getElementById("sessionBannerText");
const pwdSubTitle = document.getElementById("pwdSubTitle");

const urlParams = new URLSearchParams(window.location.search);
const oobCode = urlParams.get("oobCode");

let resetActionVerified = false;
let activeSessionUser = null;

/* Feedback Message Display */
function showFeedback(text, type = "error") {
  if (!messageBox) return;
  messageBox.className = `auth-message ${type}`;
  const icon = type === "success" 
    ? '<i class="fa-solid fa-circle-check" style="color: #00ff88;"></i>' 
    : type === "info" 
    ? '<i class="fa-solid fa-circle-info" style="color: #38bdf8;"></i>' 
    : '<i class="fa-solid fa-circle-exclamation" style="color: #ff5577;"></i>';
  
  messageBox.innerHTML = `${icon} <span>${text}</span>`;
  messageBox.style.display = "flex";
}

function clearFeedback() {
  if (messageBox) {
    messageBox.style.display = "none";
    messageBox.textContent = "";
  }
}

/* Firebase Error Formatter */
function formatAuthError(err) {
  if (!err) return "An unexpected error occurred.";
  const code = err.code || "";
  switch (code) {
    case "auth/wrong-password":
    case "auth/invalid-credential":
      return "Current password is incorrect. Please re-enter your existing password.";
    case "auth/weak-password":
      return "The password is too weak. Please meet all complexity criteria.";
    case "auth/expired-action-code":
      return "This password reset link has expired. Please request a new link.";
    case "auth/invalid-action-code":
      return "This password reset link is invalid or has already been used.";
    case "auth/requires-recent-login":
      return "For security, please log out and log back in before updating your password.";
    default:
      return err.message ? err.message.replace(/^Firebase:\s*/, "") : "Failed to update password.";
  }
}

/* Eye Visibility Toggles */
function initEyeToggles() {
  document.querySelectorAll(".password-eye-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      const icon = btn.querySelector("i");
      if (!input) return;

      if (input.type === "password") {
        input.type = "text";
        if (icon) icon.className = "fa-solid fa-eye-slash";
      } else {
        input.type = "password";
        if (icon) icon.className = "fa-solid fa-eye";
      }
    });
  });
}

/* Live Password Strength Meter */
function evaluateStrength(pwd) {
  const hasLen = pwd.length >= 8;
  const hasUpperLower = /[a-z]/.test(pwd) && /[A-Z]/.test(pwd);
  const hasNumber = /[0-9]/.test(pwd);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd);

  updateCritItem("critLength", hasLen);
  updateCritItem("critUpperLower", hasUpperLower);
  updateCritItem("critNumber", hasNumber);
  updateCritItem("critSpecial", hasSpecial);

  let score = 0;
  if (hasLen) score++;
  if (hasUpperLower) score++;
  if (hasNumber) score++;
  if (hasSpecial) score++;

  const fill = document.getElementById("strengthBarFill");
  const label = document.getElementById("strengthLabel");

  if (!fill || !label) return score;

  if (pwd.length === 0) {
    fill.style.width = "0%";
    fill.style.backgroundColor = "#ef4444";
    label.textContent = "Too Weak";
    label.style.color = "#ff5577";
  } else if (score <= 1) {
    fill.style.width = "25%";
    fill.style.backgroundColor = "#ef4444";
    label.textContent = "Weak";
    label.style.color = "#ff5577";
  } else if (score === 2) {
    fill.style.width = "50%";
    fill.style.backgroundColor = "#f97316";
    label.textContent = "Moderate";
    label.style.color = "#f97316";
  } else if (score === 3) {
    fill.style.width = "75%";
    fill.style.backgroundColor = "#38bdf8";
    label.textContent = "Strong";
    label.style.color = "#38bdf8";
  } else {
    fill.style.width = "100%";
    fill.style.backgroundColor = "#00ff88";
    label.textContent = "Fortified";
    label.style.color = "#00ff88";
  }

  return score;
}

function updateCritItem(id, met) {
  const item = document.getElementById(id);
  if (!item) return;
  item.classList.toggle("met", met);
  const icon = item.querySelector("i");
  if (icon) {
    icon.className = met ? "fa-solid fa-circle-check" : "fa-solid fa-circle-xmark";
  }
}

/* Password Match Indicator */
function checkMatch() {
  const newPwd = document.getElementById("newPassword")?.value || "";
  const confPwd = document.getElementById("confirmPassword")?.value || "";
  const indicator = document.getElementById("matchIndicator");
  if (!indicator) return true;

  if (!confPwd) {
    indicator.style.display = "none";
    return false;
  }

  if (newPwd === confPwd) {
    indicator.className = "match-indicator matched";
    indicator.innerHTML = '<i class="fa-solid fa-circle-check"></i> <span>Passwords match</span>';
    return true;
  } else {
    indicator.className = "match-indicator unmatched";
    indicator.innerHTML = '<i class="fa-solid fa-circle-xmark"></i> <span>Passwords do not match</span>';
    return false;
  }
}

/* Initialization */
async function init() {
  initEyeToggles();

  const newPwdInput = document.getElementById("newPassword");
  const confPwdInput = document.getElementById("confirmPassword");

  newPwdInput?.addEventListener("input", () => {
    evaluateStrength(newPwdInput.value);
    if (confPwdInput?.value) checkMatch();
  });

  confPwdInput?.addEventListener("input", checkMatch);

  const auth = getAuth();
  if (!auth) {
    showFeedback("Firebase client failed to initialize. Check network connectivity.", "error");
    return;
  }

  // Case 1: Arrived via verified Firebase password reset email link
  if (oobCode) {
    try {
      const email = await auth.verifyPasswordResetCode(oobCode);
      resetActionVerified = true;
      if (sessionBanner && sessionBannerText) {
        sessionBannerText.textContent = `Password reset token verified for: ${email}`;
        sessionBanner.style.display = "flex";
      }
      if (pwdSubTitle) {
        pwdSubTitle.textContent = `Choose a new master password for account ${email}.`;
      }
      showFeedback(`Reset code verified for ${email}. Enter your new password below.`, "info");
      return;
    } catch (err) {
      console.error("Code verification error:", err);
      showFeedback(formatAuthError(err), "error");
      if (submitBtn) submitBtn.disabled = true;
      return;
    }
  }

  // Case 2: Active authenticated session (e.g. user changing password from dashboard)
  try {
    const user = await window.netarmorAuthReady();
    if (user) {
      activeSessionUser = user;
      if (currentPasswordGroup) {
        currentPasswordGroup.style.display = "block";
      }
      if (sessionBanner && sessionBannerText) {
        sessionBannerText.textContent = `Authenticated Analyst: ${user.email}`;
        sessionBanner.style.display = "flex";
      }
      if (pwdSubTitle) {
        pwdSubTitle.textContent = `Updating security key for account: ${user.email}`;
      }
    } else {
      showFeedback("No active reset code found. To reset via email, use the 'Forgot Password' link on the login page.", "info");
    }
  } catch (err) {
    console.warn("Auth ready check:", err);
  }
}

/* Form Submission */
form?.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearFeedback();

  const newPwd = document.getElementById("newPassword")?.value || "";
  const confPwd = document.getElementById("confirmPassword")?.value || "";
  const currentPwd = document.getElementById("currentPassword")?.value || "";

  if (newPwd.length < 8) {
    showFeedback("New password must be at least 8 characters.", "error");
    return;
  }

  const score = evaluateStrength(newPwd);
  if (score < 2) {
    showFeedback("Password does not meet minimum complexity standards.", "error");
    return;
  }

  if (newPwd !== confPwd) {
    showFeedback("New password and confirmation do not match.", "error");
    return;
  }

  const auth = getAuth();
  if (!auth) {
    showFeedback("Authentication service unavailable.", "error");
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Fortifying Credentials...';
  }

  try {
    if (oobCode) {
      // 1. Password Reset with Email Action Code
      await auth.confirmPasswordReset(oobCode, newPwd);
      showFeedback("Master password updated successfully! Redirecting to login...", "success");
      setTimeout(() => {
        window.location.replace("login.html");
      }, 2000);

    } else if (activeSessionUser) {
      // 2. In-Session Update with Re-authentication
      if (!currentPwd) {
        showFeedback("Please enter your current password to authorize this security update.", "error");
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Update Password';
        }
        return;
      }

      const credential = firebase.auth.EmailAuthProvider.credential(activeSessionUser.email, currentPwd);
      await activeSessionUser.reauthenticateWithCredential(credential);
      await activeSessionUser.updatePassword(newPwd);

      showFeedback("Password updated securely! Re-authenticating session...", "success");
      setTimeout(async () => {
        try {
          await auth.signOut();
        } catch (_) {}
        sessionStorage.removeItem("netarmor_profile");
        window.location.replace("login.html");
      }, 2000);

    } else {
      throw new Error("No active session or valid reset token found. Please request a new reset email from the login page.");
    }

  } catch (err) {
    console.error("Password update error:", err);
    showFeedback(formatAuthError(err), "error");
  } finally {
    if (submitBtn && !messageBox.classList.contains("success")) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i class="fa-solid fa-shield-halved"></i> Update Password';
    }
  }
});

document.addEventListener("DOMContentLoaded", init);
