/* =========================================================
   NetArmor AI - Authentication System (login.js)
   Fully Integrated with Google Firebase Auth & Cloud Firestore
   ========================================================= */

const getAuth = () => window.netarmorAuth;
const getDb = () => window.netarmorDb;

// DOM Elements
const loginCard = document.getElementById("loginCard");
const registerCard = document.getElementById("registerCard");
const resetCard = document.getElementById("resetCard");

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const resetForm = document.getElementById("resetForm");

const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");
const resetBtn = document.getElementById("resetBtn");

const loginBtnText = document.getElementById("loginBtnText");
const registerBtnText = document.getElementById("registerBtnText");
const resetBtnText = document.getElementById("resetBtnText");

const loginSpinner = document.getElementById("loginSpinner");
const registerSpinner = document.getElementById("registerSpinner");
const resetSpinner = document.getElementById("resetSpinner");

const loginMessage = document.getElementById("loginMessage");
const registerMessage = document.getElementById("registerMessage");
const resetMessage = document.getElementById("resetMessage");

const showRegisterBtn = document.getElementById("showRegister");
const showLoginBtn = document.getElementById("showLogin");
const forgotPasswordLink = document.getElementById("forgotPasswordLink");
const backToLoginBtn = document.getElementById("backToLogin");

/* =========================================================
   ERROR FORMATTER
   ========================================================= */

function formatFirebaseError(err) {
  if (!err) return "An unexpected error occurred.";
  const code = err.code || "";
  switch (code) {
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found":
      return "Invalid email or password. Please check your credentials.";
    case "auth/email-already-in-use":
      return "An account with this email already exists. Please sign in.";
    case "auth/weak-password":
      return "Password should be at least 8 characters long.";
    case "auth/invalid-email":
      return "Please enter a valid email address.";
    case "auth/too-many-requests":
      return "Access temporarily blocked due to repeated failed attempts. Please try again later.";
    case "auth/network-request-failed":
      return "Network connection issue. Check your internet connection.";
    default:
      return err.message ? err.message.replace(/^Firebase:\s*/, "") : "Operation failed.";
  }
}

/* =========================================================
   CARD SWITCHING & URL HASH ROUTING
   ========================================================= */

function clearMessages() {
  [loginMessage, registerMessage, resetMessage].forEach((msg) => {
    if (msg) {
      msg.style.display = "none";
      msg.textContent = "";
      msg.className = "auth-message";
    }
  });
}

function showLogin() {
  clearMessages();
  if (registerCard) registerCard.classList.add("hidden");
  if (resetCard) resetCard.classList.add("hidden");
  if (loginCard) loginCard.classList.remove("hidden");
  if (window.location.hash !== "#login") {
    history.replaceState(null, "", "#login");
  }
}

function showRegister() {
  clearMessages();
  if (loginCard) loginCard.classList.add("hidden");
  if (resetCard) resetCard.classList.add("hidden");
  if (registerCard) registerCard.classList.remove("hidden");
  if (window.location.hash !== "#register") {
    history.replaceState(null, "", "#register");
  }
}

function showReset() {
  clearMessages();
  if (loginCard) loginCard.classList.add("hidden");
  if (registerCard) registerCard.classList.add("hidden");
  if (resetCard) resetCard.classList.remove("hidden");
  if (window.location.hash !== "#reset") {
    history.replaceState(null, "", "#reset");
  }

  const loginEmailInput = document.getElementById("loginEmail");
  const resetEmailInput = document.getElementById("resetEmail");
  if (loginEmailInput && resetEmailInput && loginEmailInput.value.trim() && !resetEmailInput.value.trim()) {
    resetEmailInput.value = loginEmailInput.value.trim();
  }
}

// Bind Navigation Triggers
showRegisterBtn?.addEventListener("click", (e) => {
  e.preventDefault();
  showRegister();
});

showLoginBtn?.addEventListener("click", (e) => {
  e.preventDefault();
  showLogin();
});

forgotPasswordLink?.addEventListener("click", (e) => {
  e.preventDefault();
  showReset();
});

backToLoginBtn?.addEventListener("click", (e) => {
  e.preventDefault();
  showLogin();
});

// Hash change detection
window.addEventListener("hashchange", () => {
  const hash = window.location.hash.toLowerCase();
  if (hash === "#register") showRegister();
  else if (hash === "#reset" || hash === "#forgot") showReset();
  else showLogin();
});

/* =========================================================
   UI FEEDBACK HELPERS
   ========================================================= */

function showMessage(element, message, type = "error") {
  if (!element) return;
  element.style.display = "block";
  element.textContent = message;
  element.className = `auth-message ${type === "success" ? "success" : "error"}`;
  element.style.color = type === "success" ? "#00ff88" : "#ff6b81";
}

function setBtnLoading(btn, textElem, spinnerElem, isLoading, defaultText) {
  if (!btn) return;
  btn.disabled = isLoading;
  if (textElem) textElem.textContent = isLoading ? "Processing..." : defaultText;
  if (spinnerElem) {
    if (isLoading) spinnerElem.classList.remove("hidden");
    else spinnerElem.classList.add("hidden");
  }
}

function checkFirebaseInit(msgElement) {
  if (typeof window.isFirebaseConfigured === "function" && !window.isFirebaseConfigured()) {
    showMessage(
      msgElement,
      "Firebase configuration missing. Please update FIREBASE_CONFIG in firebase-config.js."
    );
    return false;
  }
  if (!getAuth() || !getDb()) {
    showMessage(
      msgElement,
      "Firebase client not initialized. Check firebase-config.js."
    );
    return false;
  }
  return true;
}

/* =========================================================
   CHECK ACTIVE SESSION (Auto-redirect if already logged in)
   ========================================================= */

async function checkActiveSession() {
  const auth = getAuth();
  const db = getDb();
  if (!auth) return;

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get("action") === "logout") {
    try {
      await auth.signOut();
    } catch (_) {}
    sessionStorage.removeItem("netarmor_profile");
    return;
  }

  try {
    const user = await window.netarmorAuthReady();
    if (user && db) {
      let role = "user";
      try {
        const doc = await db.collection("profiles").doc(user.uid).get();
        if (doc.exists) {
          role = String(doc.data().role || "user").toLowerCase();
        }
      } catch (_) {}

      if (role === "associate") {
        window.location.replace("admin-dashboard.html");
      } else {
        window.location.replace("dashboard.html");
      }
    }
  } catch (err) {
    console.warn("Session check bypassed:", err);
  }
}

/* =========================================================
   LOGIN FLOW
   ========================================================= */

loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessages();

  if (!checkFirebaseInit(loginMessage)) return;

  const auth = getAuth();
  const db = getDb();

  const roleElem = document.getElementById("loginRole");
  const emailElem = document.getElementById("loginEmail");
  const passwordElem = document.getElementById("loginPassword");

  const selectedRole = roleElem ? roleElem.value : "user";
  const email = emailElem ? emailElem.value.trim() : "";
  const password = passwordElem ? passwordElem.value : "";

  if (!email) {
    showMessage(loginMessage, "Please enter your registered email address.");
    emailElem?.focus();
    return;
  }

  if (!password) {
    showMessage(loginMessage, "Please enter your password.");
    passwordElem?.focus();
    return;
  }

  setBtnLoading(loginBtn, loginBtnText, loginSpinner, true, "Login");

  try {
    // 1. Sign in with Firebase Auth
    const userCredential = await auth.signInWithEmailAndPassword(email, password);
    const user = userCredential.user;

    // 2. Fetch User Profile from Firestore
    let profile = null;
    try {
      const profileDoc = await db.collection("profiles").doc(user.uid).get();
      if (profileDoc.exists) {
        profile = profileDoc.data();
      }
    } catch (err) {
      console.warn("Error fetching profile from Firestore:", err);
    }

    // 3. Self-healing fallback: If profile record is missing, auto-create profile doc
    if (!profile) {
      console.warn("Profile document missing. Auto-generating default profile...");
      const defaultUsername = user.displayName || email.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "");
      profile = {
        id: user.uid,
        username: defaultUsername || `user_${user.uid.slice(0, 6)}`,
        email: user.email,
        full_name: user.displayName || defaultUsername,
        role: "user",
        created_at: firebase.firestore.FieldValue.serverTimestamp(),
        updated_at: firebase.firestore.FieldValue.serverTimestamp()
      };
      try {
        await db.collection("profiles").doc(user.uid).set(profile, { merge: true });
      } catch (err) {
        console.warn("Failed to create profile document:", err);
      }
    }

    const databaseRole = String(profile.role || "user").trim().toLowerCase();

    // 4. Role validation
    if (selectedRole === "associate" && databaseRole !== "associate") {
      await auth.signOut();
      throw new Error("Access Denied: This account is registered as 'Standard User'. Please select 'User (Standard Analyst)' to log in.");
    }

    // Save profile locally for rapid UI display
    sessionStorage.setItem("netarmor_profile", JSON.stringify({
      id: user.uid,
      username: profile.username || user.displayName,
      role: databaseRole,
      full_name: profile.full_name || user.displayName || "",
      email: user.email || ""
    }));

    showMessage(loginMessage, "Authentication successful! Redirecting...", "success");

    setTimeout(() => {
      if (databaseRole === "associate") {
        window.location.replace("admin-dashboard.html");
      } else {
        window.location.replace("dashboard.html");
      }
    }, 450);

  } catch (error) {
    console.error("NetArmor Login Error:", error);
    showMessage(loginMessage, formatFirebaseError(error));
  } finally {
    setBtnLoading(loginBtn, loginBtnText, loginSpinner, false, "Login");
  }
});

/* =========================================================
   USERNAME VALIDATION & AVAILABILITY ENGINE
   ========================================================= */

const RESERVED_USERNAMES = new Set([
  "admin",
  "administrator",
  "root",
  "system",
  "netarmor",
  "armorbot",
  "associate",
  "support",
  "security",
  "moderator",
  "official",
  "help",
  "guest",
  "staff",
  "soc",
  "soc_lead",
  "user",
  "null",
  "undefined",
  "api"
]);

let usernameValidationState = {
  status: "idle",       // 'idle' | 'checking' | 'available' | 'taken' | 'invalid'
  checkedUsername: "",
  message: ""
};

let usernameCheckTimeout = null;

function validateUsernameRules(rawUsername) {
  const username = (rawUsername || "").trim();

  if (!username) {
    return {
      valid: false,
      reason: "Username is required.",
      code: "EMPTY"
    };
  }

  if (username.length < 3) {
    return {
      valid: false,
      reason: "Minimum 3 characters required.",
      code: "TOO_SHORT"
    };
  }

  if (username.length > 30) {
    return {
      valid: false,
      reason: "Maximum 30 characters allowed.",
      code: "TOO_LONG"
    };
  }

  if (!/^[a-zA-Z]/.test(username)) {
    return {
      valid: false,
      reason: "Must start with a letter (A–Z or a–z).",
      code: "START_CHAR"
    };
  }

  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return {
      valid: false,
      reason: "Only letters, numbers, and underscores allowed.",
      code: "INVALID_CHARS"
    };
  }

  if (/__/.test(username)) {
    return {
      valid: false,
      reason: "Cannot contain consecutive underscores.",
      code: "CONSECUTIVE_UNDERSCORES"
    };
  }

  if (username.endsWith("_")) {
    return {
      valid: false,
      reason: "Cannot end with an underscore.",
      code: "TRAILING_UNDERSCORE"
    };
  }

  if (RESERVED_USERNAMES.has(username.toLowerCase())) {
    return {
      valid: false,
      reason: "This username is reserved by NetArmor system.",
      code: "RESERVED"
    };
  }

  return { valid: true, reason: "" };
}

function updateUsernameUI(status, message, iconClass = "") {
  const container = document.getElementById("regUsernameContainer");
  const statusIcon = document.getElementById("regUsernameStatusIcon");
  const feedback = document.getElementById("regUsernameFeedback");
  const feedbackIcon = document.getElementById("regUsernameFeedbackIcon");
  const feedbackText = document.getElementById("regUsernameFeedbackText");

  if (!feedback || !feedbackText) return;

  // Reset classes
  if (container) {
    container.classList.remove("input-valid", "input-invalid", "input-checking");
  }
  feedback.className = "username-feedback";
  if (statusIcon) {
    statusIcon.className = "username-status-icon hidden";
    statusIcon.innerHTML = "";
  }

  if (status === "idle") {
    if (feedbackIcon) feedbackIcon.innerHTML = '<i class="fa-solid fa-circle-info"></i>';
    feedbackText.textContent = message || "3–30 chars: start with letter (a–z, 0–9, _)";
    return;
  }

  if (status === "checking") {
    if (container) container.classList.add("input-checking");
    feedback.classList.add("checking");
    if (feedbackIcon) feedbackIcon.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
    feedbackText.textContent = message || "Checking availability...";
    if (statusIcon) {
      statusIcon.className = "username-status-icon status-checking";
      statusIcon.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
    }
    return;
  }

  if (status === "available") {
    if (container) container.classList.add("input-valid");
    feedback.classList.add("available");
    if (feedbackIcon) feedbackIcon.innerHTML = '<i class="fa-solid fa-circle-check"></i>';
    feedbackText.textContent = message || "Username is available!";
    if (statusIcon) {
      statusIcon.className = "username-status-icon status-available";
      statusIcon.innerHTML = '<i class="fa-solid fa-circle-check"></i>';
    }
    return;
  }

  if (status === "taken") {
    if (container) container.classList.add("input-invalid");
    feedback.classList.add("taken");
    if (feedbackIcon) feedbackIcon.innerHTML = '<i class="fa-solid fa-circle-xmark"></i>';
    feedbackText.textContent = message || "Username is already taken.";
    if (statusIcon) {
      statusIcon.className = "username-status-icon status-taken";
      statusIcon.innerHTML = '<i class="fa-solid fa-circle-xmark"></i>';
    }
    return;
  }

  if (status === "invalid") {
    if (container) container.classList.add("input-invalid");
    feedback.classList.add("invalid");
    if (feedbackIcon) feedbackIcon.innerHTML = `<i class="fa-solid ${iconClass || 'fa-triangle-exclamation'}"></i>`;
    feedbackText.textContent = message;
    if (statusIcon) {
      statusIcon.className = "username-status-icon status-invalid";
      statusIcon.innerHTML = `<i class="fa-solid ${iconClass || 'fa-triangle-exclamation'}"></i>`;
    }
  }
}

async function checkUsernameAvailability(rawUsername) {
  const username = (rawUsername || "").trim();

  // 1. Format & rule validation
  const ruleCheck = validateUsernameRules(username);
  if (!ruleCheck.valid) {
    if (!username) {
      usernameValidationState = { status: "idle", checkedUsername: "", message: "" };
      updateUsernameUI("idle");
    } else {
      usernameValidationState = { status: "invalid", checkedUsername: username, message: ruleCheck.reason };
      updateUsernameUI("invalid", ruleCheck.reason, "fa-circle-xmark");
    }
    return false;
  }

  // 2. Set checking UI state
  usernameValidationState = { status: "checking", checkedUsername: username, message: "Checking availability..." };
  updateUsernameUI("checking", "Checking availability in database...");

  const db = getDb();
  if (!db) {
    usernameValidationState = { status: "available", checkedUsername: username, message: "Username format valid." };
    updateUsernameUI("available", "Username format valid.");
    return true;
  }

  const usernameLower = username.toLowerCase();

  try {
    let isTaken = false;

    // 2a. Check dedicated usernames registry
    try {
      const usernameDoc = await db.collection("usernames").doc(usernameLower).get();
      if (usernameDoc.exists) {
        isTaken = true;
      }
    } catch (_) {}

    // 2b. Also query profiles collection (handles existing profiles and case match)
    if (!isTaken) {
      try {
        const snap = await db.collection("profiles")
          .where("username", "==", username)
          .limit(1)
          .get();
        if (!snap.empty) {
          isTaken = true;
        }
      } catch (_) {}
    }

    // Check if user continued typing while async query was running
    const currentInput = document.getElementById("regUsername")?.value.trim() || "";
    if (currentInput !== username) {
      return false; // Result is stale
    }

    if (isTaken) {
      usernameValidationState = { status: "taken", checkedUsername: username, message: "Username already taken." };
      updateUsernameUI("taken", "Username is already taken. Try another.");
      return false;
    } else {
      usernameValidationState = { status: "available", checkedUsername: username, message: "Username is available!" };
      updateUsernameUI("available", "Username is available!");
      return true;
    }
  } catch (err) {
    console.warn("Username availability lookup notice:", err);
    usernameValidationState = { status: "available", checkedUsername: username, message: "Username format verified." };
    updateUsernameUI("available", "Username format verified.");
    return true;
  }
}

// Bind Live Username Input Listeners
const regUsernameElem = document.getElementById("regUsername");
if (regUsernameElem) {
  regUsernameElem.addEventListener("input", () => {
    clearTimeout(usernameCheckTimeout);
    const value = regUsernameElem.value.trim();
    if (!value) {
      usernameValidationState = { status: "idle", checkedUsername: "", message: "" };
      updateUsernameUI("idle");
      return;
    }

    // Immediate rule validation
    const ruleCheck = validateUsernameRules(value);
    if (!ruleCheck.valid) {
      usernameValidationState = { status: "invalid", checkedUsername: value, message: ruleCheck.reason };
      updateUsernameUI("invalid", ruleCheck.reason, "fa-circle-xmark");
      return;
    }

    // Show checking spinner and debounce database call
    updateUsernameUI("checking", "Checking availability...");
    usernameCheckTimeout = setTimeout(() => {
      checkUsernameAvailability(value);
    }, 380);
  });

  regUsernameElem.addEventListener("blur", () => {
    clearTimeout(usernameCheckTimeout);
    const value = regUsernameElem.value.trim();
    if (value && (usernameValidationState.checkedUsername !== value || usernameValidationState.status === "checking")) {
      checkUsernameAvailability(value);
    }
  });
}

/* =========================================================
   REGISTRATION FLOW
   ========================================================= */

registerForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessages();

  if (!checkFirebaseInit(registerMessage)) return;

  const auth = getAuth();
  const db = getDb();

  const fullNameElem = document.getElementById("regFullName");
  const usernameElem = document.getElementById("regUsername");
  const emailElem = document.getElementById("regEmail");
  const phoneElem = document.getElementById("regPhone");
  const orgElem = document.getElementById("regOrganization");
  const passwordElem = document.getElementById("regPassword");
  const confirmPasswordElem = document.getElementById("regConfirmPassword");

  const fullName = fullNameElem ? fullNameElem.value.trim() : "";
  const username = usernameElem ? usernameElem.value.trim() : "";
  const email = emailElem ? emailElem.value.trim() : "";
  const phone = phoneElem ? phoneElem.value.trim() : "";
  const organization = orgElem ? orgElem.value.trim() : "";
  const password = passwordElem ? passwordElem.value : "";
  const confirmPassword = confirmPasswordElem ? confirmPasswordElem.value : "";

  if (!fullName || fullName.length < 2) {
    showMessage(registerMessage, "Please enter your full legal or analyst name.");
    fullNameElem?.focus();
    return;
  }

  // Validate username rules
  const ruleCheck = validateUsernameRules(username);
  if (!ruleCheck.valid) {
    showMessage(registerMessage, `Invalid Username: ${ruleCheck.reason}`);
    usernameElem?.focus();
    updateUsernameUI("invalid", ruleCheck.reason, "fa-circle-xmark");
    return;
  }

  // Ensure availability verified
  if (usernameValidationState.status !== "available" || usernameValidationState.checkedUsername !== username) {
    setBtnLoading(registerBtn, registerBtnText, registerSpinner, true, "Checking username...");
    const isAvail = await checkUsernameAvailability(username);
    setBtnLoading(registerBtn, registerBtnText, registerSpinner, false, "Create Account");
    if (!isAvail) {
      showMessage(registerMessage, "This username is already taken or unavailable. Please choose another.");
      usernameElem?.focus();
      return;
    }
  }

  if (!email || !email.includes("@")) {
    showMessage(registerMessage, "Please enter a valid email address.");
    emailElem?.focus();
    return;
  }

  if (!password || password.length < 8) {
    showMessage(registerMessage, "Password must be at least 8 characters long.");
    passwordElem?.focus();
    return;
  }

  if (password !== confirmPassword) {
    showMessage(registerMessage, "Passwords do not match. Please verify your password confirmation.");
    confirmPasswordElem?.focus();
    return;
  }

  setBtnLoading(registerBtn, registerBtnText, registerSpinner, true, "Create Account");

  try {
    // 1. Create User in Firebase Auth
    const userCredential = await auth.createUserWithEmailAndPassword(email, password);
    const user = userCredential.user;

    // 2. Set Firebase Auth Display Name
    try {
      await user.updateProfile({ displayName: fullName || username });
    } catch (_) {}

    // 3. Atomically verify against registry collision
    const usernameLower = username.toLowerCase();
    try {
      const existingDoc = await db.collection("usernames").doc(usernameLower).get();
      if (existingDoc.exists && existingDoc.data()?.uid !== user.uid) {
        await user.delete();
        throw new Error("This username was just claimed by another user. Please choose a different username.");
      }
    } catch (claimErr) {
      if (claimErr.message?.includes("just claimed")) throw claimErr;
    }

    // 4. Create Profile document in Cloud Firestore
    const newProfile = {
      id: user.uid,
      uid: user.uid,
      full_name: fullName,
      username: username,
      email: email,
      phone: phone || "",
      organization: organization || "",
      role: "user",
      created_at: firebase.firestore.FieldValue.serverTimestamp(),
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    };

    try {
      await db.collection("profiles").doc(user.uid).set(newProfile);
    } catch (dbErr) {
      console.warn("Profile document insertion error:", dbErr);
    }

    // 5. Enroll in usernames registry
    try {
      await db.collection("usernames").doc(usernameLower).set({
        uid: user.uid,
        username: username,
        created_at: firebase.firestore.FieldValue.serverTimestamp()
      });
    } catch (unErr) {
      console.warn("Usernames registry enrollment warning:", unErr);
    }

    sessionStorage.setItem("netarmor_profile", JSON.stringify({
      id: user.uid,
      uid: user.uid,
      username: username,
      full_name: fullName,
      role: "user",
      email: email,
      phone: phone || "",
      organization: organization || ""
    }));

    showMessage(registerMessage, "Account created successfully! Entering security console...", "success");
    setTimeout(() => {
      window.location.replace("dashboard.html");
    }, 700);

  } catch (error) {
    console.error("NetArmor Registration Error:", error);
    showMessage(registerMessage, formatFirebaseError(error));
  } finally {
    setBtnLoading(registerBtn, registerBtnText, registerSpinner, false, "Create Account");
  }
});

/* =========================================================
   PASSWORD RESET FLOW
   ========================================================= */

resetForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessages();

  if (!checkFirebaseInit(resetMessage)) return;

  const auth = getAuth();
  const emailElem = document.getElementById("resetEmail");
  const email = emailElem ? emailElem.value.trim() : "";

  if (!email) {
    showMessage(resetMessage, "Please enter your registered email address.");
    emailElem?.focus();
    return;
  }

  setBtnLoading(resetBtn, resetBtnText, resetSpinner, true, "Send Reset Link");

  try {
    await auth.sendPasswordResetEmail(email);

    showMessage(
      resetMessage,
      "Password reset email sent! Check your inbox for the recovery link.",
      "success"
    );

  } catch (error) {
    console.error("NetArmor Password Reset Error:", error);
    showMessage(resetMessage, formatFirebaseError(error));
  } finally {
    setBtnLoading(resetBtn, resetBtnText, resetSpinner, false, "Send Reset Link");
  }
});

/* =========================================================
   PASSWORD VISIBILITY TOGGLES
   ========================================================= */

function setupPasswordToggle(inputId, buttonId) {
  const input = document.getElementById(inputId);
  const button = document.getElementById(buttonId);
  if (!input || !button) return;

  button.addEventListener("click", () => {
    if (input.type === "password") {
      input.type = "text";
      button.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
      button.setAttribute("aria-label", "Hide password");
    } else {
      input.type = "password";
      button.innerHTML = '<i class="fa-solid fa-eye"></i>';
      button.setAttribute("aria-label", "Show password");
    }
  });
}

setupPasswordToggle("loginPassword", "loginPasswordToggle");
setupPasswordToggle("regPassword", "registerPasswordToggle");
setupPasswordToggle("regConfirmPassword", "registerConfirmPasswordToggle");

/* =========================================================
   INITIALIZATION
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {
  const hash = window.location.hash.toLowerCase();
  if (hash === "#register") {
    showRegister();
  } else if (hash === "#reset" || hash === "#forgot") {
    showReset();
  } else {
    showLogin();
  }

  checkActiveSession();
});
