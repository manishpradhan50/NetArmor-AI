/* =========================================================
   NetArmor AI - Authentication System (login.js)
   Fully Integrated with Supabase Auth & Role-Based Access
   ========================================================= */

const sb = window.netarmorSupabase;

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

  // Pre-fill reset email with whatever was typed in login email
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

function getRoleDisplayName(role) {
  return role === "associate" ? "Associate (Security Engineer)" : "User (Standard Analyst)";
}

/* =========================================================
   CHECK ACTIVE SESSION (Auto-redirect if already logged in)
   ========================================================= */

async function checkActiveSession() {
  if (!sb) return;
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get("action") === "logout") {
    await sb.auth.signOut();
    sessionStorage.removeItem("netarmor_profile");
    return;
  }

  try {
    const { data: { session } } = await sb.auth.getSession();
    if (session && session.user) {
      // User is logged in, find profile
      const { data: profile } = await sb
        .from("profiles")
        .select("role")
        .eq("id", session.user.id)
        .maybeSingle();

      const userRole = (profile?.role || "user").toLowerCase();
      if (userRole === "associate") {
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

  if (!sb) {
    showMessage(loginMessage, "Supabase client not initialized. Check supabase-config.js.");
    return;
  }

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
    // 1. Sign in with Supabase Auth
    const { data: authData, error: authError } = await sb.auth.signInWithPassword({
      email,
      password
    });

    if (authError) throw new Error(authError.message);
    if (!authData?.user) throw new Error("Authentication succeeded but no user data was returned.");

    const user = authData.user;

    // 2. Fetch User Profile
    let { data: profile, error: profileError } = await sb
      .from("profiles")
      .select("id, username, full_name, role, email")
      .eq("id", user.id)
      .maybeSingle();

    // 3. Self-healing fallback: If profile record is missing, auto-create standard profile
    if (!profile) {
      console.warn("Profile missing for user. Self-healing default profile...");
      const defaultUsername = user.user_metadata?.username || email.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "");
      const { data: newProfile, error: createError } = await sb
        .from("profiles")
        .insert({
          id: user.id,
          username: defaultUsername || `user_${user.id.slice(0, 6)}`,
          email: user.email,
          full_name: user.user_metadata?.full_name || defaultUsername,
          role: "user"
        })
        .select()
        .single();

      if (!createError && newProfile) {
        profile = newProfile;
      } else {
        // If insertion blocked by RLS, proceed with in-memory profile
        profile = {
          id: user.id,
          username: defaultUsername,
          role: "user",
          email: user.email
        };
      }
    }

    const databaseRole = String(profile.role || "user").trim().toLowerCase();

    // 4. Role validation
    if (selectedRole === "associate" && databaseRole !== "associate") {
      await sb.auth.signOut();
      throw new Error("Access Denied: This account is registered as 'Standard User'. Please select 'User (Standard Analyst)' to log in.");
    }

    // Save profile locally for swift retrieval
    sessionStorage.setItem("netarmor_profile", JSON.stringify({
      id: profile.id,
      username: profile.username,
      role: databaseRole,
      full_name: profile.full_name || "",
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
    showMessage(loginMessage, error.message || "Login failed. Please verify your email and password.");
  } finally {
    setBtnLoading(loginBtn, loginBtnText, loginSpinner, false, "Login");
  }
});

/* =========================================================
   REGISTRATION FLOW
   ========================================================= */

registerForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMessages();

  if (!sb) {
    showMessage(registerMessage, "Supabase client not initialized.");
    return;
  }

  const usernameElem = document.getElementById("regUsername");
  const emailElem = document.getElementById("regEmail");
  const passwordElem = document.getElementById("regPassword");

  const username = usernameElem ? usernameElem.value.trim() : "";
  const email = emailElem ? emailElem.value.trim() : "";
  const password = passwordElem ? passwordElem.value : "";

  if (!username || username.length < 3) {
    showMessage(registerMessage, "Username must contain at least 3 characters.");
    usernameElem?.focus();
    return;
  }

  if (!email) {
    showMessage(registerMessage, "Please enter a valid email address.");
    emailElem?.focus();
    return;
  }

  if (!password || password.length < 8) {
    showMessage(registerMessage, "Password must be at least 8 characters long.");
    passwordElem?.focus();
    return;
  }

  setBtnLoading(registerBtn, registerBtnText, registerSpinner, true, "Create Account");

  try {
    const { data, error } = await sb.auth.signUp({
      email,
      password,
      options: {
        data: {
          username,
          full_name: username,
          role: "user"
        }
      }
    });

    if (error) throw new Error(error.message);

    // If session was returned immediately (email confirmation disabled in Supabase)
    if (data?.session && data?.user) {
      // Ensure profile exists
      try {
        await sb.from("profiles").upsert({
          id: data.user.id,
          username: username,
          email: email,
          role: "user"
        });
      } catch (_) {}

      sessionStorage.setItem("netarmor_profile", JSON.stringify({
        id: data.user.id,
        username: username,
        role: "user",
        email: email
      }));

      showMessage(registerMessage, "Account created successfully! Entering security console...", "success");
      setTimeout(() => {
        window.location.replace("dashboard.html");
      }, 700);

    } else {
      // Email confirmation enabled in Supabase
      showMessage(registerMessage, "Account created! A confirmation email has been sent. Please confirm your email, then log in.", "success");
      setTimeout(() => {
        showLogin();
        const loginEmail = document.getElementById("loginEmail");
        if (loginEmail) loginEmail.value = email;
      }, 2000);
    }

  } catch (error) {
    console.error("NetArmor Registration Error:", error);
    showMessage(registerMessage, error.message || "Registration failed. Please try again.");
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

  if (!sb) {
    showMessage(resetMessage, "Supabase client not initialized.");
    return;
  }

  const emailElem = document.getElementById("resetEmail");
  const email = emailElem ? emailElem.value.trim() : "";

  if (!email) {
    showMessage(resetMessage, "Please enter your registered email address.");
    emailElem?.focus();
    return;
  }

  setBtnLoading(resetBtn, resetBtnText, resetSpinner, true, "Send Reset Link");

  try {
    const redirectUrl = `${window.location.origin}${window.location.pathname.replace(/[^/]*$/, '')}update-password.html`;

    const { error } = await sb.auth.resetPasswordForEmail(email, {
      redirectTo: redirectUrl
    });

    if (error) throw new Error(error.message);

    showMessage(
      resetMessage,
      "Password reset email sent! Check your inbox for the recovery link.",
      "success"
    );

  } catch (error) {
    console.error("NetArmor Password Reset Error:", error);
    showMessage(resetMessage, error.message || "Failed to send reset link. Please check the email address.");
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
      button.textContent = "🙈";
      button.setAttribute("aria-label", "Hide password");
    } else {
      input.type = "password";
      button.textContent = "👁";
      button.setAttribute("aria-label", "Show password");
    }
  });
}

setupPasswordToggle("loginPassword", "loginPasswordToggle");
setupPasswordToggle("regPassword", "registerPasswordToggle");

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
