const API_BASE = "http://127.0.0.1:8000";

function toggleAuthMode(target) {
  const loginCard = document.getElementById("loginCard");
  const regCard = document.getElementById("registerCard");

  if (target === "register") {
    loginCard.classList.add("hidden");
    regCard.classList.remove("hidden");
  } else {
    regCard.classList.add("hidden");
    loginCard.classList.remove("hidden");
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const role = document.getElementById("loginRole").value;
  const identifier = document.getElementById("loginIdentifier").value.trim();
  const password = document.getElementById("loginPassword").value;
  const loginBtn = document.getElementById("loginBtn");

  loginBtn.disabled = true;
  loginBtn.innerText = "Authenticating...";

  try {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role, identifier, password })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Invalid credentials.");
    }

    const data = await res.json();
    sessionStorage.setItem("netarmor_session", JSON.stringify(data));
    alert(`Access Granted as ${role.toUpperCase()}`);
    window.location.href = "detect.html";
  } catch (err) {
    alert(err.message || "Failed to reach backend.");
  } finally {
    loginBtn.disabled = false;
    loginBtn.innerText = "Login";
  }
}

async function handleRegistration(event) {
  event.preventDefault();
  const role = document.getElementById("registerRole").value; // Strictly 'user'
  const username = document.getElementById("regUsername").value.trim();
  const email = document.getElementById("regEmail").value.trim();
  const password = document.getElementById("regPassword").value;
  const regBtn = document.getElementById("registerBtn");

  regBtn.disabled = true;
  regBtn.innerText = "Creating Account...";

  try {
    const res = await fetch(`${API_BASE}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password, role })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Registration failed.");
    }

    alert("Account created successfully! You can now log in.");
    toggleAuthMode("login");
  } catch (err) {
    alert(err.message || "Registration error.");
  } finally {
    regBtn.disabled = false;
    regBtn.innerText = "Create Account";
  }
}

function handleForgotPassword(event) {
  event.preventDefault();
  const email = prompt("Enter your registered email address to receive password reset instructions:");
  if (email) {
    alert(`Reset instructions sent to ${email} if it exists in the system.`);
  }
}