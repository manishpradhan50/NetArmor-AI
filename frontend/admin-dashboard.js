/* =========================================================
   NetArmor AI - Security Operations Admin Console (admin-dashboard.js)
   SOC Incident Triage, Global Telemetry & Access Control
   ========================================================= */

const getAuth = () => window.netarmorAuth;
const getDb = () => window.netarmorDb;
const $ = (id) => document.getElementById(id);

// Application State
let currentAdminUser = null;
let currentAdminProfile = null;
let globalUsers = [];
let globalScans = [];
let globalComplaints = [];
let globalTickets = [];
let globalFeedback = [];
let adminNotifications = [];
const userMap = new Map();

/* =========================================================
   UTILITIES & FORMATTERS
   ========================================================= */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[c]);
}

function formatFirebaseError(err) {
  if (!err) return "An unexpected error occurred.";
  const code = err.code || "";
  switch (code) {
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found":
      return "Invalid email or password. Please verify credentials.";
    case "auth/email-already-in-use":
      return "An account with this email address already exists.";
    case "auth/weak-password":
      return "Password is too weak. Please use at least 8 characters.";
    case "auth/invalid-email":
      return "Please enter a valid email address.";
    case "auth/requires-recent-login":
      return "This sensitive action requires you to re-login before changing credentials.";
    default:
      return err.message ? err.message.replace(/^Firebase:\s*/, "") : "Operation failed.";
  }
}

function fmtDate(value) {
  if (!value) return "—";
  let date = typeof value?.toDate === "function" ? value.toDate() : new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function timeAgo(value) {
  if (!value) return "just now";
  let date = typeof value?.toDate === "function" ? value.toDate() : new Date(value);
  const diffSec = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  const diffDays = Math.floor(diffHrs / 24);
  return `${diffDays}d ago`;
}

function formatScanType(type) {
  switch (type) {
    case "url": return '<i class="fa-solid fa-globe"></i> URL';
    case "email": return '<i class="fa-solid fa-envelope"></i> Email';
    case "message": return '<i class="fa-solid fa-comment-sms"></i> SMS';
    case "document": return '<i class="fa-solid fa-file-lines"></i> PDF';
    default: return esc(type || "General");
  }
}

function getStatusBadge(status) {
  const s = String(status || "Open").toLowerCase();
  if (s === "open" || s.includes("open")) return `<span class="badge open"><i class="fa-solid fa-circle-dot"></i> Open</span>`;
  if (s.includes("submitted")) return `<span class="badge submitted"><i class="fa-solid fa-file-arrow-up"></i> Submitted</span>`;
  if (s.includes("review")) return `<span class="badge review"><i class="fa-solid fa-magnifying-glass"></i> Under Review</span>`;
  if (s.includes("progress")) return `<span class="badge progress"><i class="fa-solid fa-arrows-rotate fa-spin"></i> In Progress</span>`;
  if (s.includes("resolved") || s.includes("safe")) return `<span class="badge resolved"><i class="fa-solid fa-circle-check"></i> Resolved</span>`;
  if (s.includes("closed")) return `<span class="badge closed"><i class="fa-solid fa-lock"></i> Closed</span>`;
  return `<span class="badge open"><i class="fa-solid fa-circle-dot"></i> ${esc(status)}</span>`;
}

function getPriorityBadge(priority) {
  const p = String(priority || "Medium").toLowerCase();
  if (p === "critical") return `<span class="badge critical"><i class="fa-solid fa-bolt"></i> Critical</span>`;
  if (p === "high") return `<span class="badge high"><i class="fa-solid fa-circle-exclamation"></i> High</span>`;
  if (p === "medium") return `<span class="badge medium"><i class="fa-solid fa-triangle-exclamation"></i> Medium</span>`;
  return `<span class="badge low"><i class="fa-solid fa-circle-info"></i> Low</span>`;
}

/* =========================================================
   TOAST NOTIFICATION ENGINE
   ========================================================= */

function showToast(message, type = "success") {
  const container = $("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  const icon = type === "success" 
    ? '<i class="fa-solid fa-circle-check" style="color: var(--green);"></i>' 
    : type === "error" 
    ? '<i class="fa-solid fa-circle-xmark" style="color: var(--red);"></i>' 
    : '<i class="fa-solid fa-circle-info" style="color: var(--cyan);"></i>';
  toast.innerHTML = `<span style="font-size:1rem; display:inline-flex; align-items:center;">${icon}</span> <span>${esc(message)}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = "all 0.3s ease";
    toast.style.opacity = "0";
    toast.style.transform = "translateX(50px)";
    setTimeout(() => toast.remove(), 300);
  }, 3800);
}

/* =========================================================
   MODAL CONTROLLER
   ========================================================= */

window.openModal = function (id) {
  const m = $(id);
  if (m) {
    m.classList.add("open");
    document.body.style.overflow = "hidden";
  }
};

window.closeModal = function (id) {
  const m = $(id);
  if (m) {
    m.classList.remove("open");
    document.body.style.overflow = "";
  }
};

document.addEventListener("click", (e) => {
  if (e.target.classList.contains("modal-backdrop")) {
    e.target.classList.remove("open");
    document.body.style.overflow = "";
  }
});

/* =========================================================
   NAVIGATION & TAB ROUTING
   ========================================================= */

window.switchTab = function (tabName) {
  if (!tabName) return;

  if (window.location.hash !== `#${tabName}`) {
    history.replaceState(null, "", `#${tabName}`);
  }

  document.querySelectorAll(".nav-item").forEach((btn) => {
    if (btn.dataset.tab) {
      btn.classList.toggle("active", btn.dataset.tab === tabName);
    }
  });

  document.querySelectorAll(".tab-pane").forEach((pane) => {
    pane.classList.toggle("active", pane.id === `pane-${tabName}`);
  });

  const titles = {
    overview: "Command Center",
    complaints: "Complaints Triage Desk",
    tickets: "Support Desk",
    telemetry: "Global Threat Telemetry",
    users: "User Directory & Access",
    feedback: "Feedback & Sentiment",
    health: "System & ML Pipeline Health"
  };
  if ($("currentViewTitle")) {
    $("currentViewTitle").textContent = titles[tabName] || "Command Center";
  }

  closeMobileSidebar();
};

function closeMobileSidebar() {
  $("sidebar")?.classList.remove("mobile-open");
  $("sidebarBackdrop")?.classList.remove("active");
  document.body.style.overflow = "";
}

function openMobileSidebar() {
  $("sidebar")?.classList.add("mobile-open");
  $("sidebarBackdrop")?.classList.add("active");
  document.body.style.overflow = "hidden";
}

document.querySelectorAll(".nav-item[data-tab]").forEach((btn) => {
  btn.addEventListener("click", () => {
    switchTab(btn.dataset.tab);
  });
});

$("menuToggle")?.addEventListener("click", () => {
  const isOpen = $("sidebar")?.classList.contains("mobile-open");
  if (isOpen) {
    closeMobileSidebar();
  } else {
    openMobileSidebar();
  }
});
$("sidebarCloseBtn")?.addEventListener("click", closeMobileSidebar);
$("sidebarBackdrop")?.addEventListener("click", closeMobileSidebar);

/* =========================================================
   INITIALIZATION & ROLE VALIDATION
   ========================================================= */

async function initAdminDashboard() {
  const auth = getAuth();
  const db = getDb();

  if (!auth || !db) {
    alert("Firebase client not initialized. Check firebase-config.js.");
    return;
  }

  /* CHECK LOGIN */
  const user = await window.netarmorAuthReady();
  if (!user) {
    window.location.replace("login.html");
    return;
  }
  currentAdminUser = user;

  /* CHECK ASSOCIATE ROLE */
  let profile = null;
  try {
    const doc = await db.collection("profiles").doc(user.uid).get();
    if (doc.exists) {
      profile = doc.data();
    }
  } catch (err) {
    console.error("Error reading admin profile:", err);
  }

  if (String(profile?.role).toLowerCase() !== "associate") {
    // Standard users cannot access Admin Console
    window.location.replace("dashboard.html");
    return;
  }
  currentAdminProfile = profile;

  // Populate Admin Identity
  const displayName = profile.full_name || profile.username || user.email?.split("@")[0] || "Associate Lead";
  if ($("adminUserName")) $("adminUserName").textContent = displayName;
  if ($("adminAvatarText")) $("adminAvatarText").textContent = (displayName[0] || "A").toUpperCase();
  if ($("adminIdentityText")) $("adminIdentityText").textContent = `SOC Operator: ${user.email} • UID: ${user.uid.slice(0, 10)}...`;

  // Read initial tab from URL hash
  const initialHash = window.location.hash.replace("#", "").toLowerCase();
  if (initialHash && $(`pane-${initialHash}`)) {
    switchTab(initialHash);
  } else {
    switchTab("overview");
  }

  // Load all platform streams
  await loadAllAdminData();
}

async function loadAllAdminData() {
  await Promise.all([
    loadUsers(),
    loadGlobalScans(),
    loadAdminComplaints(),
    loadAdminTickets(),
    loadAdminFeedback(),
    loadAdminNotifications()
  ]);

  renderVectorBreakdown();
  renderUrgentComplaintsQueue();
}

/* =========================================================
   STREAM 1: USER MANAGEMENT
   ========================================================= */

async function loadUsers() {
  const db = getDb();
  if (!db) return;

  try {
    const snap = await db.collection("profiles").limit(200).get();
    globalUsers = [];
    userMap.clear();

    snap.forEach((doc) => {
      const data = { id: doc.id, ...doc.data() };
      globalUsers.push(data);
      userMap.set(doc.id, data.username || data.full_name || data.email?.split("@")[0] || "Analyst");
    });

    globalUsers.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    if ($("users")) $("users").textContent = globalUsers.length;
    if ($("sidebarUserCount")) $("sidebarUserCount").textContent = globalUsers.length;

    renderUsersTable(globalUsers);

  } catch (err) {
    console.error("Error fetching users:", err);
  }
}

function renderUsersTable(rows) {
  const tbody = $("userTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">No registered user profiles found.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((u) => {
    const isAssoc = String(u.role).toLowerCase() === "associate";
    return `
      <tr>
        <td>
          <strong>${esc(u.username || u.full_name || "—")}</strong>
          ${u.full_name ? `<br><small style="color: var(--muted);">${esc(u.full_name)}</small>` : ""}
        </td>
        <td style="color: #a7f3d0; font-family: monospace; font-size: 0.78rem;">
          ${esc(u.email || "—")}
        </td>
        <td>
          <span class="badge ${isAssoc ? "threat" : "safe"}">
            ${isAssoc ? '<i class="fa-solid fa-user-shield"></i> Associate Lead' : '<i class="fa-solid fa-user"></i> Standard Analyst'}
          </span>
        </td>
        <td style="color: var(--muted); font-size: 0.76rem;">
          ${fmtDate(u.created_at)}
        </td>
        <td>
          <div style="display: flex; gap: 6px;">
            <button class="btn btn-secondary btn-sm" onclick="editUserRole('${u.id}', '${esc(u.username || u.email)}', '${esc(u.email)}', '${u.role || "user"}')">
              <i class="fa-solid fa-user-gear"></i> Role
            </button>
            <button class="btn btn-primary btn-sm" onclick="openChangePasswordModal('${u.id}', '${esc(u.username || u.full_name || u.email)}', '${esc(u.email)}')">
              <i class="fa-solid fa-key"></i> Password
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

function filterUsers() {
  const query = ($("userSearchInput")?.value || "").toLowerCase().trim();
  const role = $("userRoleFilter")?.value || "all";

  const filtered = globalUsers.filter((u) => {
    const matchesQuery = !query ||
      String(u.username || "").toLowerCase().includes(query) ||
      String(u.email || "").toLowerCase().includes(query) ||
      String(u.full_name || "").toLowerCase().includes(query);
    const matchesRole = role === "all" || String(u.role || "user").toLowerCase() === role;
    return matchesQuery && matchesRole;
  });

  renderUsersTable(filtered);
}

$("userSearchInput")?.addEventListener("input", filterUsers);
$("userRoleFilter")?.addEventListener("change", filterUsers);
$("refreshUsersBtn")?.addEventListener("click", loadUsers);

/* EDIT USER ROLE MODAL */
window.editUserRole = function (userId, name, email, currentRole) {
  if ($("roleUserId")) $("roleUserId").value = userId;
  if ($("roleTargetName")) $("roleTargetName").textContent = name;
  if ($("roleTargetEmail")) $("roleTargetEmail").textContent = email;
  if ($("roleSelect")) $("roleSelect").value = currentRole === "associate" ? "associate" : "user";
  openModal("roleModal");
};

$("roleForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db) return;

  const targetUid = $("roleUserId")?.value;
  const newRole = $("roleSelect")?.value;
  if (!targetUid || !newRole) return;

  try {
    await db.collection("profiles").doc(targetUid).update({
      role: newRole,
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    showToast(`Access role updated to '${newRole}'!`, "success");
    closeModal("roleModal");
    await loadUsers();
  } catch (err) {
    console.error("Role update error:", err);
    showToast(err.message || "Failed to update role.", "error");
  }
});

/* =========================================================
   ADD NEW USER (FIREBASE AUTH & FIRESTORE DIRECTORY)
   ========================================================= */

$("openAddUserModalBtn")?.addEventListener("click", () => {
  const form = $("addUserForm");
  if (form) form.reset();
  const pwdInput = $("newPassword");
  if (pwdInput) pwdInput.type = "password";
  const icon = $("toggleNewPasswordBtn")?.querySelector("i");
  if (icon) icon.className = "fa-solid fa-eye";
  openModal("addUserModal");
});

$("toggleNewPasswordBtn")?.addEventListener("click", () => {
  const pwdInput = $("newPassword");
  const icon = $("toggleNewPasswordBtn")?.querySelector("i");
  if (!pwdInput) return;
  if (pwdInput.type === "password") {
    pwdInput.type = "text";
    if (icon) icon.className = "fa-solid fa-eye-slash";
  } else {
    pwdInput.type = "password";
    if (icon) icon.className = "fa-solid fa-eye";
  }
});

$("addUserForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db) {
    showToast("Firestore database not initialized.", "error");
    return;
  }
  if (!window.FIREBASE_CONFIG) {
    showToast("Firebase configuration missing.", "error");
    return;
  }

  const fullName = $("newFullName")?.value.trim() || "";
  const username = $("newUsername")?.value.trim() || "";
  const email = $("newEmail")?.value.trim().toLowerCase() || "";
  const password = $("newPassword")?.value || "";
  const role = $("newRoleSelect")?.value || "user";
  const submitBtn = $("submitAddUserBtn");

  if (!email || !password || !username) {
    showToast("Username, email, and password are required.", "error");
    return;
  }

  if (username.length < 3) {
    showToast("Username must be at least 3 characters.", "error");
    return;
  }

  if (password.length < 8) {
    showToast("Password must be at least 8 characters.", "error");
    return;
  }

  const origBtnText = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span>⏳ Provisioning...</span>`;
  }

  let tempApp = null;
  try {
    // Isolate creation in secondary app so the current admin session is completely preserved
    const tempAppName = `TempAddUserApp_${Date.now()}`;
    tempApp = firebase.initializeApp(window.FIREBASE_CONFIG, tempAppName);
    const tempAuth = tempApp.auth();

    const cred = await tempAuth.createUserWithEmailAndPassword(email, password);
    const newUid = cred.user.uid;

    if (fullName || username) {
      await cred.user.updateProfile({
        displayName: fullName || username
      });
    }

    // Sign out from the temporary app and delete it cleanly
    await tempAuth.signOut();
    await tempApp.delete();
    tempApp = null;

    // Enroll profile in Firestore using the primary admin connection
    await db.collection("profiles").doc(newUid).set({
      uid: newUid,
      email: email,
      username: username,
      full_name: fullName || username,
      role: role,
      created_at: firebase.firestore.FieldValue.serverTimestamp(),
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    try {
      await db.collection("usernames").doc(username.toLowerCase()).set({
        uid: newUid,
        username: username,
        created_at: firebase.firestore.FieldValue.serverTimestamp()
      });
    } catch (_) {}

    showToast(`User account '${email}' created successfully with role '${role}'!`, "success");
    closeModal("addUserModal");
    $("addUserForm")?.reset();
    await loadUsers();
  } catch (err) {
    console.error("Error creating user account:", err);
    showToast(formatFirebaseError(err), "error");
  } finally {
    if (tempApp) {
      try {
        await tempApp.delete();
      } catch (_) {}
    }
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = origBtnText;
    }
  }
});

/* =========================================================
   PASSWORD MANAGEMENT (SELF DIRECT & USER RECOVERY)
   ========================================================= */

window.openChangePasswordModal = function (userId, displayName, email) {
  if ($("pwdTargetUserId")) $("pwdTargetUserId").value = userId || "";
  if ($("pwdTargetUserEmail")) $("pwdTargetUserEmail").value = email || "";
  if ($("pwdTargetDisplayName")) $("pwdTargetDisplayName").textContent = displayName || email || "User";
  if ($("pwdTargetEmailDisplay")) $("pwdTargetEmailDisplay").textContent = email || "—";

  const isSelf = currentAdminUser && (userId === currentAdminUser.uid || email.toLowerCase() === (currentAdminUser.email || "").toLowerCase());

  if (isSelf) {
    if ($("pwdModalTitle")) $("pwdModalTitle").innerHTML = '<i class="fa-solid fa-key" style="color: var(--amber);"></i> Change Your Admin Password';
    if ($("adminSelfPasswordForm")) {
      $("adminSelfPasswordForm").style.display = "block";
      $("adminSelfPasswordForm").reset();
    }
    if ($("otherUserPasswordSection")) $("otherUserPasswordSection").style.display = "none";
  } else {
    if ($("pwdModalTitle")) $("pwdModalTitle").innerHTML = `<i class="fa-solid fa-key" style="color: var(--amber);"></i> Password Reset: ${esc(displayName || email)}`;
    if ($("adminSelfPasswordForm")) $("adminSelfPasswordForm").style.display = "none";
    if ($("otherUserPasswordSection")) $("otherUserPasswordSection").style.display = "block";
  }

  openModal("changePasswordModal");
};

$("adminChangeOwnPasswordBtn")?.addEventListener("click", () => {
  if (!currentAdminUser) return;
  const name = currentAdminProfile?.full_name || currentAdminProfile?.username || currentAdminUser.email;
  openChangePasswordModal(currentAdminUser.uid, name, currentAdminUser.email);
});

$("adminSelfPasswordForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const auth = getAuth();
  const user = auth?.currentUser || currentAdminUser;

  if (!user) {
    showToast("Session not found. Please log in again.", "error");
    return;
  }

  const newPwd = $("adminSelfNewPwd")?.value || "";
  const confirmPwd = $("adminSelfConfirmPwd")?.value || "";
  const saveBtn = $("saveSelfPwdBtn");

  if (newPwd.length < 8) {
    showToast("Password must be at least 8 characters long.", "error");
    return;
  }

  if (newPwd !== confirmPwd) {
    showToast("New passwords do not match.", "error");
    return;
  }

  const origText = saveBtn ? saveBtn.innerHTML : "";
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.innerHTML = `<span><i class="fa-solid fa-spinner fa-spin"></i> Updating Password...</span>`;
  }

  try {
    await user.updatePassword(newPwd);
    showToast("Password updated successfully! Please remember your new credentials.", "success");
    closeModal("changePasswordModal");
    $("adminSelfPasswordForm")?.reset();
  } catch (err) {
    console.error("Error updating admin password:", err);
    showToast(formatFirebaseError(err), "error");
  } finally {
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.innerHTML = origText;
    }
  }
});

// Admin modal password eye toggles
document.querySelectorAll(".password-eye-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetId = btn.dataset.target || btn.getAttribute("data-target");
    const input = targetId ? $(targetId) : null;
    if (!input) return;
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    const icon = btn.querySelector("i");
    if (icon) {
      icon.className = isPassword ? "fa-solid fa-eye-slash" : "fa-solid fa-eye";
    }
  });
});

$("toggleNewPasswordBtn")?.addEventListener("click", () => {
  const input = $("newPassword");
  const btn = $("toggleNewPasswordBtn");
  if (!input || !btn) return;
  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  const icon = btn.querySelector("i");
  if (icon) {
    icon.className = isPassword ? "fa-solid fa-eye-slash" : "fa-solid fa-eye";
  }
});

$("sendUserResetLinkBtn")?.addEventListener("click", async () => {
  const auth = getAuth();
  if (!auth) {
    showToast("Firebase auth service unavailable.", "error");
    return;
  }

  const targetEmail = $("pwdTargetUserEmail")?.value.trim();
  if (!targetEmail) {
    showToast("No target email address specified for reset link.", "error");
    return;
  }

  const btn = $("sendUserResetLinkBtn");
  const origText = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span><i class="fa-solid fa-spinner fa-spin"></i> Sending Link...</span>`;
  }

  try {
    await auth.sendPasswordResetEmail(targetEmail);
    showToast(`Password reset link successfully sent to ${targetEmail}!`, "success");
    closeModal("changePasswordModal");
  } catch (err) {
    console.error("Error sending password reset email:", err);
    showToast(formatFirebaseError(err), "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = origText;
    }
  }
});

/* =========================================================
   STREAM 2: GLOBAL THREAT TELEMETRY (ALL SCANS)
   ========================================================= */

async function loadGlobalScans() {
  const db = getDb();
  if (!db) return;

  try {
    const snap = await db.collection("scan_history").limit(200).get();
    globalScans = [];

    snap.forEach((doc) => {
      globalScans.push({ id: doc.id, ...doc.data() });
    });

    globalScans.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    const threats = globalScans.filter((s) => s.result === "Threat").length;
    const rate = globalScans.length ? `${Math.round((threats / globalScans.length) * 100)}%` : "0%";

    if ($("total")) $("total").textContent = globalScans.length;
    if ($("threats")) $("threats").textContent = threats;
    if ($("rate")) $("rate").textContent = rate;
    if ($("sidebarScanCount")) $("sidebarScanCount").textContent = globalScans.length;

    renderOverviewThreats(globalScans.slice(0, 6));
    renderGlobalThreatsTable(globalScans);

  } catch (err) {
    console.error("Error fetching global telemetry:", err);
  }
}

function renderOverviewThreats(rows) {
  const tbody = $("overviewThreatsTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No threat scans logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((s) => {
    const operator = userMap.get(s.user_id) || "Anonymous";
    const isThreat = s.result === "Threat";
    return `
      <tr>
        <td><strong style="color: #a7f3d0;">${esc(operator)}</strong></td>
        <td><strong>${formatScanType(s.scan_type)}</strong></td>
        <td title="${esc(s.target)}" style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${esc(String(s.target || "").slice(0, 45))}${String(s.target || "").length > 45 ? "…" : ""}
        </td>
        <td><span class="badge ${isThreat ? "threat" : "safe"}">${esc(s.result)}</span></td>
        <td><strong style="color: ${isThreat ? "var(--red)" : "var(--green)"};">${Number(s.risk_score ?? 0).toFixed(1)}%</strong></td>
        <td style="color: var(--muted); font-size: 0.74rem;">${timeAgo(s.created_at)}</td>
      </tr>
    `;
  }).join("");
}

function renderGlobalThreatsTable(rows) {
  const tbody = $("threatsTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No telemetry records match your filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((s) => {
    const operator = userMap.get(s.user_id) || "Anonymous";
    const isThreat = s.result === "Threat";
    return `
      <tr>
        <td><strong style="color: #a7f3d0;">${esc(operator)}</strong></td>
        <td><strong>${formatScanType(s.scan_type)}</strong></td>
        <td title="${esc(s.target)}" style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${esc(String(s.target || "").slice(0, 60))}${String(s.target || "").length > 60 ? "…" : ""}
        </td>
        <td><span class="badge ${isThreat ? "threat" : "safe"}">${esc(s.result)}</span></td>
        <td><strong style="color: ${isThreat ? "var(--red)" : "var(--green)"};">${Number(s.risk_score ?? 0).toFixed(1)}%</strong></td>
        <td style="color: var(--muted); font-size: 0.76rem;">${fmtDate(s.created_at)}</td>
      </tr>
    `;
  }).join("");
}

function filterGlobalScans() {
  const query = ($("adminScanSearch")?.value || "").toLowerCase().trim();
  const vector = $("adminScanVectorFilter")?.value || "all";
  const result = $("adminScanResultFilter")?.value || "all";

  const filtered = globalScans.filter((s) => {
    const operator = (userMap.get(s.user_id) || "").toLowerCase();
    const target = String(s.target || "").toLowerCase();
    const matchesQuery = !query || target.includes(query) || operator.includes(query);
    const matchesVector = vector === "all" || s.scan_type === vector;
    const matchesResult = result === "all" || s.result === result;
    return matchesQuery && matchesVector && matchesResult;
  });

  renderGlobalThreatsTable(filtered);
}

$("adminScanSearch")?.addEventListener("input", filterGlobalScans);
$("adminScanVectorFilter")?.addEventListener("change", filterGlobalScans);
$("adminScanResultFilter")?.addEventListener("change", filterGlobalScans);
$("refreshAdminScansBtn")?.addEventListener("click", loadGlobalScans);

function renderVectorBreakdown() {
  const counts = { url: 0, email: 0, message: 0, document: 0 };
  globalScans.forEach((s) => {
    if (counts[s.scan_type] !== undefined) counts[s.scan_type]++;
  });

  const total = Math.max(1, globalScans.length);
  if ($("breakdownUrl")) $("breakdownUrl").textContent = counts.url;
  if ($("barUrl")) $("barUrl").style.width = `${Math.round((counts.url / total) * 100)}%`;

  if ($("breakdownEmail")) $("breakdownEmail").textContent = counts.email;
  if ($("barEmail")) $("barEmail").style.width = `${Math.round((counts.email / total) * 100)}%`;

  if ($("breakdownSms")) $("breakdownSms").textContent = counts.message;
  if ($("barSms")) $("barSms").style.width = `${Math.round((counts.message / total) * 100)}%`;

  if ($("breakdownPdf")) $("breakdownPdf").textContent = counts.document;
  if ($("barPdf")) $("barPdf").style.width = `${Math.round((counts.document / total) * 100)}%`;
}

/* =========================================================
   STREAM 3: CYBER COMPLAINTS TRIAGE DESK
   ========================================================= */

async function loadAdminComplaints() {
  const db = getDb();
  if (!db) return;

  try {
    const snap = await db.collection("cyber_complaints").limit(200).get();
    globalComplaints = [];

    snap.forEach((doc) => {
      globalComplaints.push({ id: doc.id, ...doc.data() });
    });

    globalComplaints.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    const activeCount = globalComplaints.filter((c) => c.status !== "Closed" && c.status !== "Resolved").length;
    if ($("kpiComplaints")) $("kpiComplaints").textContent = globalComplaints.length;
    if ($("sidebarComplaintCount")) $("sidebarComplaintCount").textContent = activeCount;

    renderAdminComplaintsTable(globalComplaints);

  } catch (err) {
    console.error("Error loading complaints:", err);
  }
}

function renderAdminComplaintsTable(rows) {
  const tbody = $("adminComplaintsTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">No cyber complaints filed across the platform.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((c) => {
    const userLabel = userMap.get(c.user_id) || c.user_email || "Anonymous";
    return `
      <tr>
        <td><strong style="color: var(--cyan);">${esc(c.complaint_id)}</strong></td>
        <td>
          <strong>${esc(userLabel)}</strong>
          ${c.user_email ? `<br><small style="color: var(--muted); font-size: 0.72rem;">${esc(c.user_email)}</small>` : ""}
        </td>
        <td><span style="font-size: 0.78rem;">${esc(c.complaint_type)}</span></td>
        <td title="${esc(c.title)}" style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          <strong>${esc(c.title)}</strong>
        </td>
        <td>${getPriorityBadge(c.priority)}</td>
        <td>${getStatusBadge(c.status)}</td>
        <td style="color: var(--muted); font-size: 0.76rem;">${fmtDate(c.created_at)}</td>
        <td>
          <button class="btn btn-primary btn-sm" onclick="openTriageModal('${c.id}')">
            Triage &amp; Update
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function renderUrgentComplaintsQueue() {
  const queue = $("urgentComplaintsQueue");
  if (!queue) return;

  const urgent = globalComplaints.filter((c) => c.status !== "Closed" && c.status !== "Resolved").slice(0, 4);
  if (urgent.length === 0) {
    queue.innerHTML = `<div class="empty" style="padding: 14px !important;">All cases currently triaged or resolved.</div>`;
    return;
  }

  queue.innerHTML = urgent.map((c) => `
    <div style="background: rgba(255,255,255,0.02); padding: 10px 12px; border-radius: 9px; border: 1px solid var(--line-subtle); display: flex; justify-content: space-between; align-items: center; cursor: pointer;" onclick="openTriageModal('${c.id}')">
      <div>
        <strong style="font-size: 0.82rem; color: #fff;">${esc(c.complaint_id)}</strong>
        <div style="font-size: 0.72rem; color: var(--muted);">${esc(c.title?.slice(0, 32))}...</div>
      </div>
      <div>${getPriorityBadge(c.priority)}</div>
    </div>
  `).join("");
}

function filterAdminComplaints() {
  const query = ($("adminComplaintSearch")?.value || "").toLowerCase().trim();
  const status = $("adminComplaintStatusFilter")?.value || "all";
  const priority = $("adminComplaintPriorityFilter")?.value || "all";

  const filtered = globalComplaints.filter((c) => {
    const matchesQuery = !query ||
      String(c.complaint_id || "").toLowerCase().includes(query) ||
      String(c.title || "").toLowerCase().includes(query) ||
      String(c.user_email || "").toLowerCase().includes(query) ||
      String(c.reference_info || "").toLowerCase().includes(query);
    const matchesStatus = status === "all" || c.status === status;
    const matchesPriority = priority === "all" || c.priority === priority;
    return matchesQuery && matchesStatus && matchesPriority;
  });

  renderAdminComplaintsTable(filtered);
}

$("adminComplaintSearch")?.addEventListener("input", filterAdminComplaints);
$("adminComplaintStatusFilter")?.addEventListener("change", filterAdminComplaints);
$("adminComplaintPriorityFilter")?.addEventListener("change", filterAdminComplaints);
$("refreshAdminComplaintsBtn")?.addEventListener("click", loadAdminComplaints);

/* TRIAGE MODAL */
window.openTriageModal = function (docId) {
  const c = globalComplaints.find((item) => item.id === docId);
  if (!c) return;

  if ($("triageDocId")) $("triageDocId").value = docId;
  if ($("triageUserId")) $("triageUserId").value = c.user_id || "";
  if ($("triageCmpId")) $("triageCmpId").value = c.complaint_id || "";

  if ($("triageModalTitle")) $("triageModalTitle").innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color: var(--amber);"></i> Triage Incident: ${esc(c.complaint_id)}`;
  if ($("triageIncidentName")) $("triageIncidentName").textContent = c.title;
  if ($("triagePriorityBadge")) $("triagePriorityBadge").innerHTML = getPriorityBadge(c.priority);
  if ($("triageMetaInfo")) {
    $("triageMetaInfo").textContent = `Category: ${c.complaint_type} • User: ${c.user_email || "Anonymous"} • Filed: ${fmtDate(c.created_at)}`;
  }
  if ($("triageDescriptionText")) {
    $("triageDescriptionText").textContent = c.description || "No description narrative provided.";
  }

  const linkArea = $("triageEvidenceLinkArea");
  if (linkArea) {
    linkArea.innerHTML = c.evidence_url
      ? `<a href="${esc(c.evidence_url)}" target="_blank" class="uploaded-file-pill" style="text-decoration:none;"><i class="fa-solid fa-paperclip"></i> Attached Evidence: ${esc(c.evidence_filename || "View File")} →</a>`
      : `<span style="font-size: 0.74rem; color: var(--muted);">No attached evidence file. Ref: ${esc(c.reference_info || "None")}</span>`;
  }

  if ($("triageStatusSelect")) $("triageStatusSelect").value = c.status || "Submitted";
  if ($("triageAssociateName")) {
    $("triageAssociateName").value = currentAdminProfile?.full_name || currentAdminProfile?.username || "Associate Lead";
  }
  if ($("triageResolutionNote")) $("triageResolutionNote").value = c.resolution_note || "";

  openModal("triageModal");
};

$("triageForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db) return;

  const btn = $("saveTriageBtn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-arrows-rotate fa-spin"></i> Updating...`;
  }

  try {
    const docId = $("triageDocId")?.value;
    const targetUserId = $("triageUserId")?.value;
    const cmpId = $("triageCmpId")?.value;
    const newStatus = $("triageStatusSelect")?.value;
    const note = $("triageResolutionNote")?.value.trim();

    await db.collection("cyber_complaints").doc(docId).update({
      status: newStatus,
      resolution_note: note,
      triaged_by: currentAdminProfile?.full_name || currentAdminProfile?.username || "Associate Lead",
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    // Notify user of case status update
    if (targetUserId) {
      await db.collection("user_notifications").add({
        user_id: targetUserId,
        title: `Complaint ${cmpId} Updated: ${newStatus}`,
        message: `SOC advisory: ${note || "Your complaint status has been updated by an associate."}`,
        type: "complaint",
        read: false,
        created_at: firebase.firestore.FieldValue.serverTimestamp()
      });
    }

    showToast(`Case ${cmpId} successfully updated to '${newStatus}'!`, "success");
    closeModal("triageModal");
    await loadAdminComplaints();
    renderUrgentComplaintsQueue();

  } catch (err) {
    console.error("Triage update error:", err);
    showToast(err.message || "Failed to update case.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Update Incident Status`;
    }
  }
});

/* =========================================================
   STREAM 4: SUPPORT TICKETS DESK
   ========================================================= */

async function loadAdminTickets() {
  const db = getDb();
  if (!db) return;

  try {
    const snap = await db.collection("support_tickets").limit(150).get();
    globalTickets = [];

    snap.forEach((doc) => {
      globalTickets.push({ id: doc.id, ...doc.data() });
    });

    globalTickets.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    const openCount = globalTickets.filter((t) => t.status === "Open" || t.status === "In Progress").length;
    if ($("kpiTickets")) $("kpiTickets").textContent = globalTickets.length;
    if ($("sidebarTicketCount")) $("sidebarTicketCount").textContent = openCount;

    renderAdminTicketsTable(globalTickets);

  } catch (err) {
    console.error("Error loading tickets:", err);
  }
}

function renderAdminTicketsTable(rows) {
  const tbody = $("adminTicketsTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">No support tickets found across the platform.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((t) => `
    <tr>
      <td><strong style="color: var(--cyan);">${esc(t.ticket_id)}</strong></td>
      <td style="color: #a7f3d0; font-family: monospace; font-size: 0.78rem;">${esc(t.user_email || "Anonymous")}</td>
      <td><span style="font-size: 0.78rem;">${esc(t.category)}</span></td>
      <td title="${esc(t.subject)}" style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        <strong>${esc(t.subject)}</strong>
      </td>
      <td>${getPriorityBadge(t.priority)}</td>
      <td>${getStatusBadge(t.status)}</td>
      <td style="color: var(--muted); font-size: 0.76rem;">${fmtDate(t.created_at)}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="openManageTicketModal('${t.id}')">
          <i class="fa-solid fa-headset"></i> Resolve
        </button>
      </td>
    </tr>
  `).join("");
}

function filterAdminTickets() {
  const query = ($("adminTicketSearch")?.value || "").toLowerCase().trim();
  const cat = $("adminTicketCategoryFilter")?.value || "all";
  const status = $("adminTicketStatusFilter")?.value || "all";

  const filtered = globalTickets.filter((t) => {
    const matchesQuery = !query ||
      String(t.ticket_id || "").toLowerCase().includes(query) ||
      String(t.subject || "").toLowerCase().includes(query) ||
      String(t.user_email || "").toLowerCase().includes(query);
    const matchesCat = cat === "all" || t.category === cat;
    const matchesStatus = status === "all" || t.status === status;
    return matchesQuery && matchesCat && matchesStatus;
  });

  renderAdminTicketsTable(filtered);
}

$("adminTicketSearch")?.addEventListener("input", filterAdminTickets);
$("adminTicketCategoryFilter")?.addEventListener("change", filterAdminTickets);
$("adminTicketStatusFilter")?.addEventListener("change", filterAdminTickets);
$("refreshAdminTicketsBtn")?.addEventListener("click", loadAdminTickets);

/* MANAGE TICKET MODAL */
window.openManageTicketModal = function (docId) {
  const t = globalTickets.find((item) => item.id === docId);
  if (!t) return;

  if ($("manageTicketDocId")) $("manageTicketDocId").value = docId;
  if ($("manageTicketUserId")) $("manageTicketUserId").value = t.user_id || "";
  if ($("manageTicketIdVal")) $("manageTicketIdVal").value = t.ticket_id || "";

  if ($("manageTicketTitle")) $("manageTicketTitle").innerHTML = `<i class="fa-solid fa-headset" style="color: var(--cyan);"></i> Manage Ticket: ${esc(t.ticket_id || "Ticket")}`;
  if ($("manageTicketSubjectText")) $("manageTicketSubjectText").textContent = t.subject || "No Subject";
  if ($("manageTicketPriorityBadge")) $("manageTicketPriorityBadge").innerHTML = getPriorityBadge(t.priority);
  if ($("manageTicketStatusBadge")) $("manageTicketStatusBadge").innerHTML = getStatusBadge(t.status);

  if ($("manageTicketIdDisplay")) $("manageTicketIdDisplay").textContent = t.ticket_id || "—";
  if ($("manageTicketUserEmailDisplay")) $("manageTicketUserEmailDisplay").textContent = t.user_email || "Anonymous";
  if ($("manageTicketCategoryDisplay")) $("manageTicketCategoryDisplay").textContent = t.category || "General";
  if ($("manageTicketCreatedDisplay")) $("manageTicketCreatedDisplay").textContent = fmtDate(t.created_at);
  if ($("manageTicketUpdatedDisplay")) $("manageTicketUpdatedDisplay").textContent = fmtDate(t.updated_at || t.created_at);

  if ($("manageTicketMessageText")) $("manageTicketMessageText").textContent = t.message || t.description || "No inquiry description provided.";
  if ($("manageTicketStatusSelect")) $("manageTicketStatusSelect").value = t.status || "Open";
  if ($("manageTicketStaffNote")) $("manageTicketStaffNote").value = "";

  // Render Full Conversation Thread
  const thread = $("manageTicketConversationThread");
  if (thread) {
    const replies = Array.isArray(t.replies) ? t.replies : [];
    if (replies.length === 0 && !t.resolution_note) {
      thread.innerHTML = `<div class="empty" style="padding: 12px !important;">No message exchanges recorded yet.</div>`;
    } else {
      let threadHtml = "";
      if (t.resolution_note && !replies.some((r) => r.message === t.resolution_note)) {
        threadHtml += `
          <div class="conversation-bubble admin">
            <div class="bubble-header">
              <span class="bubble-sender"><i class="fa-solid fa-user-shield"></i> SOC Support Lead</span>
              <span class="bubble-time">${fmtDate(t.updated_at || t.created_at)}</span>
            </div>
            <div class="bubble-text">${esc(t.resolution_note)}</div>
          </div>
        `;
      }

      threadHtml += replies.map((r) => {
        const isAdmin = r.sender === "admin" || r.sender === "staff";
        const senderLabel = isAdmin ? (r.sender_name || "SOC Support Team") : (r.sender_name || t.user_email || "Analyst");
        const senderIcon = isAdmin ? '<i class="fa-solid fa-user-shield"></i> ' : '<i class="fa-solid fa-user"></i> ';
        const timeVal = r.created_at || r.timestamp;
        const timeStr = timeVal ? fmtDate(timeVal) : "Recent";
        return `
          <div class="conversation-bubble ${isAdmin ? "admin" : "user"}">
            <div class="bubble-header">
              <span class="bubble-sender">${senderIcon}${esc(senderLabel)}</span>
              <span class="bubble-time">${timeStr}</span>
            </div>
            <div class="bubble-text">${esc(r.message || "")}</div>
          </div>
        `;
      }).join("");

      thread.innerHTML = threadHtml;
      thread.scrollTop = thread.scrollHeight;
    }
  }

  openModal("manageTicketModal");
};

$("manageTicketForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db) return;

  const btn = $("saveTicketBtn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-arrows-rotate fa-spin"></i> Updating...`;
  }

  try {
    const docId = $("manageTicketDocId")?.value;
    const targetUserId = $("manageTicketUserId")?.value;
    const tckId = $("manageTicketIdVal")?.value;
    const newStatus = $("manageTicketStatusSelect")?.value;
    const staffNote = $("manageTicketStaffNote")?.value.trim();

    const updatePayload = {
      status: newStatus,
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    };

    if (staffNote) {
      updatePayload.resolution_note = staffNote;
      const nowIso = new Date().toISOString();
      const replyObj = {
        sender: "admin",
        sender_name: currentAdminProfile?.full_name || currentAdminProfile?.username || "SOC Support Team",
        sender_email: currentAdminUser?.email || "support@netarmor-ai.com",
        message: staffNote,
        created_at: nowIso,
        timestamp: nowIso
      };
      updatePayload.replies = firebase.firestore.FieldValue.arrayUnion(replyObj);
    }

    await db.collection("support_tickets").doc(docId).update(updatePayload);

    if (targetUserId) {
      await db.collection("user_notifications").add({
        user_id: targetUserId,
        title: `Ticket ${tckId} Status: ${newStatus}`,
        message: staffNote || `Your support inquiry status was updated to ${newStatus}.`,
        type: "ticket",
        read: false,
        created_at: firebase.firestore.FieldValue.serverTimestamp()
      });
    }

    showToast(`Ticket ${tckId} updated successfully!`, "success");
    closeModal("manageTicketModal");
    await loadAdminTickets();

  } catch (err) {
    console.error("Ticket update error:", err);
    showToast(err.message || "Failed to update ticket.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Send Reply &amp; Update Status`;
    }
  }
});

/* =========================================================
   STREAM 5: FEEDBACK ANALYTICS
   ========================================================= */

async function loadAdminFeedback() {
  const db = getDb();
  if (!db) return;

  try {
    const snap = await db.collection("user_feedback").limit(100).get();
    globalFeedback = [];

    snap.forEach((doc) => {
      globalFeedback.push({ id: doc.id, ...doc.data() });
    });

    globalFeedback.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    // Compute Average Rating
    if (globalFeedback.length > 0) {
      const sum = globalFeedback.reduce((acc, f) => acc + (Number(f.rating) || 5), 0);
      const avg = (sum / globalFeedback.length).toFixed(1);
      if ($("avgRatingDisplay")) $("avgRatingDisplay").textContent = avg;
    }

    renderFeedbackList(globalFeedback);

  } catch (err) {
    console.error("Error loading feedback:", err);
  }
}

function renderFeedbackList(rows) {
  const list = $("feedbackList");
  if (!list) return;

  if (!rows || rows.length === 0) {
    list.innerHTML = `<div class="empty">No analyst feedback reviews submitted yet.</div>`;
    return;
  }

  list.innerHTML = rows.map((f) => {
    const starCount = Math.max(1, Math.min(5, Number(f.rating) || 5));
    const stars = Array(starCount).fill('<i class="fa-solid fa-star"></i>').join("");
    return `
      <div style="background: rgba(255,255,255,0.02); padding: 14px; border-radius: 12px; border: 1px solid var(--line-subtle);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
          <div>
            <span style="color: #facc15; font-size: 1rem;">${stars}</span>
            <span style="font-size: 0.75rem; color: var(--cyan); margin-left: 8px;">${esc(f.category || "General")}</span>
          </div>
          <small style="color: var(--muted); font-size: 0.72rem;">${timeAgo(f.created_at)}</small>
        </div>
        <div style="color: #dff5ec; font-size: 0.84rem; line-height: 1.5;">${esc(f.comments || "No comments")}</div>
        <div style="font-size: 0.72rem; color: var(--muted); margin-top: 6px;">Analyst: ${esc(f.user_email || "Anonymous")}</div>
      </div>
    `;
  }).join("");
}

$("refreshFeedbackBtn")?.addEventListener("click", loadAdminFeedback);

/* =========================================================
   STREAM 6: NOTIFICATIONS & SYSTEM HEALTH
   ========================================================= */

async function loadAdminNotifications() {
  const db = getDb();
  if (!db || !currentAdminUser) return;

  try {
    const snap = await db
      .collection("user_notifications")
      .where("user_id", "==", currentAdminUser.uid)
      .limit(20)
      .get();

    adminNotifications = [];
    snap.forEach((doc) => {
      adminNotifications.push({ id: doc.id, ...doc.data() });
    });

    adminNotifications.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    const unread = adminNotifications.filter((n) => !n.read).length;
    const pill = $("notifCountPill");
    if (pill) {
      if (unread > 0) {
        pill.textContent = unread > 9 ? "9+" : unread;
        pill.style.display = "flex";
      } else {
        pill.style.display = "none";
      }
    }

    renderAdminNotificationList();

  } catch (err) {
    console.warn("Admin notifications error:", err);
  }
}

function renderAdminNotificationList() {
  const list = $("notifList");
  if (!list) return;

  if (adminNotifications.length === 0) {
    list.innerHTML = `<div class="empty">No unread alerts in SOC desk.</div>`;
    return;
  }

  list.innerHTML = adminNotifications.map((n) => `
    <div class="notif-item ${n.read ? "" : "unread"}" onclick="markAdminNotifRead('${n.id}')">
      <div class="notif-item-top">
        <span>${esc(n.type?.toUpperCase() || "SOC")}</span>
        <span>${timeAgo(n.created_at)}</span>
      </div>
      <div class="notif-item-title">${esc(n.title)}</div>
      <div class="notif-item-body">${esc(n.message)}</div>
    </div>
  `).join("");
}

window.markAdminNotifRead = async function (id) {
  const db = getDb();
  if (!db) return;
  try {
    await db.collection("user_notifications").doc(id).update({ read: true });
    const target = adminNotifications.find((n) => n.id === id);
    if (target) target.read = true;
    loadAdminNotifications();
  } catch (_) {}
};

$("markAllNotifsReadBtn")?.addEventListener("click", async () => {
  const db = getDb();
  if (!db) return;
  const unread = adminNotifications.filter((n) => !n.read);
  await Promise.all(
    unread.map((n) => db.collection("user_notifications").doc(n.id).update({ read: true }))
  );
  loadAdminNotifications();
  showToast("All SOC alerts marked as read.", "info");
});

$("notifBellBtn")?.addEventListener("click", (e) => {
  e.stopPropagation();
  $("notifPopover")?.classList.toggle("open");
});

document.addEventListener("click", (e) => {
  const popover = $("notifPopover");
  if (popover && !popover.contains(e.target) && e.target !== $("notifBellBtn")) {
    popover.classList.remove("open");
  }
});

/* PING HEALTH */
$("pingHealthBtn")?.addEventListener("click", async () => {
  const btn = $("pingHealthBtn");
  if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Pinging...';

  try {
    const apiBase = typeof window.resolveNetArmorApi === "function" ? await window.resolveNetArmorApi() : "http://127.0.0.1:8000";
    const start = performance.now();
    const res = await fetch(`${apiBase}/api/health`);
    const duration = Math.round(performance.now() - start);

    if (res.ok) {
      const data = await res.json();
      if ($("backendStatusVal")) $("backendStatusVal").textContent = `ONLINE (${duration}ms)`;
      if ($("backendEndpointVal")) $("backendEndpointVal").textContent = `${apiBase} • v${data.version || "2.4"}`;
      showToast(`Backend latency verified: ${duration}ms!`, "success");
    } else {
      throw new Error(`HTTP ${res.status}`);
    }
  } catch (err) {
    if ($("backendStatusVal")) $("backendStatusVal").textContent = "OFFLINE";
    showToast("Backend connection timed out.", "error");
  } finally {
    if (btn) btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Ping Backend Health';
  }
});

/* =========================================================
   STREAM 7: CSV EXPORT UTILITIES
   ========================================================= */

function exportToCsv(filename, headers, rows) {
  const csvContent = [
    headers.join(","),
    ...rows.map((row) =>
      row.map((val) => `"${String(val ?? "").replace(/"/g, '""')}"`).join(",")
    )
  ].join("\r\n");

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Exported ${filename}`, "success");
}

$("exportTelemetryBtn")?.addEventListener("click", () => {
  if (globalScans.length === 0) return showToast("No telemetry data to export.", "error");
  const headers = ["Scan ID", "Operator UID", "Operator Username", "Vector", "Target Payload", "Verdict", "Risk Score", "Timestamp"];
  const rows = globalScans.map((s) => [
    s.id,
    s.user_id,
    userMap.get(s.user_id) || "Anonymous",
    s.scan_type,
    s.target,
    s.result,
    s.risk_score,
    fmtDate(s.created_at)
  ]);
  exportToCsv("netarmor_global_telemetry.csv", headers, rows);
});

$("exportComplaintsBtn")?.addEventListener("click", () => {
  if (globalComplaints.length === 0) return showToast("No complaints to export.", "error");
  const headers = ["Complaint ID", "User ID", "User Email", "Category", "Title", "Priority", "Status", "Reference Info", "Date Filed"];
  const rows = globalComplaints.map((c) => [
    c.complaint_id,
    c.user_id,
    c.user_email,
    c.complaint_type,
    c.title,
    c.priority,
    c.status,
    c.reference_info,
    fmtDate(c.created_at)
  ]);
  exportToCsv("netarmor_cyber_complaints.csv", headers, rows);
});

/* =========================================================
   LOGOUT & REFRESH HANDLERS
   ========================================================= */

async function handleAdminLogout() {
  const auth = getAuth();
  if (auth) {
    try {
      await auth.signOut();
    } catch (_) {}
  }
  sessionStorage.removeItem("netarmor_profile");
  window.location.replace("login.html");
}

$("logout")?.addEventListener("click", handleAdminLogout);
$("adminSidebarLogoutBtn")?.addEventListener("click", handleAdminLogout);

$("refreshAllBtn")?.addEventListener("click", () => {
  const btn = $("refreshAllBtn");
  if (btn) btn.innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Updating...';
  loadAllAdminData().finally(() => {
    if (btn) btn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Refresh Global Telemetry';
    showToast("Global SOC data updated.", "info");
  });
});

/* =========================================================
   DOM READY
   ========================================================= */

document.addEventListener("DOMContentLoaded", initAdminDashboard);