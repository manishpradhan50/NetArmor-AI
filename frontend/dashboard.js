/* =========================================================
   NetArmor AI - Modern Production Dashboard Engine (dashboard.js)
   Fully integrated with Google Firebase (Auth & Firestore)
   ========================================================= */

const getAuth = () => window.netarmorAuth;
const getDb = () => window.netarmorDb;
const $ = (id) => document.getElementById(id);

// Application State
let currentUser = null;
let currentProfile = null;
let scansCache = [];
let complaintsCache = [];
let ticketsCache = [];
let notificationsCache = [];
let uploadedEvidenceInfo = null;

/* =========================================================
   UTILITIES & FORMATTERS
   ========================================================= */

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[c]);
}

function fmtDate(value) {
  if (!value) return "—";
  let date;
  if (typeof value?.toDate === "function") {
    date = value.toDate();
  } else {
    date = new Date(value);
  }
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
  switch (String(type || "").toLowerCase()) {
    case "url": return '<i class="fa-solid fa-globe"></i> URL';
    case "email": return '<i class="fa-solid fa-envelope"></i> Email';
    case "message": return '<i class="fa-solid fa-comment-sms"></i> SMS';
    case "document": return '<i class="fa-solid fa-file-pdf"></i> PDF';
    default: return `<i class="fa-solid fa-shield-halved"></i> ${esc(type || "General")}`;
  }
}

function getStatusBadge(status) {
  const s = String(status || "Open").toLowerCase();
  if (s === "open") {
    return `<span class="badge open"><i class="fa-solid fa-circle-dot"></i> Open</span>`;
  }
  if (s.includes("submitted")) {
    return `<span class="badge submitted"><i class="fa-solid fa-file-arrow-up"></i> Submitted</span>`;
  }
  if (s.includes("review")) {
    return `<span class="badge review"><i class="fa-solid fa-magnifying-glass"></i> Under Review</span>`;
  }
  if (s.includes("progress")) {
    return `<span class="badge progress"><i class="fa-solid fa-arrows-rotate fa-spin"></i> In Progress</span>`;
  }
  if (s.includes("resolved") || s.includes("safe")) {
    return `<span class="badge resolved"><i class="fa-solid fa-circle-check"></i> Resolved</span>`;
  }
  if (s.includes("closed")) {
    return `<span class="badge closed"><i class="fa-solid fa-lock"></i> Closed</span>`;
  }
  return `<span class="badge open"><i class="fa-solid fa-circle-dot"></i> ${esc(status)}</span>`;
}

function getPriorityBadge(priority) {
  const p = String(priority || "Medium").toLowerCase();
  if (p === "critical") return `<span class="badge critical"><i class="fa-solid fa-bolt"></i> Critical</span>`;
  if (p === "urgent" || p === "high") return `<span class="badge high"><i class="fa-solid fa-circle-exclamation"></i> High</span>`;
  if (p === "low") return `<span class="badge low"><i class="fa-solid fa-arrow-down"></i> Low</span>`;
  return `<span class="badge medium"><i class="fa-solid fa-triangle-exclamation"></i> Medium</span>`;
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

// Close modal on click outside backdrop
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

  // Update URL hash
  if (window.location.hash !== `#${tabName}`) {
    history.replaceState(null, "", `#${tabName}`);
  }

  // Update sidebar active buttons
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });

  // Update Tab Content Panes
  document.querySelectorAll(".tab-pane").forEach((pane) => {
    pane.classList.toggle("active", pane.id === `pane-${tabName}`);
  });

  // Update Topbar View Title
  const titles = {
    overview: "Overview",
    threats: "Threat Diagnostics",
    complaints: "Cyber Complaints",
    fraud: "Report Fraud",
    tickets: "Support Tickets",
    security: "Security Center",
    help: "Help & FAQs",
    feedback: "User Feedback",
    settings: "Account Settings"
  };
  if ($("currentViewTitle")) {
    $("currentViewTitle").textContent = titles[tabName] || "Overview";
  }

  // Close mobile sidebar if open
  closeMobileSidebar();
};

function closeMobileSidebar() {
  const sidebar = $("sidebar");
  const backdrop = $("sidebarBackdrop");
  if (sidebar) sidebar.classList.remove("mobile-open");
  if (backdrop) backdrop.classList.remove("active");
  document.body.style.overflow = "";
}

function openMobileSidebar() {
  const sidebar = $("sidebar");
  const backdrop = $("sidebarBackdrop");
  if (sidebar) sidebar.classList.add("mobile-open");
  if (backdrop) backdrop.classList.add("active");
  document.body.style.overflow = "hidden";
}

// Bind navigation clicks
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.tab;
    if (target) {
      switchTab(target);
      closeMobileSidebar();
    }
  });
});

// Mobile menu toggle & backdrop events
$("menuToggle")?.addEventListener("click", () => {
  const sidebar = $("sidebar");
  if (sidebar && sidebar.classList.contains("mobile-open")) {
    closeMobileSidebar();
  } else {
    openMobileSidebar();
  }
});
$("sidebarCloseBtn")?.addEventListener("click", closeMobileSidebar);
$("sidebarBackdrop")?.addEventListener("click", closeMobileSidebar);

/* =========================================================
   FIREBASE USER AUTH & INITIALIZATION
   ========================================================= */

async function initDashboard() {
  const auth = getAuth();
  const db = getDb();

  if (!auth || !db) {
    console.error("Firebase not loaded yet.");
    return;
  }

  const user = await window.netarmorAuthReady();
  if (!user) {
    window.location.replace("login.html");
    return;
  }
  currentUser = user;

  // Retrieve or self-heal profile
  let profile = null;
  try {
    const snap = await db.collection("profiles").doc(user.uid).get();
    if (snap.exists) {
      profile = snap.data();
    }
  } catch (err) {
    console.warn("Profile retrieval error:", err);
  }

  if (!profile) {
    const defaultUsername = user.displayName || user.email?.split("@")[0] || `user_${user.uid.slice(0, 6)}`;
    profile = {
      id: user.uid,
      username: defaultUsername,
      email: user.email,
      full_name: user.displayName || defaultUsername,
      role: "user",
      created_at: firebase.firestore.FieldValue.serverTimestamp()
    };
    try {
      await db.collection("profiles").doc(user.uid).set(profile, { merge: true });
    } catch (_) {}
  }
  currentProfile = profile;

  // Associate role check -> redirect to Admin Console
  if (String(profile.role).toLowerCase() === "associate") {
    window.location.replace("admin-dashboard.html");
    return;
  }

  // Populate User Identity across UI
  const displayName = profile.full_name || profile.username || user.displayName || user.email?.split("@")[0] || "Analyst";
  if ($("name")) $("name").textContent = displayName;
  if ($("sidebarUserName")) $("sidebarUserName").textContent = displayName;
  if ($("userEmail")) $("userEmail").textContent = `Identity: ${user.email} • UID: ${user.uid.slice(0, 10)}...`;
  if ($("userAvatarText")) $("userAvatarText").textContent = (displayName[0] || "U").toUpperCase();

  // Populate Account Settings Form
  if ($("profileFullName")) $("profileFullName").value = profile.full_name || "";
  if ($("profileUsername")) $("profileUsername").value = profile.username || "";
  if ($("profileEmail")) $("profileEmail").value = user.email || "";
  if ($("profilePhone")) $("profilePhone").value = profile.phone || "";
  if ($("profileOrg")) $("profileOrg").value = profile.organization || "";
  if ($("settingsUid")) $("settingsUid").textContent = user.uid;

  // Read initial URL hash for tab routing
  const initialHash = window.location.hash.replace("#", "").toLowerCase();
  if (initialHash && $(`pane-${initialHash}`)) {
    switchTab(initialHash);
  } else {
    switchTab("overview");
  }

  // Load all data streams concurrently
  await Promise.all([
    loadScans(),
    loadComplaints(),
    loadTickets(),
    loadNotifications()
  ]);

  renderActivityStream();
  initPasswordSecurity();
}

/* =========================================================
   STREAM 1: SCAN TELEMETRY (THREAT DIAGNOSTICS)
   ========================================================= */

async function loadScans() {
  const db = getDb();
  if (!db || !currentUser) return;

  try {
    let snapshot;
    try {
      snapshot = await db
        .collection("scan_history")
        .where("user_id", "==", currentUser.uid)
        .orderBy("created_at", "desc")
        .limit(100)
        .get();
    } catch (_) {
      // Fallback in case composite index is still building in Firestore
      snapshot = await db
        .collection("scan_history")
        .where("user_id", "==", currentUser.uid)
        .limit(100)
        .get();
    }

    scansCache = [];
    snapshot.forEach((doc) => {
      scansCache.push({ id: doc.id, ...doc.data() });
    });

    // Sort descending by date
    scansCache.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    // Update KPI Statistics
    const threats = scansCache.filter((s) => s.result === "Threat").length;
    const safe = scansCache.length - threats;
    const rate = scansCache.length ? `${Math.round((threats / scansCache.length) * 100)}%` : "0%";

    if ($("total")) $("total").textContent = scansCache.length;
    if ($("threats")) $("threats").textContent = threats;
    if ($("safe")) $("safe").textContent = safe;
    if ($("rate")) $("rate").textContent = rate;
    if ($("sidebarScanCount")) $("sidebarScanCount").textContent = scansCache.length;

    // Security Posture Score
    updateSecurityPosture(scansCache.length, threats);

    // Render Overview Recent Scans Table (top 5)
    renderRecentScansTable(scansCache.slice(0, 5));

    // Render Full Telemetry Table
    renderFullScansTable(scansCache);

  } catch (err) {
    console.error("Error loading scan telemetry:", err);
  }
}

function renderRecentScansTable(rows) {
  const tbody = $("history");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="empty">
          No security scans recorded yet.<br>
          <a href="detect.html" style="color: var(--green); text-decoration: underline; margin-top: 6px; display: inline-block;">
            Run your first diagnostic scan →
          </a>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = rows.map((s) => `
    <tr>
      <td><strong>${formatScanType(s.scan_type)}</strong></td>
      <td title="${esc(s.target)}" style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        ${esc(String(s.target || "").slice(0, 48))}${String(s.target || "").length > 48 ? "…" : ""}
      </td>
      <td><span class="badge ${s.result === "Threat" ? "threat" : "safe"}">${esc(s.result)}</span></td>
      <td><strong style="color: ${s.result === "Threat" ? "var(--red)" : "var(--green)"};">${Number(s.risk_score ?? 0).toFixed(1)}%</strong></td>
      <td style="color: var(--muted); font-size: 0.76rem;">${timeAgo(s.created_at)}</td>
    </tr>
  `).join("");
}

function renderFullScansTable(rows) {
  const tbody = $("fullScansTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">No diagnostic scans match your query.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((s) => `
    <tr>
      <td><strong>${formatScanType(s.scan_type)}</strong></td>
      <td title="${esc(s.target)}" style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        ${esc(String(s.target || "").slice(0, 70))}${String(s.target || "").length > 70 ? "…" : ""}
      </td>
      <td><span class="badge ${s.result === "Threat" ? "threat" : "safe"}">${esc(s.result)}</span></td>
      <td><strong style="color: ${s.result === "Threat" ? "var(--red)" : "var(--green)"};">${Number(s.risk_score ?? 0).toFixed(1)}%</strong></td>
      <td style="color: var(--muted); font-size: 0.78rem;">${fmtDate(s.created_at)}</td>
    </tr>
  `).join("");
}

function filterFullScans() {
  const query = ($("scanSearchInput")?.value || "").toLowerCase().trim();
  const vector = $("scanVectorFilter")?.value || "all";
  const result = $("scanResultFilter")?.value || "all";

  const filtered = scansCache.filter((s) => {
    const matchesQuery = !query || String(s.target || "").toLowerCase().includes(query);
    const matchesVector = vector === "all" || s.scan_type === vector;
    const matchesResult = result === "all" || s.result === result;
    return matchesQuery && matchesVector && matchesResult;
  });

  renderFullScansTable(filtered);
}

$("scanSearchInput")?.addEventListener("input", filterFullScans);
$("scanVectorFilter")?.addEventListener("change", filterFullScans);
$("scanResultFilter")?.addEventListener("change", filterFullScans);

function updateSecurityPosture(totalScans, threats) {
  const scoreElem = $("securityScoreVal");
  if (!scoreElem) return;

  // Base score 75. Increases with scans performed; decreases with active threats
  let score = 80;
  if (totalScans > 0) score += Math.min(15, totalScans * 2);
  score -= Math.min(25, threats * 4);
  score = Math.max(50, Math.min(98, score));

  scoreElem.textContent = `${score}%`;
}

/* =========================================================
   STREAM 2: CYBER COMPLAINTS
   ========================================================= */

async function loadComplaints() {
  const db = getDb();
  if (!db || !currentUser) return;

  try {
    const snap = await db
      .collection("cyber_complaints")
      .where("user_id", "==", currentUser.uid)
      .limit(100)
      .get();

    complaintsCache = [];
    snap.forEach((doc) => {
      complaintsCache.push({ id: doc.id, ...doc.data() });
    });

    complaintsCache.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    // Update Counter Badges
    const activeComplaints = complaintsCache.filter((c) => c.status !== "Closed" && c.status !== "Resolved").length;
    if ($("kpiComplaints")) $("kpiComplaints").textContent = complaintsCache.length;
    if ($("sidebarComplaintCount")) $("sidebarComplaintCount").textContent = activeComplaints;

    renderComplaintsTable(complaintsCache);

  } catch (err) {
    console.error("Error loading complaints:", err);
  }
}

function renderComplaintsTable(rows) {
  const tbody = $("complaintsTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="empty">
          No cyber crime complaints filed yet.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = rows.map((c) => `
    <tr>
      <td><strong style="color: var(--cyan); cursor: pointer;" onclick="inspectComplaint('${esc(c.complaint_id)}')">${esc(c.complaint_id)}</strong></td>
      <td><span style="font-size: 0.78rem;">${esc(c.complaint_type)}</span></td>
      <td title="${esc(c.title)}" style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        <strong>${esc(c.title)}</strong>
      </td>
      <td style="color: var(--muted); font-size: 0.78rem;">${fmtDate(c.incident_datetime || c.created_at)}</td>
      <td>${getPriorityBadge(c.priority)}</td>
      <td>${getStatusBadge(c.status)}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="viewComplaintDetails('${c.id}')">
          View Details
        </button>
      </td>
    </tr>
  `).join("");
}

function filterComplaints() {
  const statusFilter = $("complaintStatusFilter")?.value || "all";
  const filtered = complaintsCache.filter((c) => statusFilter === "all" || c.status === statusFilter);
  renderComplaintsTable(filtered);
}

$("complaintStatusFilter")?.addEventListener("change", filterComplaints);

/* COMPLAINT TRACKER SEARCH */
window.inspectComplaint = function (complaintId) {
  switchTab("complaints");
  const input = $("complaintSearchIdInput");
  if (input) input.value = complaintId;
  trackComplaintById(complaintId);
};

function trackComplaintById(complaintId) {
  if (!complaintId) return;
  const cleanId = complaintId.trim().toUpperCase();

  const found = complaintsCache.find((c) => (c.complaint_id || "").toUpperCase() === cleanId);
  const detailsArea = $("trackerDetailsArea");
  const badge = $("trackerStatusBadge");

  if (!found) {
    showToast(`Complaint ID '${cleanId}' not found in your filed records.`, "error");
    if (detailsArea) detailsArea.style.display = "none";
    if (badge) {
      badge.className = "badge closed";
      badge.textContent = "Not Found";
    }
    return;
  }

  if (detailsArea) detailsArea.style.display = "block";
  if ($("trackerComplaintTitle")) $("trackerComplaintTitle").textContent = `${found.complaint_id} — ${found.title}`;
  if ($("trackerComplaintMeta")) {
    $("trackerComplaintMeta").textContent = `Category: ${found.complaint_type} • Filed: ${fmtDate(found.created_at)}`;
  }
  if ($("trackerComplaintPriority")) {
    $("trackerComplaintPriority").innerHTML = getPriorityBadge(found.priority);
  }
  if (badge) {
    badge.innerHTML = getStatusBadge(found.status);
  }

  // Update Milestone Steps
  const statusSteps = {
    "submitted": 1,
    "under review": 2,
    "in progress": 3,
    "resolved": 4,
    "closed": 5
  };

  const currentStep = statusSteps[String(found.status || "submitted").toLowerCase()] || 1;

  for (let i = 1; i <= 5; i++) {
    const stepElem = $(`step-${i}`);
    if (stepElem) {
      stepElem.className = "tracker-step";
      if (i < currentStep) stepElem.classList.add("completed");
      else if (i === currentStep) stepElem.classList.add("active");
    }
  }

  showToast(`Loaded tracker for ${found.complaint_id}`, "info");
}

$("trackComplaintBtn")?.addEventListener("click", () => {
  const val = $("complaintSearchIdInput")?.value;
  if (!val) return showToast("Please enter a valid Complaint ID.", "error");
  trackComplaintById(val);
});

$("quickTrackForm")?.addEventListener("submit", (e) => {
  e.preventDefault();
  const val = $("quickTrackInput")?.value;
  if (val) {
    inspectComplaint(val);
  }
});

/* VIEW COMPLAINT DETAILS MODAL */
window.viewComplaintDetails = function (id) {
  const c = complaintsCache.find((item) => item.id === id);
  if (!c) return;

  if ($("viewCmpHeader")) $("viewCmpHeader").textContent = `${c.complaint_id} — Details`;
  if ($("viewCmpBody")) {
    $("viewCmpBody").innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
        <div>
          <span style="font-size: 0.74rem; color: var(--muted);">COMPLAINT CATEGORY:</span>
          <div style="font-weight: 700; color: #fff;">${esc(c.complaint_type)}</div>
        </div>
        <div style="display: flex; gap: 8px;">
          ${getPriorityBadge(c.priority)}
          ${getStatusBadge(c.status)}
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Subject / Title</label>
        <div style="color: #fff; font-size: 0.92rem; font-weight: 600;">${esc(c.title)}</div>
      </div>

      <div class="form-group">
        <label class="form-label">Incident Date & Time</label>
        <div style="color: var(--muted-light); font-size: 0.82rem;">${fmtDate(c.incident_datetime || c.created_at)}</div>
      </div>

      <div class="form-group">
        <label class="form-label">Suspect Reference / Identification Info</label>
        <div style="color: var(--cyan); font-size: 0.82rem; font-family: monospace;">${esc(c.reference_info || "None specified")}</div>
      </div>

      <div class="form-group">
        <label class="form-label">Incident Narrative Description</label>
        <div style="background: rgba(255,255,255,0.03); padding: 12px; border-radius: 9px; border: 1px solid var(--line-subtle); color: #dff5ec; font-size: 0.82rem; line-height: 1.6; white-space: pre-wrap;">${esc(c.description)}</div>
      </div>

      ${c.evidence_url ? `
        <div class="form-group" style="margin-top: 14px;">
          <label class="form-label">Attached Supporting Evidence File</label>
          <a href="${esc(c.evidence_url)}" target="_blank" class="uploaded-file-pill" style="text-decoration: none;">
            <i class="fa-solid fa-paperclip"></i> ${esc(c.evidence_filename || "View Attached Evidence File")} <i class="fa-solid fa-arrow-up-right-from-square" style="font-size: 0.72rem; margin-left: 4px;"></i>
          </a>
        </div>
      ` : ""}
    `;
  }

  openModal("viewComplaintModal");
};

/* =========================================================
   COMPLAINT EVIDENCE FILE UPLOAD (BACKEND INTEGRATION)
   ========================================================= */

$("fileDropzone")?.addEventListener("click", () => {
  $("cmpEvidenceFile")?.click();
});

$("cmpEvidenceFile")?.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  const statusDiv = $("fileUploadStatus");
  if (!file || !statusDiv) return;

  statusDiv.innerHTML = `<span style="font-size: 0.78rem; color: var(--cyan);"><i class="fa-solid fa-spinner fa-spin"></i> Uploading ${esc(file.name)}...</span>`;

  try {
    const apiBase = typeof window.resolveNetArmorApi === "function" ? await window.resolveNetArmorApi() : "http://127.0.0.1:8000";
    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch(`${apiBase}/api/upload-evidence`, {
      method: "POST",
      body: formData
    });

    if (res.ok) {
      const data = await res.json();
      uploadedEvidenceInfo = {
        filename: data.original_name || file.name,
        url: `${apiBase}${data.url}`
      };
      statusDiv.innerHTML = `
        <div class="uploaded-file-pill">
          <i class="fa-solid fa-circle-check" style="color: var(--green);"></i> Evidence attached: ${esc(file.name)} (${(file.size / 1024).toFixed(1)} KB)
        </div>
      `;
      showToast("Evidence file successfully uploaded!", "success");
    } else {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Upload rejected.");
    }
  } catch (err) {
    console.warn("Evidence upload failed, saving file reference locally:", err);
    uploadedEvidenceInfo = {
      filename: file.name,
      url: ""
    };
    statusDiv.innerHTML = `
      <div class="uploaded-file-pill" style="color: var(--amber); border-color: var(--amber);">
        <i class="fa-solid fa-triangle-exclamation" style="color: var(--amber);"></i> Attached file noted: ${esc(file.name)}
      </div>
    `;
  }
});

/* SUBMIT NEW CYBER COMPLAINT */
$("newComplaintForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db || !currentUser) return;

  const btn = $("submitComplaintBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Filing Complaint...";
  }

  try {
    const complaintId = `NET-CMP-2026-${Math.floor(1000 + Math.random() * 9000)}`;
    const category = $("cmpType")?.value || "Other Cyber Incident";
    const priority = $("cmpPriority")?.value || "Medium";
    const title = $("cmpTitle")?.value.trim() || "Untitled Complaint";
    const dt = $("cmpDateTime")?.value || new Date().toISOString();
    const ref = $("cmpReference")?.value.trim() || "";
    const desc = $("cmpDescription")?.value.trim() || "";

    const newDoc = {
      complaint_id: complaintId,
      user_id: currentUser.uid,
      user_email: currentUser.email,
      complaint_type: category,
      priority: priority,
      title: title,
      incident_datetime: dt,
      reference_info: ref,
      description: desc,
      status: "Submitted",
      evidence_filename: uploadedEvidenceInfo?.filename || null,
      evidence_url: uploadedEvidenceInfo?.url || null,
      created_at: firebase.firestore.FieldValue.serverTimestamp(),
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    };

    await db.collection("cyber_complaints").add(newDoc);

    // Create In-App Notification
    await createNotification(
      "Cyber Complaint Acknowledged",
      `Your complaint '${complaintId}: ${title}' has been logged and assigned to Cyber Triage.`,
      "complaint"
    );

    showToast(`Cyber Complaint ${complaintId} successfully lodged!`, "success");

    // Reset Form
    $("newComplaintForm")?.reset();
    uploadedEvidenceInfo = null;
    if ($("fileUploadStatus")) $("fileUploadStatus").innerHTML = "";

    closeModal("complaintModal");
    await loadComplaints();
    renderActivityStream();

    // Auto-inspect the newly created complaint
    inspectComplaint(complaintId);

  } catch (err) {
    console.error("Complaint filing error:", err);
    showToast(err.message || "Failed to submit cyber complaint.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Submit Complaint`;
    }
  }
});

$("openComplaintModalBtn")?.addEventListener("click", () => {
  const dtInput = $("cmpDateTime");
  if (dtInput) {
    // Pre-fill with current local datetime
    const now = new Date();
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    dtInput.value = now.toISOString().slice(0, 16);
  }
  openModal("complaintModal");
});

$("quickComplaintBtn")?.addEventListener("click", () => {
  openModal("complaintModal");
});

/* =========================================================
   STREAM 3: REPORT FRAUD & SUSPICIOUS ACTIVITY
   ========================================================= */

$("reportFraudForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db || !currentUser) return;

  const category = $("fraudCategory")?.value;
  const target = $("fraudTarget")?.value.trim();
  const desc = $("fraudDescription")?.value.trim();

  if (!target || !desc) {
    showToast("Please provide both target and incident details.", "error");
    return;
  }

  try {
    const reportId = `NET-FRD-2026-${Math.floor(1000 + Math.random() * 9000)}`;

    await db.collection("cyber_complaints").add({
      complaint_id: reportId,
      user_id: currentUser.uid,
      user_email: currentUser.email,
      complaint_type: category,
      priority: "High",
      title: `Fraud Report: ${target.slice(0, 50)}`,
      incident_datetime: new Date().toISOString(),
      reference_info: target,
      description: desc,
      status: "Submitted",
      created_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    await createNotification(
      "Fraud Report Logged",
      `Suspicious vector '${target.slice(0, 35)}...' has been submitted for heuristic analysis.`,
      "threat"
    );

    showToast("Fraud report submitted! Our threat engine has queued the target.", "success");
    $("reportFraudForm")?.reset();
    await loadComplaints();
    renderActivityStream();

  } catch (err) {
    console.error("Fraud report error:", err);
    showToast("Failed to submit report. Please try again.", "error");
  }
});

$("testFraudInScannerBtn")?.addEventListener("click", () => {
  const target = $("fraudTarget")?.value.trim();
  if (!target) {
    window.location.href = "detect.html";
    return;
  }
  // Redirect to scanner with query
  window.location.href = `detect.html?target=${encodeURIComponent(target)}`;
});

/* =========================================================
   STREAM 4: SUPPORT TICKETS
   ========================================================= */

async function loadTickets() {
  const db = getDb();
  if (!db || !currentUser) return;

  try {
    const snap = await db
      .collection("support_tickets")
      .where("user_id", "==", currentUser.uid)
      .limit(100)
      .get();

    ticketsCache = [];
    snap.forEach((doc) => {
      ticketsCache.push({ id: doc.id, ...doc.data() });
    });

    ticketsCache.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    const openCount = ticketsCache.filter((t) => t.status === "Open" || t.status === "In Progress").length;
    if ($("sidebarTicketCount")) $("sidebarTicketCount").textContent = openCount;

    renderTicketsTable(ticketsCache);

  } catch (err) {
    console.error("Error loading tickets:", err);
  }
}

function renderTicketsTable(rows) {
  const tbody = $("ticketsTable");
  if (!tbody) return;

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">No support tickets found.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map((t) => `
    <tr>
      <td><strong style="color: var(--cyan);">${esc(t.ticket_id)}</strong></td>
      <td><span style="font-size: 0.78rem;">${esc(t.category)}</span></td>
      <td title="${esc(t.subject)}" style="max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        <strong>${esc(t.subject)}</strong>
      </td>
      <td>${getPriorityBadge(t.priority)}</td>
      <td>${getStatusBadge(t.status)}</td>
      <td style="color: var(--muted); font-size: 0.76rem;">${timeAgo(t.created_at)}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="viewTicketDetails('${t.id}')">
          <i class="fa-solid fa-eye"></i> View
        </button>
      </td>
    </tr>
  `).join("");
}

function filterTickets() {
  const query = ($("ticketSearchInput")?.value || "").toLowerCase().trim();
  const category = $("ticketCategoryFilter")?.value || "all";
  const status = $("ticketStatusFilter")?.value || "all";

  const filtered = ticketsCache.filter((t) => {
    const matchesQuery = !query || String(t.subject || "").toLowerCase().includes(query) || String(t.ticket_id || "").toLowerCase().includes(query);
    const matchesCat = category === "all" || t.category === category;
    const matchesStatus = status === "all" || t.status === status;
    return matchesQuery && matchesCat && matchesStatus;
  });

  renderTicketsTable(filtered);
}

$("ticketSearchInput")?.addEventListener("input", filterTickets);
$("ticketCategoryFilter")?.addEventListener("change", filterTickets);
$("ticketStatusFilter")?.addEventListener("change", filterTickets);

/* CREATE NEW SUPPORT TICKET */
$("newTicketForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db || !currentUser) return;

  const btn = $("submitTicketBtn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Creating...`;
  }

  try {
    const ticketId = `NET-TCK-${Math.floor(1000 + Math.random() * 9000)}`;
    const category = $("tckCategory")?.value;
    const priority = $("tckPriority")?.value;
    const subject = $("tckSubject")?.value.trim();
    const msg = $("tckMessage")?.value.trim();

    await db.collection("support_tickets").add({
      ticket_id: ticketId,
      user_id: currentUser.uid,
      user_email: currentUser.email,
      category: category,
      priority: priority,
      subject: subject,
      message: msg,
      status: "Open",
      replies: [],
      created_at: firebase.firestore.FieldValue.serverTimestamp(),
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    await createNotification(
      "Support Ticket Created",
      `Ticket '${ticketId}: ${subject}' has been assigned to NetArmor Engineering Support.`,
      "ticket"
    );

    showToast(`Support Ticket ${ticketId} created!`, "success");
    $("newTicketForm")?.reset();
    closeModal("ticketModal");

    await loadTickets();
    renderActivityStream();

  } catch (err) {
    console.error("Ticket creation error:", err);
    showToast(err.message || "Failed to create support ticket.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-ticket"></i> Create Ticket`;
    }
  }
});

$("openTicketModalBtn")?.addEventListener("click", () => {
  openModal("ticketModal");
});

/* =========================================================
   VIEW TICKET DETAILS & USER CONVERSATION
   ========================================================= */
window.viewTicketDetails = function (id) {
  const t = ticketsCache.find((item) => item.id === id);
  if (!t) return;

  if ($("viewTckHeader")) {
    $("viewTckHeader").innerHTML = `<i class="fa-solid fa-ticket" style="color: var(--cyan);"></i> Ticket ${esc(t.ticket_id)} — Details`;
  }

  const createdDate = fmtDate(t.created_at);
  const lastUpdated = t.updated_at ? fmtDate(t.updated_at) : createdDate;
  const adminResponse = t.resolution_note || "";
  const replies = Array.isArray(t.replies) ? t.replies : [];
  const isClosed = String(t.status || "").toLowerCase() === "closed";

  // Admin Response highlight card
  let adminResponseCard = "";
  if (adminResponse) {
    adminResponseCard = `
      <div class="admin-response-card">
        <div class="admin-response-header">
          <span class="admin-response-title">
            <i class="fa-solid fa-shield-halved"></i> SOC Official Resolution &amp; Response
          </span>
          <span style="font-size: 0.72rem; color: var(--muted);">${lastUpdated}</span>
        </div>
        <div class="admin-response-content">${esc(adminResponse)}</div>
      </div>
    `;
  }

  // Conversation history
  let conversationHtml = "";
  if (replies.length > 0) {
    conversationHtml = `
      <div class="conversation-thread-title">
        <i class="fa-solid fa-comments"></i> Conversation History (${replies.length} ${replies.length === 1 ? 'Message' : 'Messages'})
      </div>
      <div class="conversation-thread" id="ticketConversationThread">
        ${replies.map((msg) => {
          const isAdmin = msg.sender === 'admin' || msg.sender_role === 'associate' || msg.sender_role === 'admin';
          const senderLabel = isAdmin ? (msg.sender_name || 'NetArmor SOC Lead') : (msg.sender_name || 'You (Analyst)');
          const icon = isAdmin ? '<i class="fa-solid fa-shield-halved"></i>' : '<i class="fa-solid fa-user"></i>';
          const timeVal = msg.created_at || msg.timestamp;
          const timeStr = timeVal ? fmtDate(timeVal) : 'Recent';
          return `
            <div class="conversation-bubble ${isAdmin ? 'admin' : 'user'}">
              <div class="bubble-header">
                <span class="bubble-sender">${icon} ${esc(senderLabel)}</span>
                <span class="bubble-time">${timeStr}</span>
              </div>
              <div class="bubble-text">${esc(msg.message || '')}</div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  } else if (!adminResponse) {
    conversationHtml = `
      <div style="background: rgba(255,255,255,0.02); border: 1px dashed var(--line-subtle); border-radius: 10px; padding: 14px; text-align: center; color: var(--muted); font-size: 0.8rem; margin: 16px 0;">
        <i class="fa-solid fa-headset" style="font-size: 1.2rem; display: block; margin-bottom: 6px; color: var(--cyan);"></i>
        Awaiting response from NetArmor Support Engineering. You will be notified in-app once an engineer replies.
      </div>
    `;
  }

  // Reply box
  let replyBoxHtml = "";
  if (!isClosed) {
    replyBoxHtml = `
      <div class="ticket-reply-box">
        <label class="form-label" style="display: flex; align-items: center; gap: 6px;">
          <i class="fa-solid fa-reply"></i> Post a Reply / Follow-Up Note
        </label>
        <textarea id="userTicketReplyInput" class="form-textarea" placeholder="Add further details or ask a follow-up question regarding this ticket..." style="min-height: 75px; margin-bottom: 10px;"></textarea>
        <div style="display: flex; justify-content: flex-end; gap: 8px;">
          <button type="button" class="btn btn-primary btn-sm" id="sendUserReplyBtn" onclick="submitUserTicketReply('${t.id}')">
            <i class="fa-solid fa-paper-plane"></i> Send Reply
          </button>
        </div>
      </div>
    `;
  } else {
    replyBoxHtml = `
      <div style="margin-top: 14px; background: rgba(255,255,255,0.03); border: 1px solid var(--line-subtle); border-radius: 10px; padding: 12px 16px; font-size: 0.8rem; color: var(--muted); display: flex; align-items: center; gap: 10px;">
        <i class="fa-solid fa-lock" style="color: var(--amber);"></i>
        <span>This ticket is marked as <strong>Closed</strong>. If you require further support, please create a new support ticket.</span>
      </div>
    `;
  }

  if ($("viewTckBody")) {
    $("viewTckBody").innerHTML = `
      <!-- TOP METADATA CHIPS -->
      <div class="ticket-detail-grid">
        <div class="ticket-detail-item">
          <small>Ticket ID</small>
          <strong style="color: var(--cyan);"><i class="fa-solid fa-hashtag"></i> ${esc(t.ticket_id)}</strong>
        </div>
        <div class="ticket-detail-item">
          <small>Category</small>
          <span>${esc(t.category || 'General')}</span>
        </div>
        <div class="ticket-detail-item">
          <small>Priority</small>
          <div>${getPriorityBadge(t.priority)}</div>
        </div>
        <div class="ticket-detail-item">
          <small>Status</small>
          <div>${getStatusBadge(t.status)}</div>
        </div>
        <div class="ticket-detail-item">
          <small>Created</small>
          <span style="font-size: 0.76rem; color: var(--muted-light);">${createdDate}</span>
        </div>
        <div class="ticket-detail-item">
          <small>Last Updated</small>
          <span style="font-size: 0.76rem; color: var(--muted-light);">${lastUpdated}</span>
        </div>
      </div>

      <!-- SUBJECT -->
      <div style="margin-bottom: 14px;">
        <small style="color: var(--muted); text-transform: uppercase; font-weight: 700; font-size: 0.7rem; letter-spacing: 0.5px;">SUBJECT</small>
        <h4 style="margin: 4px 0 0; color: #fff; font-size: 1.05rem;">${esc(t.subject)}</h4>
      </div>

      <!-- ORIGINAL DESCRIPTION -->
      <div class="ticket-description-box">
        <h5><i class="fa-solid fa-align-left"></i> Original Request / Issue Description</h5>
        <div class="ticket-description-content">${esc(t.message || t.description || 'No description provided.')}</div>
      </div>

      <!-- ADMIN OFFICIAL RESPONSE -->
      ${adminResponseCard}

      <!-- CONVERSATION TIMELINE -->
      ${conversationHtml}

      <!-- REPLY ACTION BOX -->
      ${replyBoxHtml}
    `;
  }

  openModal("viewTicketModal");
};

window.submitUserTicketReply = async function (id) {
  const db = getDb();
  if (!db || !currentUser) return;

  const replyInput = $("userTicketReplyInput");
  const msg = (replyInput?.value || "").trim();
  if (!msg) {
    showToast("Please enter a reply message before submitting.", "error");
    return;
  }

  const btn = $("sendUserReplyBtn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Sending...`;
  }

  try {
    const t = ticketsCache.find((item) => item.id === id);
    const nowIso = new Date().toISOString();
    const newReply = {
      sender: "user",
      sender_name: currentUser.displayName || "Analyst",
      sender_email: currentUser.email || "",
      message: msg,
      timestamp: nowIso,
      created_at: nowIso
    };

    const updatePayload = {
      replies: firebase.firestore.FieldValue.arrayUnion(newReply),
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    };

    if (t && t.status === "Resolved") {
      updatePayload.status = "In Progress";
    }

    await db.collection("support_tickets").doc(id).update(updatePayload);

    showToast("Reply posted successfully!", "success");
    await loadTickets();
    window.viewTicketDetails(id);

  } catch (err) {
    console.error("Error submitting ticket reply:", err);
    showToast(err.message || "Failed to submit reply.", "error");
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Send Reply`;
    }
  }
};

/* =========================================================
   STREAM 5: IN-APP NOTIFICATIONS
   ========================================================= */

async function loadNotifications() {
  const db = getDb();
  if (!db || !currentUser) return;

  try {
    const snap = await db
      .collection("user_notifications")
      .where("user_id", "==", currentUser.uid)
      .limit(30)
      .get();

    notificationsCache = [];
    snap.forEach((doc) => {
      notificationsCache.push({ id: doc.id, ...doc.data() });
    });

    notificationsCache.sort((a, b) => {
      const tA = a.created_at?.toDate ? a.created_at.toDate().getTime() : new Date(a.created_at || 0).getTime();
      const tB = b.created_at?.toDate ? b.created_at.toDate().getTime() : new Date(b.created_at || 0).getTime();
      return tB - tA;
    });

    const unread = notificationsCache.filter((n) => !n.read).length;
    const pill = $("notifCountPill");
    if (pill) {
      if (unread > 0) {
        pill.textContent = unread > 9 ? "9+" : unread;
        pill.style.display = "flex";
      } else {
        pill.style.display = "none";
      }
    }

    renderNotificationsList();

  } catch (err) {
    console.error("Notifications fetch error:", err);
  }
}

function renderNotificationsList() {
  const list = $("notifList");
  if (!list) return;

  if (notificationsCache.length === 0) {
    list.innerHTML = `<div class="empty">No notifications yet.</div>`;
    return;
  }

  list.innerHTML = notificationsCache.map((n) => `
    <div class="notif-item ${n.read ? "" : "unread"}" onclick="markNotifAsRead('${n.id}')">
      <div class="notif-item-top">
        <span>${esc(n.type?.toUpperCase() || "SYSTEM")}</span>
        <span>${timeAgo(n.created_at)}</span>
      </div>
      <div class="notif-item-title">${esc(n.title)}</div>
      <div class="notif-item-body">${esc(n.message)}</div>
    </div>
  `).join("");
}

window.markNotifAsRead = async function (id) {
  const db = getDb();
  if (!db) return;
  try {
    await db.collection("user_notifications").doc(id).update({ read: true });
    const target = notificationsCache.find((n) => n.id === id);
    if (target) target.read = true;
    loadNotifications();
  } catch (_) {}
};

$("markAllNotifsReadBtn")?.addEventListener("click", async () => {
  const db = getDb();
  if (!db) return;
  const unreadDocs = notificationsCache.filter((n) => !n.read);
  await Promise.all(
    unreadDocs.map((n) => db.collection("user_notifications").doc(n.id).update({ read: true }))
  );
  loadNotifications();
  showToast("All notifications marked as read.", "info");
});

// Notification Bell Toggle
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

async function createNotification(title, message, type = "system") {
  const db = getDb();
  if (!db || !currentUser) return;
  try {
    await db.collection("user_notifications").add({
      user_id: currentUser.uid,
      title: title,
      message: message,
      type: type,
      read: false,
      created_at: firebase.firestore.FieldValue.serverTimestamp()
    });
    loadNotifications();
  } catch (_) {}
}

/* =========================================================
   STREAM 6: UNIFIED LIVE RECENT ACTIVITY STREAM
   ========================================================= */

function renderActivityStream() {
  const stream = $("recentActivityStream");
  if (!stream) return;

  const activities = [];

  // 1. Scans
  scansCache.slice(0, 4).forEach((s) => {
    activities.push({
      icon: s.result === "Threat" ? '<i class="fa-solid fa-ban" style="color:var(--red);"></i>' : '<i class="fa-solid fa-shield-halved" style="color:var(--green);"></i>',
      iconBg: s.result === "Threat" ? "rgba(255,85,119,0.15)" : "rgba(0,255,136,0.12)",
      title: `${s.result} Scan: ${formatScanType(s.scan_type)}`,
      time: s.created_at,
      detail: esc(String(s.target || "").slice(0, 36))
    });
  });

  // 2. Complaints
  complaintsCache.slice(0, 3).forEach((c) => {
    activities.push({
      icon: '<i class="fa-solid fa-triangle-exclamation" style="color:var(--cyan);"></i>',
      iconBg: "rgba(56,189,248,0.15)",
      title: `Complaint Filed: ${c.complaint_id}`,
      time: c.created_at,
      detail: esc(c.title)
    });
  });

  // 3. Tickets
  ticketsCache.slice(0, 3).forEach((t) => {
    activities.push({
      icon: '<i class="fa-solid fa-ticket" style="color:var(--purple);"></i>',
      iconBg: "rgba(168,85,247,0.15)",
      title: `Support Ticket: ${t.ticket_id}`,
      time: t.created_at,
      detail: esc(t.subject)
    });
  });

  // Sort unified list descending
  activities.sort((a, b) => {
    const tA = a.time?.toDate ? a.time.toDate().getTime() : new Date(a.time || 0).getTime();
    const tB = b.time?.toDate ? b.time.toDate().getTime() : new Date(b.time || 0).getTime();
    return tB - tA;
  });

  if (activities.length === 0) {
    stream.innerHTML = `<div class="empty">No recent security events recorded.</div>`;
    return;
  }

  stream.innerHTML = activities.slice(0, 6).map((act) => `
    <div class="activity-item">
      <div class="activity-icon" style="background: ${act.iconBg};">
        ${act.icon}
      </div>
      <div class="activity-info">
        <div class="activity-title">${act.title}</div>
        <div style="font-size: 0.73rem; color: #b4cbbf; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
          ${act.detail}
        </div>
        <div class="activity-time">${timeAgo(act.time)}</div>
      </div>
    </div>
  `).join("");
}

/* =========================================================
   STREAM 7: USER FEEDBACK
   ========================================================= */

// Interactive Star Rating
document.querySelectorAll(".star-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const val = Number(btn.dataset.value);
    const hidden = $("feedbackRating");
    if (hidden) hidden.value = val;

    document.querySelectorAll(".star-btn").forEach((s) => {
      const sVal = Number(s.dataset.value);
      s.classList.toggle("active", sVal <= val);
    });
  });
});

$("feedbackForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db || !currentUser) return;

  const btn = $("feedbackSubmitBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Submitting...";
  }

  try {
    const rating = Number($("feedbackRating")?.value || 5);
    const category = $("feedbackCategory")?.value;
    const comments = $("feedbackComments")?.value.trim();

    await db.collection("user_feedback").add({
      user_id: currentUser.uid,
      user_email: currentUser.email,
      rating: rating,
      category: category,
      comments: comments,
      created_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    showToast("Thank you! Your feedback has been recorded.", "success");
    $("feedbackForm")?.reset();

    // Reset stars to 5
    document.querySelectorAll(".star-btn").forEach((s) => s.classList.add("active"));
    if ($("feedbackRating")) $("feedbackRating").value = 5;

  } catch (err) {
    console.error("Feedback submission error:", err);
    showToast("Failed to submit feedback.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Submit User Feedback`;
    }
  }
});

/* =========================================================
   STREAM 8: ACCOUNT SETTINGS & PROFILE UPDATE
   ========================================================= */

$("profileSettingsForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const db = getDb();
  if (!db || !currentUser) return;

  const btn = $("saveProfileBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Saving...";
  }

  try {
    const fullName = $("profileFullName")?.value.trim() || "";
    const username = $("profileUsername")?.value.trim() || "";
    const phone = $("profilePhone")?.value.trim() || "";
    const org = $("profileOrg")?.value.trim() || "";

    if (!username) throw new Error("Username cannot be empty.");

    await db.collection("profiles").doc(currentUser.uid).update({
      full_name: fullName,
      username: username,
      phone: phone,
      organization: org,
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    // Update in-memory
    currentProfile.full_name = fullName;
    currentProfile.username = username;
    currentProfile.phone = phone;
    currentProfile.organization = org;

    const displayName = fullName || username;
    if ($("name")) $("name").textContent = displayName;
    if ($("sidebarUserName")) $("sidebarUserName").textContent = displayName;
    if ($("userAvatarText")) $("userAvatarText").textContent = (displayName[0] || "U").toUpperCase();

    showToast("Profile settings saved successfully!", "success");

  } catch (err) {
    console.error("Profile save error:", err);
    showToast(err.message || "Failed to save profile.", "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save Profile Changes';
    }
  }
});

/* =========================================================
   PASSWORD CHANGE & SECURITY CREDENTIALS CONTROLLER
   ========================================================= */

function initPasswordSecurity() {
  // 1. Password eye visibility toggles
  document.querySelectorAll(".password-eye-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
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

  // 2. Real-time strength meter on newPassword
  $("newPassword")?.addEventListener("input", (e) => {
    evaluatePasswordStrength(e.target.value);
    checkPasswordMatch();
  });

  // 3. Live password match checking
  $("confirmPassword")?.addEventListener("input", () => {
    checkPasswordMatch();
  });

  // 4. Form submission handler
  $("changePasswordForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const auth = getAuth();
    if (!auth || !auth.currentUser) {
      showPasswordAlert("Active user session required. Please sign in.", "error");
      return;
    }

    const currentPassword = $("currentPassword")?.value || "";
    const newPassword = $("newPassword")?.value || "";
    const confirmPassword = $("confirmPassword")?.value || "";

    if (!currentPassword) {
      showPasswordAlert("Please provide your current password.", "error");
      return;
    }

    if (newPassword.length < 8) {
      showPasswordAlert("New password must contain at least 8 characters.", "error");
      return;
    }

    if (newPassword !== confirmPassword) {
      showPasswordAlert("New password and confirm password do not match.", "error");
      return;
    }

    if (currentPassword === newPassword) {
      showPasswordAlert("New password must be different from your current password.", "error");
      return;
    }

    const btn = $("changePasswordBtn");
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Verifying & Updating...`;
    }

    try {
      const user = auth.currentUser;
      // Step A: Re-authenticate with Current Password
      const credential = firebase.auth.EmailAuthProvider.credential(user.email, currentPassword);
      await user.reauthenticateWithCredential(credential);

      // Step B: Update Password
      await user.updatePassword(newPassword);

      // Step C: Success Feedback
      showPasswordAlert("Password updated successfully! Your account credentials have been securely refreshed.", "success");
      showToast("Password updated successfully!", "success");

      // In-app audit notification
      await createNotification(
        "Password Updated",
        "Your account password was updated successfully. If this wasn't you, report immediate fraud.",
        "security"
      );

      // Reset form
      $("changePasswordForm")?.reset();
      evaluatePasswordStrength("");
      const matchFeedback = $("passwordMatchFeedback");
      if (matchFeedback) matchFeedback.style.display = "none";

      renderActivityStream();

    } catch (err) {
      console.error("Password update error:", err);
      let msg = "Unable to update password. Please try again.";
      if (err.code === "auth/wrong-password" || err.code === "auth/invalid-credential" || err.code === "auth/invalid-login-credentials") {
        msg = "Current password is incorrect. Please verify and try again.";
      } else if (err.code === "auth/weak-password") {
        msg = "Password is too weak. Please include at least 8 characters with a mix of letters, numbers, and symbols.";
      } else if (err.code === "auth/requires-recent-login") {
        msg = "Security session expired. Please sign out and log back in to verify your identity.";
      } else if (err.message) {
        msg = err.message;
      }
      showPasswordAlert(msg, "error");
      showToast(msg, "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-key"></i> Update Password`;
      }
    }
  });
}

function evaluatePasswordStrength(password) {
  const p = password || "";
  const criteria = {
    length: p.length >= 8,
    upper: /[A-Z]/.test(p),
    lower: /[a-z]/.test(p),
    number: /[0-9]/.test(p),
    special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(p)
  };

  const updateCrit = (id, met) => {
    const el = $(id);
    if (!el) return;
    if (met) {
      el.classList.add("met");
      const icon = el.querySelector("i");
      if (icon) icon.className = "fa-solid fa-circle-check";
    } else {
      el.classList.remove("met");
      const icon = el.querySelector("i");
      if (icon) icon.className = "fa-regular fa-circle";
    }
  };

  updateCrit("crit-len", criteria.length);
  updateCrit("crit-upper", criteria.upper);
  updateCrit("crit-lower", criteria.lower);
  updateCrit("crit-num", criteria.number);
  updateCrit("crit-special", criteria.special);

  let score = 0;
  if (criteria.length) score++;
  if (criteria.upper) score++;
  if (criteria.lower) score++;
  if (criteria.number) score++;
  if (criteria.special) score++;

  const fill = $("strengthFill");
  const text = $("strengthText");

  if (!p) {
    if (fill) { fill.className = "strength-bar-fill"; fill.style.width = "0%"; }
    if (text) { text.className = "strength-text"; text.textContent = "Too Short"; }
    return score;
  }

  if (score <= 2) {
    if (fill) fill.className = "strength-bar-fill weak";
    if (text) { text.className = "strength-text weak"; text.textContent = "Weak"; }
  } else if (score === 3) {
    if (fill) fill.className = "strength-bar-fill fair";
    if (text) { text.className = "strength-text fair"; text.textContent = "Moderate"; }
  } else if (score === 4) {
    if (fill) fill.className = "strength-bar-fill good";
    if (text) { text.className = "strength-text good"; text.textContent = "Strong"; }
  } else {
    if (fill) fill.className = "strength-bar-fill strong";
    if (text) { text.className = "strength-text strong"; text.textContent = "Very Strong"; }
  }

  return score;
}

function checkPasswordMatch() {
  const newPwd = $("newPassword")?.value || "";
  const confPwd = $("confirmPassword")?.value || "";
  const feedback = $("passwordMatchFeedback");
  if (!feedback) return;

  if (!confPwd) {
    feedback.style.display = "none";
    return;
  }

  feedback.style.display = "block";
  if (newPwd === confPwd) {
    feedback.style.color = "var(--green)";
    feedback.innerHTML = '<i class="fa-solid fa-circle-check"></i> Passwords match';
  } else {
    feedback.style.color = "var(--red)";
    feedback.innerHTML = '<i class="fa-solid fa-circle-xmark"></i> Passwords do not match';
  }
}

function showPasswordAlert(msg, type = "error") {
  const box = $("passwordAlertBox");
  if (!box) return;
  box.style.display = "flex";
  box.className = `password-feedback ${type}`;
  const icon = type === "success" ? '<i class="fa-solid fa-circle-check"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>';
  box.innerHTML = `${icon} <span>${esc(msg)}</span>`;
}

/* =========================================================
   FAQ ACCORDION INTERACTIVITY
   ========================================================= */

document.querySelectorAll(".faq-question").forEach((q) => {
  q.addEventListener("click", () => {
    const parent = q.parentElement;
    parent.classList.toggle("open");
  });
});

$("faqSearchInput")?.addEventListener("input", (e) => {
  const query = e.target.value.toLowerCase().trim();
  document.querySelectorAll(".faq-item").forEach((item) => {
    const text = item.textContent.toLowerCase();
    item.style.display = !query || text.includes(query) ? "block" : "none";
    if (query && text.includes(query)) {
      item.classList.add("open");
    }
  });
});

/* =========================================================
   LOGOUT CONTROLLERS
   ========================================================= */

async function handleLogout() {
  const auth = getAuth();
  if (auth) {
    try {
      await auth.signOut();
    } catch (_) {}
  }
  sessionStorage.removeItem("netarmor_profile");
  window.location.replace("login.html");
}

$("logout")?.addEventListener("click", handleLogout);
$("sidebarLogoutBtn")?.addEventListener("click", handleLogout);

/* =========================================================
   REFRESH TRIGGERS
   ========================================================= */

$("refresh")?.addEventListener("click", () => {
  $("refresh").innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Updating...';
  loadScans().finally(() => ($("refresh").innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Refresh'));
});

$("refreshFullScansBtn")?.addEventListener("click", () => {
  $("refreshFullScansBtn").innerHTML = '<i class="fa-solid fa-arrows-rotate fa-spin"></i> Updating...';
  loadScans().finally(() => ($("refreshFullScansBtn").innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> Refresh'));
});

$("refreshComplaintsBtn")?.addEventListener("click", () => {
  loadComplaints();
});

$("refreshTicketsBtn")?.addEventListener("click", () => {
  loadTickets();
});

/* =========================================================
   DOM READY
   ========================================================= */

document.addEventListener("DOMContentLoaded", initDashboard);
