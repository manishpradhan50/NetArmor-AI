const sb = window.netarmorSupabase;
const $ = (id) => document.getElementById(id);

/* HTML ESCAPE */
const esc = (value) => {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
};

/* DATE FORMAT */
const fmt = (date) => {
  if (!date) return "—";
  return new Date(date).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short"
  });
};

function formatScanType(type) {
  switch (type) {
    case "url": return "🌐 URL";
    case "email": return "✉️ Email";
    case "message": return "💬 SMS";
    case "document": return "📄 PDF";
    default: return esc(type || "General");
  }
}

/* LOAD ADMIN DASHBOARD */
async function load() {
  if (!sb) {
    alert("Supabase client not initialized.");
    return;
  }

  /* CHECK LOGIN */
  const { data: { user }, error: authError } = await sb.auth.getUser();
  if (authError || !user) {
    location.replace("login.html");
    return;
  }

  /* CHECK ROLE */
  const { data: profile } = await sb
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .maybeSingle();

  /* ONLY ASSOCIATE CAN ENTER */
  if (profile?.role !== "associate") {
    location.replace("dashboard.html");
    return;
  }

  /* SHOW LOADING TELEMETRY */
  if ($("threatsTable")) $("threatsTable").innerHTML = `<tr><td colspan="6" class="empty">Scanning global activity database...</td></tr>`;
  if ($("userTable")) $("userTable").innerHTML = `<tr><td colspan="3" class="empty">Querying user credentials directory...</td></tr>`;

  /* GET USERS + SCANS (Independent queries to avoid relational schema cache failure) */
  const [usersResult, scansResult] = await Promise.all([
    sb
      .from("profiles")
      .select("id, username, email, full_name, role, created_at")
      .order("created_at", { ascending: false })
      .limit(200),

    sb
      .from("scan_history")
      .select("id, scan_type, target, result, risk_score, created_at, user_id")
      .order("created_at", { ascending: false })
      .limit(100)
  ]);

  if (usersResult.error) {
    console.error("Error fetching users:", usersResult.error);
    if ($("userTable")) $("userTable").innerHTML = `<tr><td colspan="3" class="empty">Failed to load users: ${esc(usersResult.error.message)}</td></tr>`;
  }

  if (scansResult.error) {
    console.error("Error fetching scans:", scansResult.error);
    if ($("threatsTable")) $("threatsTable").innerHTML = `<tr><td colspan="6" class="empty">Failed to load threat scans: ${esc(scansResult.error.message)}</td></tr>`;
  }

  const users = usersResult.data || [];
  const scans = scansResult.data || [];

  // Build ID to Username lookup map for instant resolution
  const userMap = new Map();
  users.forEach((u) => {
    userMap.set(u.id, u.username || u.email?.split("@")[0] || "Analyst");
  });

  /* THREAT COUNT */
  const threats = scans.filter((scan) => scan.result === "Threat").length;

  /* DASHBOARD STATISTICS */
  if ($("users")) $("users").textContent = users.length;
  if ($("total")) $("total").textContent = scans.length;
  if ($("threats")) $("threats").textContent = threats;
  if ($("rate")) {
    $("rate").textContent = scans.length
      ? Math.round((threats / scans.length) * 100) + "%"
      : "0%";
  }

  /* USERS TABLE */
  if ($("userTable")) {
    $("userTable").innerHTML = users.length
      ? users.map((u) => `
        <tr>
          <td>
            <strong>${esc(u.username || "—")}</strong>
            ${u.email ? `<br><small style="color: var(--muted); font-size: 0.72rem;">${esc(u.email)}</small>` : ""}
          </td>
          <td>
            <span class="badge ${u.role === "associate" ? "threat" : "safe"}">
              ${u.role === "associate" ? "🛡️ Associate" : "Standard User"}
            </span>
          </td>
          <td style="color: var(--muted); font-size: 0.78rem;">
            ${fmt(u.created_at)}
          </td>
        </tr>
      `).join("")
      : `<tr><td colspan="3" class="empty">No registered user profiles found.</td></tr>`;
  }

  /* SCAN ACTIVITY TABLE */
  if ($("threatsTable")) {
    $("threatsTable").innerHTML = scans.length
      ? scans.map((scan) => {
        const username = userMap.get(scan.user_id) || "Anonymous";
        const isThreat = scan.result === "Threat";
        return `
          <tr>
            <td>
              <span style="font-weight: 700; color: #a7f3d0;">${esc(username)}</span>
            </td>
            <td>
              <strong>${formatScanType(scan.scan_type)}</strong>
            </td>
            <td title="${esc(scan.target)}" style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${esc(String(scan.target || "").slice(0, 50))}${String(scan.target || "").length > 50 ? "…" : ""}
            </td>
            <td>
              <span class="badge ${isThreat ? "threat" : "safe"}">
                ${esc(scan.result)}
              </span>
            </td>
            <td>
              <strong style="color: ${isThreat ? "var(--red)" : "var(--green)"};">
                ${Number(scan.risk_score ?? 0).toFixed(1)}%
              </strong>
            </td>
            <td style="color: var(--muted); font-size: 0.78rem;">
              ${fmt(scan.created_at)}
            </td>
          </tr>
        `;
      }).join("")
      : `<tr><td colspan="6" class="empty">No security threat events recorded yet.</td></tr>`;
  }
}

/* REFRESH & LOGOUT EVENT HANDLERS */
document.addEventListener("DOMContentLoaded", () => {
  const refreshBtn = $("refresh");
  if (refreshBtn) {
    refreshBtn.onclick = () => {
      refreshBtn.textContent = "↻ Updating...";
      load().finally(() => {
        refreshBtn.textContent = "↻ Refresh Data";
      });
    };
  }

  const logoutBtn = $("logout");
  if (logoutBtn) {
    logoutBtn.onclick = async () => {
      if (sb) await sb.auth.signOut();
      sessionStorage.removeItem("netarmor_profile");
      location.replace("login.html");
    };
  }

  load();
});