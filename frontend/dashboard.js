const sb = window.netarmorSupabase;
const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[c]);
}

function fmt(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function formatScanType(type) {
  switch (type) {
    case "url": return "🌐 URL";
    case "email": return "✉️ Email";
    case "message": return "💬 SMS";
    case "document": return "📄 PDF";
    default: return esc(type || "General");
  }
}

async function loadDashboard() {
  if (!sb) {
    alert("Supabase client not initialized. Check supabase-config.js.");
    return;
  }

  const { data: { user }, error: authError } = await sb.auth.getUser();
  if (authError || !user) {
    window.location.replace("login.html");
    return;
  }

  // Fetch or self-heal profile
  let { data: profile } = await sb
    .from("profiles")
    .select("id, username, full_name, role, email")
    .eq("id", user.id)
    .maybeSingle();

  if (!profile) {
    const defaultUsername = user.user_metadata?.username || user.email?.split("@")[0] || `user_${user.id.slice(0, 6)}`;
    try {
      const { data: newProfile } = await sb
        .from("profiles")
        .insert({
          id: user.id,
          username: defaultUsername,
          email: user.email,
          role: "user"
        })
        .select()
        .maybeSingle();
      profile = newProfile || { id: user.id, username: defaultUsername, role: "user", email: user.email };
    } catch (_) {
      profile = { id: user.id, username: defaultUsername, role: "user", email: user.email };
    }
  }

  // Redirect associate to Admin Console
  if (profile.role === "associate") {
    window.location.replace("admin-dashboard.html");
    return;
  }

  // Display user identity
  const displayName = profile.full_name || profile.username || user.email?.split("@")[0] || "User";
  if ($("name")) $("name").textContent = displayName;
  if ($("userEmail")) $("userEmail").textContent = `Logged in as: ${user.email || profile.email || "Authenticated User"}`;
  if ($("userRoleBadge")) {
    $("userRoleBadge").textContent = "Standard Analyst";
    $("userRoleBadge").style.display = "inline-block";
  }

  // Show loading indicator in table
  if ($("history")) {
    $("history").innerHTML = `<tr><td colspan="5" class="empty">Scanning telemetry database...</td></tr>`;
  }

  // Fetch user scans
  const { data: scans, error: scansError } = await sb
    .from("scan_history")
    .select("id, scan_type, target, result, risk_score, created_at")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false })
    .limit(100);

  if (scansError) {
    console.error("Scan history error:", scansError);
    if ($("history")) $("history").innerHTML = `<tr><td colspan="5" class="empty">Unable to load scan history. Click 'Refresh' to retry.</td></tr>`;
    return;
  }

  const rows = scans || [];
  const threats = rows.filter((s) => s.result === "Threat").length;
  const safe = rows.length - threats;

  if ($("total")) $("total").textContent = rows.length;
  if ($("threats")) $("threats").textContent = threats;
  if ($("safe")) $("safe").textContent = safe;
  if ($("rate")) $("rate").textContent = rows.length ? `${Math.round((threats / rows.length) * 100)}%` : "0%";

  if ($("history")) {
    $("history").innerHTML = rows.length ? rows.map((scan) => `
      <tr>
        <td><strong>${formatScanType(scan.scan_type)}</strong></td>
        <td title="${esc(scan.target)}" style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${esc(String(scan.target || "").slice(0, 65))}${String(scan.target || "").length > 65 ? "…" : ""}
        </td>
        <td><span class="badge ${scan.result === "Threat" ? "threat" : "safe"}">${esc(scan.result)}</span></td>
        <td><strong>${Number(scan.risk_score ?? 0).toFixed(1)}%</strong></td>
        <td style="color: var(--muted);">${fmt(scan.created_at)}</td>
      </tr>
    `).join("") : `
      <tr>
        <td colspan="5" class="empty">
          No threat scans recorded yet. <br>
          <a href="detect.html" style="color: var(--green); text-decoration: underline; display: inline-block; margin-top: 8px;">Run your first security scan →</a>
        </td>
      </tr>
    `;
  }
}

async function logout() {
  if (sb) await sb.auth.signOut();
  sessionStorage.removeItem("netarmor_profile");
  window.location.replace("login.html");
}

document.addEventListener("DOMContentLoaded", () => {
  $("refresh")?.addEventListener("click", () => {
    if ($("refresh")) $("refresh").textContent = "↻ Updating...";
    loadDashboard().finally(() => {
      if ($("refresh")) $("refresh").textContent = "↻ Refresh";
    });
  });
  $("logout")?.addEventListener("click", logout);
  loadDashboard();
});
