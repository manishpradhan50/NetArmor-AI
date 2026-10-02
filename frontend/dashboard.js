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

async function loadDashboard() {
  if (!sb) {
    alert("Supabase is not configured correctly.");
    return;
  }

  const { data: { user }, error: authError } = await sb.auth.getUser();
  if (authError || !user) {
    window.location.replace("login.html");
    return;
  }

  const { data: profile, error: profileError } = await sb
    .from("profiles")
    .select("id, username, full_name, role, email")
    .eq("id", user.id)
    .single();

  if (profileError || !profile) {
    await sb.auth.signOut();
    alert("Your account profile could not be loaded.");
    window.location.replace("login.html");
    return;
  }

  if (profile.role === "associate") {
    window.location.replace("admin-dashboard.html");
    return;
  }

  const displayName = profile.full_name || profile.username || user.email?.split("@")[0] || "User";
  if ($("name")) $("name").textContent = displayName;

  const { data: scans, error: scansError } = await sb
    .from("scan_history")
    .select("id, scan_type, target, result, risk_score, created_at")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false })
    .limit(100);

  if (scansError) {
    console.error("Scan history error:", scansError);
    if ($("history")) $("history").innerHTML = `<tr><td colspan="5" class="empty">Unable to load scan history.</td></tr>`;
    return;
  }

  const rows = scans || [];
  const threats = rows.filter((s) => s.result === "Threat").length;
  const safe = rows.length - threats;

  $("total").textContent = rows.length;
  $("threats").textContent = threats;
  $("safe").textContent = safe;
  $("rate").textContent = rows.length ? `${Math.round((threats / rows.length) * 100)}%` : "0%";

  $("history").innerHTML = rows.length ? rows.map((scan) => `
    <tr>
      <td>${esc(scan.scan_type)}</td>
      <td>${esc(String(scan.target || "").slice(0, 70))}</td>
      <td><span class="badge ${scan.result === "Threat" ? "threat" : "safe"}">${esc(scan.result)}</span></td>
      <td>${Number(scan.risk_score ?? 0).toFixed(2)}%</td>
      <td>${fmt(scan.created_at)}</td>
    </tr>
  `).join("") : `<tr><td colspan="5" class="empty">No scans recorded yet.</td></tr>`;
}

async function logout() {
  if (sb) await sb.auth.signOut();
  sessionStorage.removeItem("netarmor_profile");
  window.location.replace("login.html");
}

document.addEventListener("DOMContentLoaded", () => {
  $("refresh")?.addEventListener("click", loadDashboard);
  $("logout")?.addEventListener("click", logout);
  loadDashboard();
});
