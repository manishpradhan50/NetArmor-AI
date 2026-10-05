/*
=========================================================
 NetArmor AI - Central Configuration & Supabase Client
=========================================================
*/

const SUPABASE_URL = "https://gxkwigruwikawfmvmrax.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_oRjkGcSdMBDVDemVADh_9w_TRue7_T5";

// Shared Backend API Config
window.NETARMOR_CONFIG = {
  LOCAL_API: "http://127.0.0.1:8000",
  CLOUD_API: "https://netarmor-ai.onrender.com",
  activeApi: null
};

// Auto-resolves fastest online backend (Localhost if active, else Render cloud)
window.resolveNetArmorApi = async function () {
  if (window.NETARMOR_CONFIG.activeApi) {
    return window.NETARMOR_CONFIG.activeApi;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 800);
    const res = await fetch("http://127.0.0.1:8000/api/health", {
      method: "GET",
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (res.ok) {
      window.NETARMOR_CONFIG.activeApi = "http://127.0.0.1:8000";
      return window.NETARMOR_CONFIG.activeApi;
    }
  } catch (_) {
    // Local offline
  }

  window.NETARMOR_CONFIG.activeApi = window.NETARMOR_CONFIG.CLOUD_API;
  return window.NETARMOR_CONFIG.activeApi;
};

// Initialize Supabase Client
if (window.supabase) {
  try {
    const netarmorSupabase = window.supabase.createClient(
      SUPABASE_URL,
      SUPABASE_PUBLISHABLE_KEY,
      {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true
        }
      }
    );
    window.netarmorSupabase = netarmorSupabase;
  } catch (err) {
    console.error("NetArmor Supabase initialization error:", err);
  }
} else {
  console.warn("Supabase library not yet loaded in window.");
}