/*
=========================================================
 NetArmor AI - Supabase Configuration
=========================================================

 IMPORTANT:
 Replace the two values below with your own Supabase
 Project URL and Publishable/Anon Key.

 NEVER put the Supabase service_role / secret key here.
 This file is loaded by the browser.
=========================================================
*/

const SUPABASE_URL = "https://gxkwigruwikawfmvmrax.supabase.co";

const SUPABASE_PUBLISHABLE_KEY =
  "sb_publishable_oRjkGcSdMBDVDemVADh_9w_TRue7_T5";


if (!window.supabase) {
    throw new Error(
        "Supabase JavaScript library failed to load."
    );
}


/*
=========================================================
 Create Supabase Client
=========================================================
*/

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


/*
=========================================================
 Make client globally available
=========================================================
*/

window.netarmorSupabase = netarmorSupabase;