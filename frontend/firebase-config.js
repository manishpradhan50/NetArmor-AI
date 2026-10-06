/* =========================================================
   NetArmor AI - Central Configuration & Google Firebase Client
   ========================================================= */

// Paste your Firebase Web App configuration from Firebase Console:
// Firebase Console -> Project Settings -> General -> Your apps -> Web app SDK setup and configuration
const FIREBASE_CONFIG = {
    apiKey: "AIzaSyDrUh57zOr_lCpzpJwYFAk-bs_OPqyupVI",
    authDomain: "netarmor-ai.firebaseapp.com",
    projectId: "netarmor-ai",
    storageBucket: "netarmor-ai.firebasestorage.app",
    messagingSenderId: "461912490255",
    appId: "1:461912490255:web:bd3412fb2511d5a7f9fe7a",
    measurementId: "G-KBKQ9MMXFJ"
  };

window.FIREBASE_CONFIG = FIREBASE_CONFIG;

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

// Check if credentials have been replaced from placeholders
window.isFirebaseConfigured = function () {
  return (
    FIREBASE_CONFIG.apiKey &&
    !FIREBASE_CONFIG.apiKey.startsWith("YOUR_") &&
    FIREBASE_CONFIG.projectId &&
    !FIREBASE_CONFIG.projectId.startsWith("YOUR_")
  );
};

// Initialize Firebase App & Services
if (typeof firebase !== "undefined") {
  try {
    if (!firebase.apps.length) {
      firebase.initializeApp(FIREBASE_CONFIG);
    }
    window.netarmorAuth = firebase.auth();
    window.netarmorDb = firebase.firestore();
  } catch (err) {
    console.error("NetArmor Firebase initialization error:", err);
  }
} else {
  console.warn("Firebase scripts not yet loaded in window.");
}

// Helper: Promise-based resolution of current authenticated user (resolves initial state)
window.netarmorAuthReady = function () {
  return new Promise((resolve) => {
    if (!window.netarmorAuth) {
      resolve(null);
      return;
    }
    const unsubscribe = window.netarmorAuth.onAuthStateChanged((user) => {
      unsubscribe();
      resolve(user);
    }, () => resolve(null));
  });
};
