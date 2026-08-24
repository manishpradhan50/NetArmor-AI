const API_BASE = "http://127.0.0.1:8000";

// 1. Auto-Redirect to index.html on page reload
const navEntry = performance.getEntriesByType("navigation")[0];
if (navEntry && navEntry.type === "reload") {
  window.location.replace("index.html");
}

// 2. Preloader Skeleton Boot Sequence
window.addEventListener("DOMContentLoaded", () => {
  const skeleton = document.getElementById("skeletonLoader");
  const statusElem = document.getElementById("skeletonStatus");

  const bootStages = [
    "LOADING DIAGNOSTIC INTERFACE...",
    "CONNECTING ML INFERENCE ENGINE...",
    "RADAR HUB READY."
  ];

  let stage = 0;
  const interval = setInterval(() => {
    stage++;
    if (stage < bootStages.length && statusElem) {
      statusElem.innerText = bootStages[stage];
    } else {
      clearInterval(interval);
      if (skeleton) {
        skeleton.classList.add("fade-out");
      }
    }
  }, 320);

  const params = new URLSearchParams(window.location.search);
  const requestedTab = params.get("tab");
  if (requestedTab === "email") {
    switchTab("email");
  }
});

// Tab Switching Logic
function switchTab(type) {
  const urlTab = document.getElementById("url-tab");
  const emailTab = document.getElementById("email-tab");
  const urlBtn = document.getElementById("tab-btn-url");
  const emailBtn = document.getElementById("tab-btn-email");

  if (type === "url") {
    urlTab.classList.add("active");
    emailTab.classList.remove("active");
    urlBtn.classList.add("active");
    emailBtn.classList.remove("active");
  } else {
    emailTab.classList.add("active");
    urlTab.classList.remove("active");
    emailBtn.classList.add("active");
    urlBtn.classList.remove("active");
  }
}

// Helper to delay execution for visual scanner feedback
const delay = (ms) => new Promise((res) => setTimeout(res, ms));

// URL Scanner API Caller with Skeleton Loading State
async function analyzeURL() {
  const urlInput = document.getElementById("urlInput");
  const url = urlInput.value.trim();
  if (!url) return alert("Please enter a valid URL to analyze.");

  const scanBtn = document.getElementById("scanUrlBtn");
  const btnText = scanBtn.querySelector(".btn-text");
  const btnSpinner = scanBtn.querySelector(".btn-spinner");
  const scanningCard = document.getElementById("urlScanningState");
  const resultBox = document.getElementById("urlResult");

  // Activate In-Card Loading State
  btnText.innerText = "Analyzing Structural Vectors...";
  btnSpinner.classList.remove("hidden");
  scanBtn.disabled = true;
  resultBox.classList.add("hidden");
  scanningCard.classList.remove("hidden");

  try {
    // Run fetch in parallel with minimum 800ms presentation delay
    const [response] = await Promise.all([
      fetch(`${API_BASE}/api/predict-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      }),
      delay(800)
    ]);

    if (!response.ok) throw new Error("Server error");
    const data = await response.json();

    const score = document.getElementById("urlScore");
    const badge = document.getElementById("urlBadge");
    const flags = document.getElementById("urlFlags");

    score.innerText = `${data.risk_percentage}% Threat`;
    badge.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      score.style.color = "#ef4444";
      badge.className = "badge badge-danger";
    } else {
      score.style.color = "#22c55e";
      badge.className = "badge badge-safe";
    }

    flags.innerHTML = (data.flags || ["No high-risk flags."]).map((f) => `<li>${f}</li>`).join("");

    // Hide scanner skeleton and reveal results
    scanningCard.classList.add("hidden");
    resultBox.classList.remove("hidden");
  } catch (err) {
    scanningCard.classList.add("hidden");
    alert("Backend server offline. Ensure FastAPI is running on port 8000.");
  } finally {
    btnText.innerText = "Scan Website URL";
    btnSpinner.classList.add("hidden");
    scanBtn.disabled = false;
  }
}

// Email NLP Scanner API Caller with Skeleton Loading State
async function analyzeEmail() {
  const emailInput = document.getElementById("emailInput");
  const text = emailInput.value.trim();
  if (!text) return alert("Please paste email body text to analyze.");

  const scanBtn = document.getElementById("scanEmailBtn");
  const btnText = scanBtn.querySelector(".btn-text");
  const btnSpinner = scanBtn.querySelector(".btn-spinner");
  const scanningCard = document.getElementById("emailScanningState");
  const resultBox = document.getElementById("emailResult");

  // Activate In-Card Loading State
  btnText.innerText = "Running NLP Vectorizer...";
  btnSpinner.classList.remove("hidden");
  scanBtn.disabled = true;
  resultBox.classList.add("hidden");
  scanningCard.classList.remove("hidden");

  try {
    const [response] = await Promise.all([
      fetch(`${API_BASE}/api/predict-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      }),
      delay(800)
    ]);

    if (!response.ok) throw new Error("Server error");
    const data = await response.json();

    const score = document.getElementById("emailScore");
    const badge = document.getElementById("emailBadge");
    const verdictText = document.getElementById("emailVerdictText");

    score.innerText = `${data.risk_percentage}% Phishing Risk`;
    badge.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      score.style.color = "#ef4444";
      badge.className = "badge badge-danger";
      verdictText.innerText = "High-risk trigger terms and urgency patterns detected in content.";
    } else {
      score.style.color = "#22c55e";
      badge.className = "badge badge-safe";
      verdictText.innerText = "Clean content. No manipulative triggers or phishing patterns detected.";
    }

    // Hide scanner skeleton and reveal results
    scanningCard.classList.add("hidden");
    resultBox.classList.remove("hidden");
  } catch (err) {
    scanningCard.classList.add("hidden");
    alert("Backend server offline. Ensure FastAPI is running on port 8000.");
  } finally {
    btnText.innerText = "Analyze Email Text";
    btnSpinner.classList.add("hidden");
    scanBtn.disabled = false;
  }
}