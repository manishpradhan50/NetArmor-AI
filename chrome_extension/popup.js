const API_BASE = "http://127.0.0.1:8000";

// --- Tab Navigation Switcher ---
function setTab(activeKey) {
  const tabs = ["url", "email", "msg"];
  tabs.forEach((key) => {
    const btn = document.getElementById(`tab-${key}-btn`);
    const view = document.getElementById(`${key}-view`);
    if (btn && view) {
      if (key === activeKey) {
        btn.classList.add("active");
        view.classList.add("active");
      } else {
        btn.classList.remove("active");
        view.classList.remove("active");
      }
    }
  });
}

// 1. Scan Active Tab URL
async function scanActiveTab() {
  const urlBox = document.getElementById("url-box");
  const scoreElem = document.getElementById("url-score");
  const badgeElem = document.getElementById("url-badge");

  if (!urlBox || !scoreElem || !badgeElem) return;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      urlBox.innerText = "Cannot read tab URL";
      return;
    }

    urlBox.innerText = tab.url;

    const res = await fetch(`${API_BASE}/api/predict-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });

    if (!res.ok) throw new Error("API Error");
    const data = await res.json();

    scoreElem.innerText = `${data.risk_percentage}%`;
    badgeElem.innerText = data.verdict;
    badgeElem.className = data.risk_percentage >= 50 ? "badge danger" : "badge safe";
    scoreElem.style.color = data.risk_percentage >= 50 ? "var(--danger)" : "var(--safe)";
  } catch (err) {
    scoreElem.innerText = "Offline";
    badgeElem.innerText = "API Offline";
    badgeElem.className = "badge danger";
    scoreElem.style.color = "var(--danger)";
  }
}

// 2. Scan Email NLP Text
async function scanEmailText() {
  const inputElem = document.getElementById("email-input");
  const scoreElem = document.getElementById("email-score");
  const badgeElem = document.getElementById("email-badge");
  const btn = document.getElementById("scan-email-btn");

  if (!inputElem || !scoreElem || !badgeElem || !btn) return;

  const text = inputElem.value.trim();
  if (!text) return alert("Please paste email body text to analyze.");

  btn.innerText = "Analyzing...";
  btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/api/predict-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });

    if (!res.ok) throw new Error("API Error");
    const data = await res.json();

    scoreElem.innerText = `${data.risk_percentage}%`;
    badgeElem.innerText = data.verdict;
    badgeElem.className = data.risk_percentage >= 50 ? "badge danger" : "badge safe";
    scoreElem.style.color = data.risk_percentage >= 50 ? "var(--danger)" : "var(--safe)";
  } catch (err) {
    scoreElem.innerText = "Offline";
    badgeElem.innerText = "API Offline";
    badgeElem.className = "badge danger";
    scoreElem.style.color = "var(--danger)";
  } finally {
    btn.innerText = "Analyze Email Text";
    btn.disabled = false;
  }
}

// 3. Scan SMS & Social Media Message
async function scanMessageText() {
  const inputElem = document.getElementById("msg-input");
  const scoreElem = document.getElementById("msg-score");
  const badgeElem = document.getElementById("msg-badge");
  const btn = document.getElementById("scan-msg-btn");

  if (!inputElem || !scoreElem || !badgeElem || !btn) return;

  const message = inputElem.value.trim();
  if (!message) return alert("Please paste SMS or message text to analyze.");

  btn.innerText = "Scanning...";
  btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/api/predict-message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });

    if (!res.ok) throw new Error("API Error");
    const data = await res.json();

    scoreElem.innerText = `${data.risk_percentage}%`;
    badgeElem.innerText = data.verdict;
    badgeElem.className = data.risk_percentage >= 50 ? "badge danger" : "badge safe";
    scoreElem.style.color = data.risk_percentage >= 50 ? "var(--danger)" : "var(--safe)";
  } catch (err) {
    scoreElem.innerText = "Offline";
    badgeElem.innerText = "API Offline";
    badgeElem.className = "badge danger";
    scoreElem.style.color = "var(--danger)";
  } finally {
    btn.innerText = "Scan Message";
    btn.disabled = false;
  }
}

// --- Bind Event Listeners ---
document.addEventListener("DOMContentLoaded", () => {
  // Tab Switch Buttons
  const urlTabBtn = document.getElementById("tab-url-btn");
  const emailTabBtn = document.getElementById("tab-email-btn");
  const msgTabBtn = document.getElementById("tab-msg-btn");

  if (urlTabBtn) urlTabBtn.addEventListener("click", () => setTab("url"));
  if (emailTabBtn) emailTabBtn.addEventListener("click", () => setTab("email"));
  if (msgTabBtn) msgTabBtn.addEventListener("click", () => setTab("msg"));

  // Action Buttons
  const rescanBtn = document.getElementById("rescan-url-btn");
  const emailScanBtn = document.getElementById("scan-email-btn");
  const msgScanBtn = document.getElementById("scan-msg-btn");

  if (rescanBtn) rescanBtn.addEventListener("click", scanActiveTab);
  if (emailScanBtn) emailScanBtn.addEventListener("click", scanEmailText);
  if (msgScanBtn) msgScanBtn.addEventListener("click", scanMessageText);

  // Auto-scan current tab URL on popup open
  scanActiveTab();
});