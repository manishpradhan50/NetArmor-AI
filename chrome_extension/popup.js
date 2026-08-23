const API_BASE = "http://127.0.0.1:8000";

// Tab Switching
document.getElementById("tab-url-btn").addEventListener("click", () => {
  document.getElementById("tab-url-btn").classList.add("active");
  document.getElementById("tab-email-btn").classList.remove("active");
  document.getElementById("url-view").classList.add("active");
  document.getElementById("email-view").classList.remove("active");
});

document.getElementById("tab-email-btn").addEventListener("click", () => {
  document.getElementById("tab-email-btn").classList.add("active");
  document.getElementById("tab-url-btn").classList.remove("active");
  document.getElementById("email-view").classList.add("active");
  document.getElementById("url-view").classList.remove("active");
});

// URL Scanner Logic
async function scanActiveTab() {
  const urlBox = document.getElementById("url-box");
  const scoreElem = document.getElementById("url-score");
  const badgeElem = document.getElementById("url-badge");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      urlBox.innerText = "Cannot read tab URL";
      return;
    }

    urlBox.innerText = tab.url;

    const response = await fetch(`${API_BASE}/api/predict-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });

    const data = await response.json();
    scoreElem.innerText = `${data.risk_percentage}%`;
    badgeElem.innerText = data.verdict;
    badgeElem.className = data.risk_percentage >= 50 ? "badge danger" : "badge safe";
    scoreElem.style.color = data.risk_percentage >= 50 ? "#ef4444" : "#22c55e";
  } catch (err) {
    scoreElem.innerText = "Offline";
    badgeElem.innerText = "API Offline";
    badgeElem.className = "badge danger";
  }
}

// Email NLP Scanner Logic
async function scanEmailText() {
  const text = document.getElementById("email-input").value.trim();
  if (!text) return alert("Please paste email body text to analyze.");

  const scoreElem = document.getElementById("email-score");
  const badgeElem = document.getElementById("email-badge");
  const btn = document.getElementById("scan-email-btn");

  btn.innerText = "Analyzing...";
  btn.disabled = true;

  try {
    const response = await fetch(`${API_BASE}/api/predict-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text })
    });

    const data = await response.json();
    scoreElem.innerText = `${data.risk_percentage}%`;
    badgeElem.innerText = data.verdict;
    badgeElem.className = data.risk_percentage >= 50 ? "badge danger" : "badge safe";
    scoreElem.style.color = data.risk_percentage >= 50 ? "#ef4444" : "#22c55e";
  } catch (err) {
    scoreElem.innerText = "Offline";
    badgeElem.innerText = "API Offline";
    badgeElem.className = "badge danger";
  } finally {
    btn.innerText = "Analyze Email Text";
    btn.disabled = false;
  }
}

document.getElementById("rescan-url-btn").addEventListener("click", scanActiveTab);
document.getElementById("scan-email-btn").addEventListener("click", scanEmailText);
document.addEventListener("DOMContentLoaded", scanActiveTab);