/* =========================================================
   NetArmor AI - Scanner Hub Engine (detect.js)
   ========================================================= */

const API_BASE = "http://127.0.0.1:8000";
let selectedPdfFile = null;

// Helper to delay execution for visual scanner feedback
const delay = (ms) => new Promise((res) => setTimeout(res, ms));

// --- 1. Auto-Redirect to index.html on Browser Page Reload ---
const navEntry = performance.getEntriesByType("navigation")[0];
if (navEntry && navEntry.type === "reload") {
  window.location.replace("index.html");
}

// --- 2. Dynamic Radar HUD Preloader Sequence ---
window.addEventListener("DOMContentLoaded", () => {
  const loader = document.getElementById("skeletonLoader");
  const statusElem = document.getElementById("skeletonStatus");
  const counterElem = document.getElementById("telemetryCounter");
  const progressFill = document.getElementById("radarProgressFill");

  const telemetrySteps = [
    { progress: 20, text: "CALIBRATING TOPOLOGY MATRIX..." },
    { progress: 48, text: "STREAMING NLP SEMANTIC WEIGHTS..." },
    { progress: 75, text: "ENGAGING ZERO-DAY XGBOOST CORE..." },
    { progress: 100, text: "RADAR INFERENCE ONLINE." }
  ];

  let step = 0;
  let currentPct = 0;

  const timer = setInterval(() => {
    if (step < telemetrySteps.length) {
      const targetPct = telemetrySteps[step].progress;
      if (currentPct < targetPct) {
        currentPct += 2;
        if (counterElem) counterElem.innerText = `${currentPct < 10 ? "0" + currentPct : currentPct}%`;
        if (progressFill) progressFill.style.width = `${currentPct}%`;
      } else {
        if (statusElem) statusElem.innerText = telemetrySteps[step].text;
        step++;
      }
    } else {
      clearInterval(timer);
      setTimeout(() => {
        if (loader) loader.classList.add("fade-out");
      }, 250);
    }
  }, 35);

  // Auto-switch tab if redirected with ?tab=email, ?tab=url, ?tab=message, or ?tab=document
  const params = new URLSearchParams(window.location.search);
  const requestedTab = params.get("tab");
  if (["url", "email", "message", "document"].includes(requestedTab)) {
    switchTab(requestedTab);
  }

  setupDropZone();
});

// --- 3. Dark & Light Mode Theme Switcher ---
const themeToggleBtn = document.getElementById("themeToggleBtn");
const htmlRoot = document.documentElement;

const savedTheme = localStorage.getItem("netarmor-theme") || "dark";
htmlRoot.setAttribute("data-theme", savedTheme);

if (themeToggleBtn) {
  themeToggleBtn.addEventListener("click", () => {
    const currentTheme = htmlRoot.getAttribute("data-theme");
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    
    htmlRoot.setAttribute("data-theme", nextTheme);
    localStorage.setItem("netarmor-theme", nextTheme);
  });
}

// --- 4. Interactive Tab Switching (4 Modes) ---
function switchTab(type) {
  const tabs = ["url", "email", "message", "document"];
  tabs.forEach((tab) => {
    const tabContent = document.getElementById(`${tab}-tab`);
    const tabBtn = document.getElementById(`tab-btn-${tab}`);
    if (tabContent && tabBtn) {
      if (tab === type) {
        tabContent.classList.add("active");
        tabBtn.classList.add("active");
      } else {
        tabContent.classList.remove("active");
        tabBtn.classList.remove("active");
      }
    }
  });
}

// --- 5. Interactive Green Topology Canvas Animation ---
const canvas = document.getElementById("particleCanvas");
if (canvas) {
  const ctx = canvas.getContext("2d");
  let nodes = [];
  let packets = [];
  let mouse = { x: null, y: null, radius: 140 };

  let w = (canvas.width = window.innerWidth);
  let h = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
    initNetwork();
  });

  window.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  window.addEventListener("mouseout", () => {
    mouse.x = null;
    mouse.y = null;
  });

  class NetworkNode {
    constructor() {
      this.x = Math.random() * w;
      this.y = Math.random() * h;
      this.size = Math.random() * 2.2 + 1.6;
      this.speedX = (Math.random() - 0.5) * 0.4;
      this.speedY = (Math.random() - 0.5) * 0.4;
      this.isHub = Math.random() > 0.88;
    }

    update() {
      this.x += this.speedX;
      this.y += this.speedY;

      if (this.x < 0 || this.x > w) this.speedX *= -1;
      if (this.y < 0 || this.y > h) this.speedY *= -1;

      if (mouse.x && mouse.y) {
        let dx = this.x - mouse.x;
        let dy = this.y - mouse.y;
        let dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          let force = (mouse.radius - dist) / mouse.radius;
          this.x += (dx / dist) * force * 1.8;
          this.y += (dy / dist) * force * 1.8;
        }
      }
    }

    draw(isLight) {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.isHub ? this.size * 1.8 : this.size, 0, Math.PI * 2);

      if (this.isHub) {
        ctx.fillStyle = isLight ? "#059669" : "#00ff88";
        ctx.shadowBlur = 10;
        ctx.shadowColor = isLight ? "rgba(5, 150, 105, 0.8)" : "rgba(0, 255, 136, 0.8)";
      } else {
        ctx.fillStyle = isLight ? "rgba(5, 150, 105, 0.5)" : "rgba(52, 211, 153, 0.6)";
        ctx.shadowBlur = 0;
      }

      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  class DataPacket {
    constructor(nodeA, nodeB) {
      this.nodeA = nodeA;
      this.nodeB = nodeB;
      this.progress = 0;
      this.speed = Math.random() * 0.015 + 0.008;
    }

    update() {
      this.progress += this.speed;
    }

    draw(isLight) {
      let currX = this.nodeA.x + (this.nodeB.x - this.nodeA.x) * this.progress;
      let currY = this.nodeA.y + (this.nodeB.y - this.nodeA.y) * this.progress;

      ctx.beginPath();
      ctx.arc(currX, currY, 2.2, 0, Math.PI * 2);
      ctx.fillStyle = isLight ? "#047857" : "#00ff88";
      ctx.shadowBlur = 8;
      ctx.shadowColor = isLight ? "#047857" : "#00ff88";
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  function initNetwork() {
    nodes = [];
    packets = [];
    const count = window.innerWidth < 768 ? 20 : 50;
    for (let i = 0; i < count; i++) {
      nodes.push(new NetworkNode());
    }
  }
  initNetwork();

  function renderNetwork() {
    ctx.clearRect(0, 0, w, h);
    const isLight = htmlRoot.getAttribute("data-theme") === "light";

    for (let i = 0; i < nodes.length; i++) {
      nodes[i].update();
      nodes[i].draw(isLight);

      for (let j = i + 1; j < nodes.length; j++) {
        let dx = nodes[i].x - nodes[j].x;
        let dy = nodes[i].y - nodes[j].y;
        let dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 130) {
          let alpha = (1 - dist / 130) * 0.2;
          ctx.strokeStyle = isLight 
            ? `rgba(5, 150, 105, ${alpha})` 
            : `rgba(0, 255, 136, ${alpha})`;
          ctx.lineWidth = nodes[i].isHub || nodes[j].isHub ? 1.2 : 0.7;
          
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.stroke();

          if (Math.random() < 0.002 && packets.length < 16) {
            packets.push(new DataPacket(nodes[i], nodes[j]));
          }
        }
      }
    }

    for (let i = packets.length - 1; i >= 0; i--) {
      packets[i].update();
      packets[i].draw(isLight);
      if (packets[i].progress >= 1) {
        packets.splice(i, 1);
      }
    }

    requestAnimationFrame(renderNetwork);
  }
  renderNetwork();
}

// --- 6. URL Scanner API Caller ---
async function analyzeURL() {
  const url = document.getElementById("urlInput").value.trim();
  if (!url) return alert("Please enter a valid website URL to analyze.");

  const scanBtn = document.getElementById("scanUrlBtn");
  scanBtn.innerText = "Analyzing Structural Vectors...";
  scanBtn.disabled = true;

  try {
    const [res] = await Promise.all([
      fetch(`${API_BASE}/api/predict-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      }),
      delay(600)
    ]);
    
    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();

    const box = document.getElementById("urlResult");
    const score = document.getElementById("urlScore");
    const badge = document.getElementById("urlBadge");
    const flags = document.getElementById("urlFlags");

    box.classList.remove("hidden");
    score.innerText = `${data.risk_percentage}% Threat`;
    badge.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      score.style.color = "var(--danger)";
      badge.className = "badge badge-danger";
    } else {
      score.style.color = "var(--safe)";
      badge.className = "badge badge-safe";
    }

    flags.innerHTML = (data.flags && data.flags.length > 0)
      ? data.flags.map(f => `<li>${f}</li>`).join("")
      : "<li>No malicious anomalies detected in URL structure.</li>";

  } catch (err) {
    alert("Backend server offline. Ensure FastAPI is running on port 8000.");
  } finally {
    scanBtn.innerText = "Scan Website URL";
    scanBtn.disabled = false;
  }
}

// --- 7. Email NLP Scanner API Caller ---
async function analyzeEmail() {
  const text = document.getElementById("emailInput").value.trim();
  if (!text) return alert("Please paste the email text to analyze.");

  const scanBtn = document.getElementById("scanEmailBtn");
  scanBtn.innerText = "Running NLP Vectorizer...";
  scanBtn.disabled = true;

  try {
    const [res] = await Promise.all([
      fetch(`${API_BASE}/api/predict-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      }),
      delay(600)
    ]);

    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();

    const box = document.getElementById("emailResult");
    const score = document.getElementById("emailScore");
    const badge = document.getElementById("emailBadge");
    const verdictText = document.getElementById("emailVerdictText");

    box.classList.remove("hidden");
    score.innerText = `${data.risk_percentage}% Phishing Risk`;
    badge.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      score.style.color = "var(--danger)";
      badge.className = "badge badge-danger";
      verdictText.innerText = "High-risk trigger terms, urgent action demands, or credential-harvesting patterns identified.";
    } else {
      score.style.color = "var(--safe)";
      badge.className = "badge badge-safe";
      verdictText.innerText = "Clean content. No manipulative triggers or phishing signatures detected.";
    }

  } catch (err) {
    alert("Backend server offline. Ensure FastAPI is running on port 8000.");
  } finally {
    scanBtn.innerText = "Analyze Email Text";
    scanBtn.disabled = false;
  }
}

// --- 8. SMS & Social Media Smishing Scanner API Caller ---
async function analyzeMessage() {
  const msgInput = document.getElementById("messageInput");
  if (!msgInput) return;
  const message = msgInput.value.trim();
  if (!message) return alert("Please enter the SMS or message content to inspect.");

  const scanBtn = document.getElementById("scanMessageBtn");
  scanBtn.innerText = "Scanning Smishing Vectors...";
  scanBtn.disabled = true;

  try {
    const [res] = await Promise.all([
      fetch(`${API_BASE}/api/predict-message`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
      }),
      delay(600)
    ]);

    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();

    const box = document.getElementById("messageResult");
    const score = document.getElementById("messageScore");
    const badge = document.getElementById("messageBadge");
    const flags = document.getElementById("messageFlags");

    box.classList.remove("hidden");
    score.innerText = `${data.risk_percentage}% Smishing Risk`;
    badge.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      score.style.color = "var(--danger)";
      badge.className = "badge badge-danger";
    } else {
      score.style.color = "var(--safe)";
      badge.className = "badge badge-safe";
    }

    flags.innerHTML = (data.flags && data.flags.length > 0)
      ? data.flags.map(f => `<li>${f}</li>`).join("")
      : "<li>No high-risk smishing or social engineering triggers identified.</li>";

  } catch (err) {
    alert("Backend server offline. Ensure FastAPI is running on port 8000.");
  } finally {
    scanBtn.innerText = "Scan Message Content";
    scanBtn.disabled = false;
  }
}

// --- 9. PDF Document Scanner API Caller & Dropzone Logic ---
function handleFileSelected(e) {
  const file = e.target.files[0];
  if (file) {
    selectedPdfFile = file;
    const title = document.getElementById("dropZoneTitle");
    const sub = document.getElementById("dropZoneSub");
    if (title) title.innerText = `Selected: ${file.name}`;
    if (sub) sub.innerText = `${(file.size / 1024).toFixed(1)} KB • Ready for deep scan`;
  }
}

function setupDropZone() {
  const dropZone = document.getElementById("dropZone");
  if (!dropZone) return;

  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add("drag-active");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.remove("drag-active");
    });
  });

  dropZone.addEventListener("drop", (e) => {
    const file = e.dataTransfer.files[0];
    if (file && file.name.toLowerCase().endsWith(".pdf")) {
      selectedPdfFile = file;
      document.getElementById("dropZoneTitle").innerText = `Selected: ${file.name}`;
      document.getElementById("dropZoneSub").innerText = `${(file.size / 1024).toFixed(1)} KB • Ready for deep scan`;
    } else {
      alert("Only .pdf documents are supported currently.");
    }
  });
}

async function analyzeDocument() {
  if (!selectedPdfFile) return alert("Please select or drop a PDF file first.");

  const scanBtn = document.getElementById("scanDocBtn");
  scanBtn.innerText = "Extracting & Scanning PDF...";
  scanBtn.disabled = true;

  const formData = new FormData();
  formData.append("file", selectedPdfFile);

  try {
    const [res] = await Promise.all([
      fetch(`${API_BASE}/api/scan-document`, {
        method: "POST",
        body: formData
      }),
      delay(800)
    ]);

    if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    const data = await res.json();

    const box = document.getElementById("docResult");
    const score = document.getElementById("docScore");
    const badge = document.getElementById("docBadge");
    const flags = document.getElementById("docFlags");
    const urlsElem = document.getElementById("docExtractedUrls");

    box.classList.remove("hidden");
    score.innerText = `${data.risk_percentage}% Document Risk`;
    badge.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      score.style.color = "var(--danger)";
      badge.className = "badge badge-danger";
    } else {
      score.style.color = "var(--safe)";
      badge.className = "badge badge-safe";
    }

    flags.innerHTML = (data.flags && data.flags.length > 0)
      ? data.flags.map(f => `<li>${f}</li>`).join("")
      : "<li>No executable triggers or malicious signals found inside document.</li>";

    if (urlsElem) {
      if (data.extracted_urls && data.extracted_urls.length > 0) {
        urlsElem.innerHTML = `<strong>Embedded Hyperlinks Found (${data.extracted_urls.length}):</strong><br>` +
          data.extracted_urls.slice(0, 3).map(u => `• ${u}`).join("<br>");
      } else {
        urlsElem.innerHTML = "";
      }
    }

  } catch (err) {
    alert("Backend server offline. Ensure FastAPI is running on port 8000.");
  } finally {
    scanBtn.innerText = "Scan Uploaded PDF";
    scanBtn.disabled = false;
  }
}

// --- 10. Live Backend Health Status Poller ---
async function checkBackendHealth() {
  const pill = document.getElementById("backendStatusPill");
  const text = document.getElementById("backendStatusText");
  const dot = document.getElementById("backendStatusDot");

  if (!pill || !text || !dot) return;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

    const res = await fetch(`${API_BASE}/`, {
      method: "GET",
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    if (res.ok) {
      pill.className = "system-status-pill status-online";
      text.innerText = "Online";
    } else {
      throw new Error();
    }
  } catch (error) {
    pill.className = "system-status-pill status-offline";
    text.innerText = "Offline";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  checkBackendHealth();
  setInterval(checkBackendHealth, 5000);
});

// =========================================================
// ArmorBot AI Assistant Integration
// =========================================================
const chatToggleBtn = document.getElementById("chatToggleBtn");
const chatWindow = document.getElementById("chatWindow");
const closeChatBtn = document.getElementById("closeChatBtn");
const sendChatBtn = document.getElementById("sendChatBtn");
const chatInput = document.getElementById("chatInput");
const chatMessages = document.getElementById("chatMessages");

if (chatToggleBtn && chatWindow) {
  chatToggleBtn.addEventListener("click", () => {
    chatWindow.classList.toggle("hidden");
    if (!chatWindow.classList.contains("hidden") && chatInput) {
      chatInput.focus();
    }
  });
}

if (closeChatBtn && chatWindow) {
  closeChatBtn.addEventListener("click", () => {
    chatWindow.classList.add("hidden");
  });
}

async function handleSendMessage() {
  if (!chatInput) return;
  const userText = chatInput.value.trim();
  if (!userText) return;

  // Render User Message
  const userBubble = document.createElement("div");
  userBubble.className = "user-msg";
  userBubble.innerText = userText;
  chatMessages.appendChild(userBubble);
  chatInput.value = "";
  chatMessages.scrollTop = chatMessages.scrollHeight;

  // Render Placeholder Shimmer Bubble
  const botBubble = document.createElement("div");
  botBubble.className = "bot-msg loading-shimmer";
  botBubble.innerText = "⚡ ArmorBot is analyzing...";
  chatMessages.appendChild(botBubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;

  try {
    const response = await fetch(`${API_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: userText })
    });

    if (!response.ok) throw new Error("API request failed");
    const data = await response.json();

    botBubble.className = "bot-msg";
    botBubble.innerText = data.reply || "No response received.";
  } catch (error) {
    botBubble.className = "bot-msg";
    botBubble.innerText = "⚠️ Unable to reach ArmorBot core. Ensure FastAPI is running and your GEMINI_API_KEY is configured.";
  }

  chatMessages.scrollTop = chatMessages.scrollHeight;
}

if (sendChatBtn) {
  sendChatBtn.addEventListener("click", handleSendMessage);
}

if (chatInput) {
  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleSendMessage();
    }
  });
}