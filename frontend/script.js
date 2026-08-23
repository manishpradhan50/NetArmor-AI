/* =========================================================
   NetArmor AI - Frontend Client Logic
   Connects UI to FastAPI REST Endpoints
   ========================================================= */

const API_BASE = "http://127.0.0.1:8000";

// --- 1. Website URL Structural Scanner ---
async function analyzeURL() {
  const urlInput = document.getElementById("urlInput");
  const url = urlInput.value.trim();

  if (!url) {
    alert("Please enter a valid website URL to analyze.");
    return;
  }

  const scanBtn = document.getElementById("scanUrlBtn");
  const resultBox = document.getElementById("urlResult");
  const scoreElem = document.getElementById("urlScore");
  const badgeElem = document.getElementById("urlBadge");
  const flagsElem = document.getElementById("urlFlags");

  // Loading State
  scanBtn.innerText = "Analyzing Structural Vectors...";
  scanBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE}/api/predict-url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`Server returned status: ${response.status}`);
    }

    const data = await response.json();

    // Display Results
    resultBox.classList.remove("hidden");
    scoreElem.innerText = `${data.risk_percentage}% Threat`;
    badgeElem.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      scoreElem.style.color = "#ef4444";
      badgeElem.className = "badge badge-danger";
    } else {
      scoreElem.style.color = "#22c55e";
      badgeElem.className = "badge badge-safe";
    }

    // Render Detection Flags
    if (data.flags && data.flags.length > 0) {
      flagsElem.innerHTML = data.flags.map(flag => `<li>${flag}</li>`).join("");
    } else {
      flagsElem.innerHTML = "<li>No malicious anomalies detected.</li>";
    }

  } catch (error) {
    console.error("URL Analysis Error:", error);
    alert("Unable to reach backend API. Make sure FastAPI server is running on http://127.0.0.1:8000");
  } finally {
    scanBtn.innerText = "Scan Website URL";
    scanBtn.disabled = false;
  }
}

// --- 2. Email Content NLP Scanner (TF-IDF + XGBoost) ---
async function analyzeEmail() {
  const emailInput = document.getElementById("emailInput");
  const text = emailInput.value.trim();

  if (!text) {
    alert("Please paste email message text to analyze.");
    return;
  }

  const scanBtn = document.getElementById("scanEmailBtn");
  const resultBox = document.getElementById("emailResult");
  const scoreElem = document.getElementById("emailScore");
  const badgeElem = document.getElementById("emailBadge");
  const verdictText = document.getElementById("emailVerdictText");

  // Loading State
  scanBtn.innerText = "Running NLP Vectorizer...";
  scanBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE}/api/predict-email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ text: text })
    });

    if (!response.ok) {
      throw new Error(`Server returned status: ${response.status}`);
    }

    const data = await response.json();

    // Display Results
    resultBox.classList.remove("hidden");
    scoreElem.innerText = `${data.risk_percentage}% Risk`;
    badgeElem.innerText = data.verdict;

    if (data.risk_percentage >= 50) {
      scoreElem.style.color = "#ef4444";
      badgeElem.className = "badge badge-danger";
      verdictText.innerText = "Suspicious phrasing, urgent action prompts, or credential-harvesting signatures identified.";
    } else {
      scoreElem.style.color = "#22c55e";
      badgeElem.className = "badge badge-safe";
      verdictText.innerText = "Clean content. No manipulative triggers or phishing patterns detected.";
    }

  } catch (error) {
    console.error("Email NLP Analysis Error:", error);
    alert("Unable to reach backend API. Make sure FastAPI server is running on http://127.0.0.1:8000");
  } finally {
    scanBtn.innerText = "Analyze Email Text";
    scanBtn.disabled = false;
  }
}