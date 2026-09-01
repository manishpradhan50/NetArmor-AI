/* =========================================================
   NetArmor AI - Cyber Green Engine (home.js)
   ========================================================= */

// --- 1. Preloader Diagnostics ---
window.addEventListener("DOMContentLoaded", () => {
  const skeleton = document.getElementById("skeletonLoader");
  const statusElem = document.getElementById("skeletonStatus");

  const bootStages = [
    "LOADING TF-IDF NLP VECTORIZER...",
    "CALIBRATING XGBOOST MODEL WEIGHTS...",
    "SYNCING THREAT MATRIX & HEURISTICS...",
    "NETARMOR AI ACTIVE."
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
  }, 380);
});

// --- 2. Dark & Light Mode Theme Switcher ---
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

// --- 3. Mobile Hamburger Navigation Drawer ---
const hamburgerBtn = document.getElementById("hamburgerBtn");
const navMenu = document.getElementById("navMenu");

if (hamburgerBtn && navMenu) {
  hamburgerBtn.addEventListener("click", () => {
    hamburgerBtn.classList.toggle("active");
    navMenu.classList.toggle("open");
  });

  // Close drawer when any anchor link is tapped
  navMenu.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      hamburgerBtn.classList.remove("active");
      navMenu.classList.remove("open");
    });
  });
}

// --- 4. Synchronized Navbar Indicator Shift & Scrollspy ---
function setupNavbarNavigation() {
  const navLinks = document.querySelectorAll(".nav-link");
  const sections = document.querySelectorAll("section[id]");

  // Immediate indicator shift on click
  navLinks.forEach((link) => {
    link.addEventListener("click", function () {
      navLinks.forEach((l) => l.classList.remove("active"));
      this.classList.add("active");
    });
  });

  // Dynamic shift on scroll
  window.addEventListener("scroll", () => {
    const scrollPos = window.scrollY + 180;
    sections.forEach((section) => {
      const top = section.offsetTop;
      const height = section.offsetHeight;
      const id = section.getAttribute("id");

      if (scrollPos >= top && scrollPos < top + height) {
        navLinks.forEach((link) => {
          if (link.getAttribute("href") === `#${id}`) {
            navLinks.forEach((l) => l.classList.remove("active"));
            link.classList.add("active");
          }
        });
      }
    });
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", setupNavbarNavigation);
} else {
  setupNavbarNavigation();
}

// --- 5. Interactive Green Computer Network Topology Canvas ---
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
    const count = window.innerWidth < 768 ? 24 : 55;
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

          if (Math.random() < 0.002 && packets.length < 18) {
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

// --- 6. 3D Tilt HUD Card Effect ---
const previewCard = document.getElementById("previewCard");
if (previewCard && window.innerWidth >= 768) {
  document.addEventListener("mousemove", (e) => {
    const rect = previewCard.getBoundingClientRect();
    const cardCenterX = rect.left + rect.width / 2;
    const cardCenterY = rect.top + rect.height / 2;

    const angleX = (e.clientY - cardCenterY) / 38;
    const angleY = (cardCenterX - e.clientX) / 38;

    previewCard.style.transform = `rotateX(${Math.max(Math.min(angleX, 7), -7)}deg) rotateY(${Math.max(Math.min(angleY, 7), -7)}deg)`;
  });
}

// --- 7. Real-Time FastAPI Backend Health Check ---
const BACKEND_API = "https://netarmor-ai.onrender.com";

async function checkBackendHealth() {
  const pill = document.getElementById("backendStatusPill");
  const text = document.getElementById("backendStatusText");
  const dot = document.getElementById("backendStatusDot");

  if (!pill || !text || !dot) return;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

    await fetch(`${BACKEND_API}/docs`, {
      method: "GET",
      mode: "no-cors",
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    pill.className = "system-status-pill status-online";
    text.innerText = "Online";
  } catch (error) {
    pill.className = "system-status-pill status-offline";
    text.innerText = "Offline";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  checkBackendHealth();
  setInterval(checkBackendHealth, 5000);
});