// Dynamic Preloader Diagnostics
window.addEventListener("DOMContentLoaded", () => {
  const skeleton = document.getElementById("skeletonLoader");
  const statusElem = document.getElementById("skeletonStatus");

  const bootStages = [
    "LOADING TF-IDF NLP VECTORIZER...",
    "CALIBRATING XGBOOST MODEL WEIGHTS...",
    "SYNCING THREAT MATRIX & LEXICAL ENGINE...",
    "NETARMOR AI SHIELD ONLINE."
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
  }, 420);
});

// Mobile Hamburger Toggle
const hamburgerBtn = document.getElementById("hamburgerBtn");
const navMenu = document.getElementById("navMenu");

if (hamburgerBtn && navMenu) {
  hamburgerBtn.addEventListener("click", () => {
    hamburgerBtn.classList.toggle("active");
    navMenu.classList.toggle("open");
  });

  navMenu.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      hamburgerBtn.classList.remove("active");
      navMenu.classList.remove("open");
    });
  });
}

// Background Particle Network Canvas Animation
const canvas = document.getElementById("particleCanvas");
if (canvas) {
  const ctx = canvas.getContext("2d");
  let particlesArray = [];
  let w = (canvas.width = window.innerWidth);
  let h = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  });

  class Particle {
    constructor() {
      this.x = Math.random() * w;
      this.y = Math.random() * h;
      this.size = Math.random() * 2 + 1;
      this.speedX = (Math.random() - 0.5) * 0.7;
      this.speedY = (Math.random() - 0.5) * 0.7;
    }
    update() {
      this.x += this.speedX;
      this.y += this.speedY;
      if (this.x < 0 || this.x > w) this.speedX *= -1;
      if (this.y < 0 || this.y > h) this.speedY *= -1;
    }
    draw() {
      ctx.fillStyle = "rgba(0, 210, 255, 0.7)";
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  const particleCount = window.innerWidth < 768 ? 25 : 65;
  for (let i = 0; i < particleCount; i++) {
    particlesArray.push(new Particle());
  }

  function renderParticles() {
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < particlesArray.length; i++) {
      particlesArray[i].update();
      particlesArray[i].draw();

      for (let j = i; j < particlesArray.length; j++) {
        const dx = particlesArray[i].x - particlesArray[j].x;
        const dy = particlesArray[i].y - particlesArray[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 110) {
          ctx.strokeStyle = `rgba(0, 210, 255, ${0.18 - dist / 110 * 0.18})`;
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          ctx.moveTo(particlesArray[i].x, particlesArray[i].y);
          ctx.lineTo(particlesArray[j].x, particlesArray[j].y);
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(renderParticles);
  }
  renderParticles();
}

// Parallax 3D Perspective on Desktop
document.addEventListener("mousemove", (e) => {
  if (window.innerWidth < 768) return;
  const grid = document.getElementById("cyberGrid");
  if (!grid) return;

  const xAxis = (window.innerWidth / 2 - e.pageX) / 30;
  const yAxis = (window.innerHeight / 2 - e.pageY) / 30;

  grid.style.transform = `perspective(600px) rotateX(${45 + yAxis * 0.2}deg) rotateY(${xAxis * 0.2}deg)`;
});

// Scrollspy for Navbar
window.addEventListener("scroll", () => {
  const sections = document.querySelectorAll("section");
  const links = document.querySelectorAll(".nav-link");

  let current = "";
  sections.forEach((section) => {
    const sectionTop = section.offsetTop - 120;
    if (pageYOffset >= sectionTop) {
      current = section.getAttribute("id");
    }
  });

  links.forEach((link) => {
    link.classList.remove("active");
    if (link.getAttribute("href") === `#${current}`) {
      link.classList.add("active");
    }
  });
});