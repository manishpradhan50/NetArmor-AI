<!DOCTYPE html>
<html lang="en" data-theme="dark">

<head>
  <meta charset="UTF-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >

  <title>NetArmor AI - Security Portal Authentication</title>

  <link
    rel="icon"
    type="image/png"
    href="images/logo.png"
  >

  <link rel="stylesheet" href="home.css">
  <link rel="stylesheet" href="login.css">
</head>

<body>

  <!-- Background -->
  <div class="tunnel-container">
    <div class="laser-scanner"></div>
    <div
      class="cyber-grid"
      id="cyberGrid"
    ></div>
    <div class="radial-center-glow"></div>
  </div>


  <!-- NAVBAR -->
  <header class="navbar-wrapper">

    <div class="navbar">

      <a
        href="index.html"
        class="nav-logo"
      >

        <div class="logo-shield-badge">

          <img
            src="images/logo.png"
            alt="NetArmor AI Logo"
            class="brand-logo-img"
          >

        </div>

        <span>
          NetArmor<span class="logo-accent">AI</span>
        </span>

      </a>


      <a
        href="index.html"
        class="nav-btn-back"
      >
        ← Back to Terminal
      </a>

    </div>

  </header>


  <!-- AUTHENTICATION -->
  <main class="auth-wrapper">


    <!-- ================= LOGIN ================= -->

    <div
      class="auth-card"
      id="loginCard"
    >

      <div class="auth-header">

        <div class="auth-status-badge">
          <span class="badge-dot"></span>
          SECURE GATEWAY
        </div>

        <h2 class="auth-title">
          System Authentication
        </h2>

        <p class="auth-subtitle">
          Verify credentials to access threat inspection services
        </p>

      </div>


      <form
        id="loginForm"
        class="auth-form"
      >


        <!-- ROLE -->

        <div class="form-group">

          <label for="loginRole">
            AUTHORIZATION ROLE
          </label>

          <div class="input-container">

            <span class="input-icon">
              🛡️
            </span>

            <select
              id="loginRole"
              class="auth-input"
              required
            >

              <option
                value="user"
                selected
              >
                User (Standard Analyst)
              </option>

              <option value="associate">
                Associate (Security Engineer)
              </option>

            </select>

          </div>

        </div>


        <!-- EMAIL -->

        <div class="form-group">

          <label for="loginIdentifier">
            EMAIL ADDRESS
          </label>

          <div class="input-container">

            <span class="input-icon">
              👤
            </span>

            <input
              type="email"
              id="loginIdentifier"
              class="auth-input"
              placeholder="Enter your email address"
              autocomplete="email"
              required
            >

          </div>

        </div>


        <!-- PASSWORD -->

        <div class="form-group">

          <label for="loginPassword">
            PASSWORD
          </label>

          <div class="input-container">

            <span class="input-icon">
              🔒
            </span>

            <input
              type="password"
              id="loginPassword"
              class="auth-input"
              placeholder="••••••••••••"
              autocomplete="current-password"
              required
            >

          </div>


          <div class="field-sub-action">

            <a
              href="#forgot"
              class="sub-link"
              id="forgotPassword"
            >
              Forgot Password?
            </a>

          </div>

        </div>


        <!-- LOGIN BUTTON -->

        <button
          type="submit"
          class="auth-btn-primary"
          id="loginBtn"
        >

          <span>
            Login
          </span>

        </button>


        <!-- MESSAGE -->

        <div
          id="loginMessage"
          class="auth-message"
          style="display:none;"
        ></div>

      </form>


      <div class="auth-footer">

        <p>
          Dont have an account?

          <a
            href="#register"
            class="neon-link"
            id="showRegister"
          >
            Sign up
          </a>

        </p>

      </div>

    </div>



    <!-- ================= REGISTER ================= -->

    <div
      class="auth-card hidden"
      id="registerCard"
    >

      <div class="auth-header">

        <div class="auth-status-badge">

          <span class="badge-dot"></span>

          REGISTRATION PORTAL

        </div>


        <h2 class="auth-title">
          Create Account
        </h2>


        <p class="auth-subtitle">
          Public signups are assigned the User role only
        </p>

      </div>


      <form
        id="registerForm"
        class="auth-form"
      >


        <!-- ROLE -->

        <div class="form-group">

          <label>
            ACCOUNT ROLE
          </label>


          <div class="role-locked-pill">

            <span class="pill-dot"></span>

            Standard User

          </div>


          <input
            type="hidden"
            id="registerRole"
            value="user"
          >

        </div>


        <!-- USERNAME -->

        <div class="form-group">

          <label for="regUsername">
            USERNAME
          </label>

          <div class="input-container">

            <span class="input-icon">
              👤
            </span>

            <input
              type="text"
              id="regUsername"
              class="auth-input"
              placeholder="Choose a username"
              autocomplete="username"
              required
            >

          </div>

        </div>


        <!-- EMAIL -->

        <div class="form-group">

          <label for="regEmail">
            EMAIL ADDRESS
          </label>

          <div class="input-container">

            <span class="input-icon">
              ✉️
            </span>

            <input
              type="email"
              id="regEmail"
              class="auth-input"
              placeholder="name@domain.com"
              autocomplete="email"
              required
            >

          </div>

        </div>


        <!-- PASSWORD -->

        <div class="form-group">

          <label for="regPassword">
            PASSWORD
          </label>

          <div class="input-container">

            <span class="input-icon">
              🔒
            </span>

            <input
              type="password"
              id="regPassword"
              class="auth-input"
              placeholder="Create password"
              autocomplete="new-password"
              required
            >

          </div>

        </div>


        <!-- REGISTER -->

        <button
          type="submit"
          class="auth-btn-primary"
          id="registerBtn"
        >

          <span>
            Create Account
          </span>

        </button>


        <div
          id="registerMessage"
          class="auth-message"
          style="display:none;"
        ></div>

      </form>


      <div class="auth-footer">

        <p>

          Already have an account?

          <a
            href="#login"
            class="neon-link"
            id="showLogin"
          >
            Login here
          </a>

        </p>

      </div>

    </div>


  </main>


  <!-- SUPABASE -->

  <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>

  <script src="supabase-config.js"></script>

  <script src="login.js"></script>

</body>

</html>