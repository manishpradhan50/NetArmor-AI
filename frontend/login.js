/* =========================================================
   NETARMOR AI
   SUPABASE AUTHENTICATION
   login.js
   ========================================================= */


/* =========================================================
   SUPABASE CLIENT
   ========================================================= */

const supabaseClient = window.netarmorSupabase;


/* =========================================================
   CHECK SUPABASE CONFIGURATION
   ========================================================= */

if (!supabaseClient) {
    console.error(
        "NetArmor AI: Supabase client was not initialized."
    );

    alert(
        "Supabase configuration is missing. Please check supabase-config.js."
    );
}


/* =========================================================
   DOM ELEMENTS
   ========================================================= */

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");

const loginCard = document.getElementById("loginCard");
const registerCard = document.getElementById("registerCard");

const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");

const loginMessage = document.getElementById("loginMessage");
const registerMessage = document.getElementById("registerMessage");

const showRegisterBtn = document.getElementById("showRegister");
const showLoginBtn = document.getElementById("showLogin");

/*
   IMPORTANT:
   Your HTML uses "forgotPasswordLink",
   not "forgotPassword".
*/
const forgotPasswordBtn =
    document.getElementById("forgotPasswordLink");


/* =========================================================
   FORM SWITCHING
   ========================================================= */

function showLogin() {

    if (!loginCard || !registerCard) {
        return;
    }

    registerCard.classList.add("hidden");
    loginCard.classList.remove("hidden");

    clearMessages();
}


function showRegister() {

    if (!loginCard || !registerCard) {
        return;
    }

    loginCard.classList.add("hidden");
    registerCard.classList.remove("hidden");

    clearMessages();
}


/* =========================================================
   FORM SWITCH BUTTONS
   ========================================================= */

if (showRegisterBtn) {

    showRegisterBtn.addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            window.location.hash = "register";

            showRegister();
        }
    );
}


if (showLoginBtn) {

    showLoginBtn.addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            window.location.hash = "login";

            showLogin();
        }
    );
}


/* =========================================================
   MESSAGE FUNCTIONS
   ========================================================= */

function clearMessages() {

    if (loginMessage) {

        loginMessage.style.display = "none";
        loginMessage.textContent = "";
    }

    if (registerMessage) {

        registerMessage.style.display = "none";
        registerMessage.textContent = "";
    }
}


function showLoginMessage(
    message,
    type = "error"
) {

    if (!loginMessage) {
        return;
    }

    loginMessage.style.display = "block";
    loginMessage.textContent = message;

    if (type === "success") {

        loginMessage.style.color = "#00ff88";

    } else {

        loginMessage.style.color = "#ff6b81";
    }
}


function showRegisterMessage(
    message,
    type = "error"
) {

    if (!registerMessage) {
        return;
    }

    registerMessage.style.display = "block";
    registerMessage.textContent = message;

    if (type === "success") {

        registerMessage.style.color = "#00ff88";

    } else {

        registerMessage.style.color = "#ff6b81";
    }
}


/* =========================================================
   ROLE NAME HELPER
   ========================================================= */

function getRoleName(role) {

    if (role === "associate") {
        return "Associate Security Engineer";
    }

    return "Standard User";
}


/* =========================================================
   LOGIN
   ========================================================= */

if (loginForm) {

    loginForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();

            clearMessages();


            /* ---------------------------------------------
               GET INPUT VALUES
            --------------------------------------------- */

            const roleElement =
                document.getElementById("loginRole");

            /*
               IMPORTANT FIX:
               HTML uses loginEmail.
               The old JavaScript incorrectly used
               loginIdentifier.
            */
            const emailElement =
                document.getElementById("loginEmail");

            const passwordElement =
                document.getElementById("loginPassword");


            const selectedRole =
                roleElement
                    ? roleElement.value
                    : "user";


            const email =
                emailElement
                    ? emailElement.value.trim()
                    : "";


            const password =
                passwordElement
                    ? passwordElement.value
                    : "";


            /* ---------------------------------------------
               VALIDATION
            --------------------------------------------- */

            if (!email) {

                showLoginMessage(
                    "Please enter your email address."
                );

                if (emailElement) {
                    emailElement.focus();
                }

                return;
            }


            if (!password) {

                showLoginMessage(
                    "Please enter your password."
                );

                if (passwordElement) {
                    passwordElement.focus();
                }

                return;
            }


            if (!supabaseClient) {

                showLoginMessage(
                    "Supabase is not configured correctly."
                );

                return;
            }


            /* ---------------------------------------------
               DISABLE LOGIN BUTTON
            --------------------------------------------- */

            if (loginBtn) {

                loginBtn.disabled = true;

                loginBtn.dataset.originalText =
                    loginBtn.innerText;

                loginBtn.innerText =
                    "Authenticating...";
            }


            try {

                /* =========================================
                   STEP 1
                   SIGN IN WITH SUPABASE
                ========================================= */

                const {
                    data: authData,
                    error: authError
                } =
                    await supabaseClient.auth.signInWithPassword({

                        email: email,
                        password: password

                    });


                if (authError) {

                    throw new Error(
                        authError.message
                    );
                }


                if (
                    !authData ||
                    !authData.user
                ) {

                    throw new Error(
                        "Login failed. Supabase did not return a user."
                    );
                }


                const user = authData.user;


                /* =========================================
                   STEP 2
                   GET USER PROFILE
                ========================================= */

                const {
                    data: profile,
                    error: profileError
                } =
                    await supabaseClient
                        .from("profiles")
                        .select(
                            "id, username, role, full_name"
                        )
                        .eq(
                            "id",
                            user.id
                        )
                        .single();


                if (profileError) {

                    console.error(
                        "Profile lookup error:",
                        profileError
                    );


                    /*
                     * Sign out if authentication worked
                     * but the profile is missing.
                     */

                    await supabaseClient.auth.signOut();


                    throw new Error(
                        "Your account profile could not be found. Please contact the administrator."
                    );
                }


                if (!profile) {

                    await supabaseClient.auth.signOut();

                    throw new Error(
                        "No profile exists for this account."
                    );
                }


                /* =========================================
                   STEP 3
                   NORMALIZE ROLE
                ========================================= */

                const databaseRole =
                    String(
                        profile.role || ""
                    )
                        .trim()
                        .toLowerCase();


                /* =========================================
                   STEP 4
                   VALIDATE ROLE
                ========================================= */

                if (
                    databaseRole !== "user" &&
                    databaseRole !== "associate"
                ) {

                    await supabaseClient.auth.signOut();

                    throw new Error(
                        "Your account has an invalid security role. Please contact the administrator."
                    );
                }


                /* =========================================
                   STEP 5
                   CHECK SELECTED ROLE
                ========================================= */

                if (
                    selectedRole !== databaseRole
                ) {

                    await supabaseClient.auth.signOut();

                    throw new Error(
                        `Role mismatch. This account is registered as "${getRoleName(databaseRole)}". Please select the correct role.`
                    );
                }


                /* =========================================
                   STEP 6
                   SAVE USER PROFILE
                ========================================= */

                const profileToStore = {

                    id: profile.id,

                    username: profile.username,

                    role: databaseRole,

                    full_name:
                        profile.full_name || "",

                    email:
                        user.email || ""
                };


                sessionStorage.setItem(
                    "netarmor_profile",
                    JSON.stringify(
                        profileToStore
                    )
                );


                /* =========================================
                   STEP 7
                   ROLE-BASED REDIRECTION
                ========================================= */

                if (
                    databaseRole === "associate"
                ) {

                    /*
                     * ASSOCIATE / ADMIN
                     */

                    window.location.replace(
                        "admin-dashboard.html"
                    );

                } else {

                    /*
                     * STANDARD USER
                     */

                    window.location.replace(
                        "dashboard.html"
                    );
                }

            }

            catch (error) {

                console.error(
                    "NetArmor login error:",
                    error
                );


                showLoginMessage(
                    error.message ||
                    "Login failed. Please check your credentials."
                );
            }

            finally {

                if (loginBtn) {

                    loginBtn.disabled = false;

                    loginBtn.innerText =
                        loginBtn.dataset.originalText ||
                        "Login";
                }
            }
        }
    );
}


/* =========================================================
   REGISTRATION
   ========================================================= */

if (registerForm) {

    registerForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();

            clearMessages();


            /* ---------------------------------------------
               GET INPUTS
            --------------------------------------------- */

            const usernameElement =
                document.getElementById("regUsername");

            const emailElement =
                document.getElementById("regEmail");

            const passwordElement =
                document.getElementById("regPassword");


            const username =
                usernameElement
                    ? usernameElement.value.trim()
                    : "";


            const email =
                emailElement
                    ? emailElement.value.trim()
                    : "";


            const password =
                passwordElement
                    ? passwordElement.value
                    : "";


            /* ---------------------------------------------
               VALIDATION
            --------------------------------------------- */

            if (!username) {

                showRegisterMessage(
                    "Please enter a username."
                );

                if (usernameElement) {
                    usernameElement.focus();
                }

                return;
            }


            if (username.length < 3) {

                showRegisterMessage(
                    "Username must contain at least 3 characters."
                );

                if (usernameElement) {
                    usernameElement.focus();
                }

                return;
            }


            if (!email) {

                showRegisterMessage(
                    "Please enter your email address."
                );

                if (emailElement) {
                    emailElement.focus();
                }

                return;
            }


            if (!password) {

                showRegisterMessage(
                    "Please create a password."
                );

                if (passwordElement) {
                    passwordElement.focus();
                }

                return;
            }


            /*
               Match the HTML requirement:
               minimum 8 characters.
            */

            if (password.length < 8) {

                showRegisterMessage(
                    "Password must contain at least 8 characters."
                );

                if (passwordElement) {
                    passwordElement.focus();
                }

                return;
            }


            if (!supabaseClient) {

                showRegisterMessage(
                    "Supabase is not configured correctly."
                );

                return;
            }


            /* ---------------------------------------------
               DISABLE REGISTER BUTTON
            --------------------------------------------- */

            if (registerBtn) {

                registerBtn.disabled = true;

                registerBtn.dataset.originalText =
                    registerBtn.innerText;

                registerBtn.innerText =
                    "Creating Account...";
            }


            try {

                /* =========================================
                   CREATE SUPABASE ACCOUNT
                ========================================= */

                const {
                    data,
                    error
                } =
                    await supabaseClient.auth.signUp({

                        email: email,

                        password: password,

                        options: {

                            data: {

                                username:
                                    username,

                                role: "user"
                            }
                        }
                    });


                if (error) {

                    throw new Error(
                        error.message
                    );
                }


                console.log(
                    "NetArmor registration:",
                    data
                );


                /*
                 * Public registration always creates
                 * a STANDARD USER.
                 *
                 * Associate/Admin accounts must be
                 * promoted manually in Supabase.
                 */


                /*
                 * If email confirmation is enabled,
                 * Supabase will not immediately provide
                 * a session.
                 */

                if (
                    data &&
                    data.user &&
                    !data.session
                ) {

                    showRegisterMessage(
                        "Account created successfully. Please check your email and confirm your account before logging in.",
                        "success"
                    );

                } else {

                    showRegisterMessage(
                        "Account created successfully. You can now log in.",
                        "success"
                    );
                }


                /* -----------------------------------------
                   RETURN TO LOGIN
                ----------------------------------------- */

                setTimeout(
                    function () {

                        showLogin();


                        /*
                         * Put registered email into
                         * the correct login field.
                         */

                        const loginEmail =
                            document.getElementById(
                                "loginEmail"
                            );


                        if (loginEmail) {

                            loginEmail.value =
                                email;
                        }


                        /*
                         * Standard user is the
                         * default registration role.
                         */

                        const loginRole =
                            document.getElementById(
                                "loginRole"
                            );


                        if (loginRole) {

                            loginRole.value =
                                "user";
                        }


                        const loginPassword =
                            document.getElementById(
                                "loginPassword"
                            );


                        if (loginPassword) {

                            loginPassword.value =
                                "";
                        }

                    },
                    1500
                );

            }

            catch (error) {

                console.error(
                    "NetArmor registration error:",
                    error
                );


                showRegisterMessage(
                    error.message ||
                    "Registration failed. Please try again."
                );
            }

            finally {

                if (registerBtn) {

                    registerBtn.disabled = false;

                    registerBtn.innerText =
                        registerBtn.dataset.originalText ||
                        "Create Account";
                }
            }
        }
    );
}


/* =========================================================
   FORGOT PASSWORD
   ========================================================= */

if (forgotPasswordBtn) {

    forgotPasswordBtn.addEventListener(
        "click",
        async function (event) {

            event.preventDefault();

            clearMessages();


            /*
             * IMPORTANT FIX:
             * Your HTML uses loginEmail.
             */

            const emailElement =
                document.getElementById(
                    "loginEmail"
                );


            const email =
                emailElement
                    ? emailElement.value.trim()
                    : "";


            if (!email) {

                showLoginMessage(
                    "Please enter your email address first."
                );


                if (emailElement) {
                    emailElement.focus();
                }


                return;
            }


            if (!supabaseClient) {

                showLoginMessage(
                    "Supabase is not configured correctly."
                );

                return;
            }


            try {

                /* =========================================
                   PASSWORD RESET
                ========================================= */

                const {
                    error
                } =
                    await supabaseClient.auth
                        .resetPasswordForEmail(
                            email,
                            {

                                redirectTo:
                                    `${window.location.origin}/frontend/update-password.html`

                            }
                        );


                if (error) {

                    throw new Error(
                        error.message
                    );
                }


                showLoginMessage(
                    "Password reset instructions have been sent to your email.",
                    "success"
                );

            }

            catch (error) {

                console.error(
                    "Password reset error:",
                    error
                );


                showLoginMessage(
                    error.message ||
                    "Unable to send password reset instructions."
                );
            }
        }
    );
}


/* =========================================================
   PASSWORD SHOW / HIDE
   ========================================================= */

function setupPasswordToggle(
    inputId,
    buttonId
) {

    const input =
        document.getElementById(inputId);

    const button =
        document.getElementById(buttonId);


    if (!input || !button) {
        return;
    }


    button.addEventListener(
        "click",
        function () {

            if (input.type === "password") {

                input.type = "text";

                button.textContent = "🙈";

                button.setAttribute(
                    "aria-label",
                    "Hide password"
                );

            } else {

                input.type = "password";

                button.textContent = "👁";

                button.setAttribute(
                    "aria-label",
                    "Show password"
                );
            }
        }
    );
}


setupPasswordToggle(
    "loginPassword",
    "loginPasswordToggle"
);


setupPasswordToggle(
    "regPassword",
    "registerPasswordToggle"
);


/* =========================================================
   INITIAL PAGE
   ========================================================= */

if (
    window.location.hash === "#register"
) {

    showRegister();

} else {

    showLogin();
}


/* =========================================================
   DEBUG INFORMATION
   ========================================================= */

console.log(
    "NetArmor AI authentication system initialized."
);

console.log(
    "Login email field:",
    document.getElementById("loginEmail")
);

console.log(
    "Login form:",
    document.getElementById("loginForm")
);

console.log(
    "Supabase client:",
    supabaseClient ? "Connected" : "Missing"
);