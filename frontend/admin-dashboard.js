const sb = window.netarmorSupabase;

const $ = (id) =>
  document.getElementById(id);


/* HTML ESCAPE */

const esc = (value) => {

  return String(value ?? "").replace(
    /[&<>"']/g,

    (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    })[char]
  );

};


/* DATE FORMAT */

const fmt = (date) => {

  if (!date) return "—";

  return new Date(date).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short"
  });

};


/* LOAD ADMIN DASHBOARD */

async function load() {

  /* CHECK LOGIN */

  const {
    data: { user }
  } = await sb.auth.getUser();


  if (!user) {

    location.href = "login.html";

    return;
  }


  /* CHECK ROLE */

  const {
    data: profile
  } = await sb
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .maybeSingle();


  /* ONLY ASSOCIATE CAN ENTER */

  if (profile?.role !== "associate") {

    location.href = "dashboard.html";

    return;
  }


  /* GET USERS + SCANS */

  const [
    usersResult,
    scansResult
  ] = await Promise.all([

    sb
      .from("profiles")
      .select(
        "username, role, created_at"
      )
      .order(
        "created_at",
        {
          ascending: false
        }
      )
      .limit(200),


    sb
      .from("scan_history")
      .select(`
        scan_type,
        target,
        result,
        risk_score,
        created_at,
        user_id,
        profiles(username)
      `)
      .order(
        "created_at",
        {
          ascending: false
        }
      )
      .limit(100)

  ]);


  const users = usersResult.data || [];

  const scans = scansResult.data || [];


  if (
    usersResult.error ||
    scansResult.error
  ) {

    console.error(
      usersResult.error ||
      scansResult.error
    );

    return;
  }


  /* THREAT COUNT */

  const threats = scans.filter(
    (scan) =>
      scan.result === "Threat"
  ).length;


  /* DASHBOARD STATISTICS */

  $( "users" ).textContent =
    users.length;

  $( "total" ).textContent =
    scans.length;

  $( "threats" ).textContent =
    threats;

  $( "rate" ).textContent =
    scans.length
      ? Math.round(
          (threats / scans.length) * 100
        ) + "%"
      : "0%";


  /* USERS TABLE */

  $( "userTable" ).innerHTML =

    users.length

      ? users.map(
          (user) => `

          <tr>

            <td>
              ${esc(user.username)}
            </td>

            <td>
              ${esc(user.role)}
            </td>

            <td>
              ${fmt(user.created_at)}
            </td>

          </tr>

        `
        ).join("")

      : `
        <tr>

          <td
            colspan="3"
            class="empty"
          >
            No users.
          </td>

        </tr>
      `;


  /* SCAN ACTIVITY */

  $( "threatsTable" ).innerHTML =

    scans.length

      ? scans.map(
          (scan) => `

          <tr>

            <td>
              ${esc(
                scan.profiles?.username ||
                "Unknown"
              )}
            </td>

            <td>
              ${esc(scan.scan_type)}
            </td>

            <td>
              ${esc(
                String(
                  scan.target
                ).slice(0, 35)
              )}
            </td>

            <td>

              <span
                class="badge ${
                  scan.result === "Threat"
                    ? "threat"
                    : "safe"
                }"
              >
                ${esc(scan.result)}
              </span>

            </td>

            <td>
              ${scan.risk_score ?? 0}%
            </td>

            <td>
              ${fmt(scan.created_at)}
            </td>

          </tr>

        `
        ).join("")

      : `
        <tr>

          <td
            colspan="6"
            class="empty"
          >
            No records yet.
          </td>

        </tr>
      `;


  /* REFRESH */

  $( "refresh" ).onclick = load;


  /* LOGOUT */

  $( "logout" ).onclick = async () => {

    await sb.auth.signOut();

    location.href = "login.html";

  };

}


/* START */

load();