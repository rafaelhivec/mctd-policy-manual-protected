// Site-wide access key middleware for Cloudflare Pages Functions.
// If env.SITE_KEY is set, users must unlock the site before accessing any route.
// Cookie is HttpOnly to prevent JS access.

const COOKIE_NAME = "site_access";

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const parts = cookie.split(";").map(v => v.trim());
  for (const p of parts) {
    if (!p) continue;
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    if (k === name) return v;
  }
  return null;
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function expectedToken(env) {
  const siteKey = env.SITE_KEY || "";
  if (!siteKey) return null;
  return await sha256Hex(siteKey + "::site_access_v1");
}

function isJsonOrApi(request) {
  const url = new URL(request.url);
  if (url.pathname.startsWith("/api/")) return true;
  const accept = (request.headers.get("Accept") || "").toLowerCase();
  return accept.includes("application/json");
}

function unlockHtml({ errorMessage = "", returnPath = "/" } = {}) {
  const err = errorMessage
    ? `<div class="err" role="alert">${errorMessage}</div>`
    : "";
  // Inline HTML/CSS so it works even when the site is locked (no external assets).
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Unlock</title>
  <style>
    :root{--bg:#f7f7f7;--card:#fff;--text:#111;--muted:#666;--accent:#0b3a47;}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
    .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .card{width:100%;max-width:520px;background:var(--card);border:1px solid #e5e5e5;border-radius:14px;padding:22px 22px 18px;box-shadow:0 10px 25px rgba(0,0,0,.06)}
    h1{margin:0 0 8px;font-size:22px}
    p{margin:0 0 14px;color:var(--muted);line-height:1.35}
    label{display:block;font-weight:600;margin:12px 0 6px}
    input{width:100%;padding:12px 12px;border:1px solid #d7d7d7;border-radius:10px;font-size:16px}
    button{margin-top:12px;width:100%;padding:12px;border:0;border-radius:10px;background:var(--accent);color:#fff;font-weight:700;font-size:16px;cursor:pointer}
    button:hover{filter:brightness(.95)}
    .fine{margin-top:12px;font-size:12px;color:#888}
    .err{margin:10px 0 0;padding:10px 12px;background:#fff2f2;border:1px solid #ffd0d0;color:#a40000;border-radius:10px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Access key required</h1>
      <p>Enter the website access key to continue.</p>
      ${err}
      <form method="POST" action="/unlock">
        <label for="key">Access key</label>
        <input id="key" name="key" type="password" autocomplete="current-password" required />
        <input type="hidden" name="r" value="${returnPath.replace(/"/g, "&quot;")}" />
        <button type="submit">Unlock</button>
      </form>
      <div class="fine">Tip: If you just set the key in Cloudflare, redeploy the site once.</div>
    </div>
  </div>
</body>
</html>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // If no site key is configured, do nothing (site is public).
  const token = await expectedToken(env);
  if (!token) return next();

  // Always allow unlock/logout routes.
  if (url.pathname === "/unlock" || url.pathname === "/logout") return next();

  // Already unlocked?
  const cookieVal = getCookie(request, COOKIE_NAME);
  if (cookieVal && cookieVal === token) return next();

  // If API/JSON request, return 401 JSON (so callers can handle it).
  if (isJsonOrApi(request)) {
    return new Response(JSON.stringify({
      ok: false,
      error: "SITE_LOCKED",
      message: "Website is locked. Visit the site in a browser and unlock with the access key."
    }), {
      status: 401,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store"
      }
    });
  }

  // Otherwise, return unlock page.
  return new Response(unlockHtml({ returnPath: url.pathname + url.search }), {
    status: 401,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
