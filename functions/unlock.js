// /unlock route: verifies the access key and sets an HttpOnly cookie.
const COOKIE_NAME = "site_access";

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

function unlockHtml(errorMessage, returnPath="/") {
  const err = errorMessage ? `<div style="margin:10px 0 0;padding:10px 12px;background:#fff2f2;border:1px solid #ffd0d0;color:#a40000;border-radius:10px">${errorMessage}</div>` : "";
  return `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Unlock</title></head>
  <body style="margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f7f7f7">
  <div style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px">
    <div style="width:100%;max-width:520px;background:#fff;border:1px solid #e5e5e5;border-radius:14px;padding:22px;box-shadow:0 10px 25px rgba(0,0,0,.06)">
      <h1 style="margin:0 0 8px;font-size:22px;color:#111">Access key required</h1>
      <p style="margin:0 0 14px;color:#666;line-height:1.35">Enter the website access key to continue.</p>
      ${err}
      <form method="POST" action="/unlock">
        <label style="display:block;font-weight:600;margin:12px 0 6px;color:#111" for="key">Access key</label>
        <input id="key" name="key" type="password" required style="width:100%;padding:12px;border:1px solid #d7d7d7;border-radius:10px;font-size:16px"/>
        <input type="hidden" name="r" value="${returnPath.replace(/"/g, "&quot;")}"/>
        <button type="submit" style="margin-top:12px;width:100%;padding:12px;border:0;border-radius:10px;background:#0b3a47;color:#fff;font-weight:700;font-size:16px">Unlock</button>
      </form>
    </div>
  </div>
  </body></html>`;
}

export async function onRequestPost(context) {
  const { request, env } = context;

  const siteKey = env.SITE_KEY || "";
  if (!siteKey) {
    return new Response("Site key is not configured.", { status: 500 });
  }

  const form = await request.formData();
  const provided = (form.get("key") || "").toString();
  const redirectTo = (form.get("r") || "/").toString();

  if (provided !== siteKey) {
    return new Response(unlockHtml("Incorrect access key.", redirectTo), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
    });
  }

  const token = await expectedToken(env);
  const headers = new Headers();
  headers.set("Set-Cookie", `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
  headers.set("Location", redirectTo.startsWith("/") ? redirectTo : "/");
  return new Response(null, { status: 302, headers });
}

export async function onRequestGet() {
  // If someone navigates to /unlock directly, show a small message.
  return new Response("Use the access key form on the main page to unlock.", {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }
  });
}
