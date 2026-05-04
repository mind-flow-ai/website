// Stealth gate Worker for mindflow.ai. Every request is intercepted; the
// real content (served via env.ASSETS) is reached only after the SHA-256
// of the submitted passcode matches PASSCODE_HASH and the resulting
// cookie is presented on subsequent requests.

const PASSCODE_HASH = "62652d2d33187a4f05c3e4d1a72a689e7f00309e8b49bfd3845692dbf879fdb7";
const COOKIE_NAME = "mf_gate";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30;
const GATE_PATH = "/__gate";

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function gatePage(error) {
  const errMarkup = error ? `<div class="err">${error}</div>` : `<div class="err"></div>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>mindflow.ai</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { background:#0a0e1a; color:#f1f5f9; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .gate { max-width:380px; width:100%; padding:40px; text-align:center; }
  h1 { font-size:1rem; font-weight:500; margin:0 0 28px; letter-spacing:0.06em; color:#94a3b8; text-transform:uppercase; }
  input[type=password] { width:100%; padding:14px 16px; background:#1a2035; border:1px solid #1e293b; border-radius:10px; color:#f1f5f9; font-size:0.95rem; outline:none; transition:border-color 0.2s; }
  input[type=password]:focus { border-color:#0e7490; }
  button { width:100%; margin-top:12px; padding:12px 16px; background:linear-gradient(135deg,#0e7490,#059669); border:none; border-radius:10px; color:#fff; font-size:0.95rem; font-weight:600; cursor:pointer; transition:transform 0.1s; font-family:inherit; }
  button:hover { transform:translateY(-1px); }
  .err { color:#f87171; font-size:0.85rem; margin-top:14px; min-height:1.2em; }
</style>
</head>
<body>
<form class="gate" method="POST" action="${GATE_PATH}">
  <h1>mindflow.ai</h1>
  <input type="password" name="p" autofocus autocomplete="off" placeholder="Passcode">
  <button type="submit">Enter</button>
  ${errMarkup}
</form>
</body>
</html>`;
}

function gateResponse(status, error) {
  return new Response(gatePage(error), {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === GATE_PATH) {
      if (request.method !== "POST") {
        return gateResponse(405);
      }
      const form = await request.formData();
      const passcode = String(form.get("p") || "");
      const hash = await sha256Hex(passcode);
      if (hash === PASSCODE_HASH) {
        return new Response(null, {
          status: 303,
          headers: {
            Location: "/",
            "Set-Cookie": `${COOKIE_NAME}=${hash}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
          },
        });
      }
      return gateResponse(401, "Incorrect passcode");
    }

    if (getCookie(request, COOKIE_NAME) === PASSCODE_HASH) {
      return env.ASSETS.fetch(request);
    }

    return gateResponse(401);
  },
};
