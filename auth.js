export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    const REDIRECT_URI = env.OAUTH_REDIRECT_URI || `${url.origin}/api/callback`;

    if (path === "/api/login") {
      const state = randomString(24);
      const authorize = new URL("https://discord.com/oauth2/authorize");
      authorize.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
      authorize.searchParams.set("response_type", "code");
      authorize.searchParams.set("redirect_uri", REDIRECT_URI);
      authorize.searchParams.set("scope", "identify");
      authorize.searchParams.set("state", state);

      const headers = new Headers({
        Location: authorize.toString(),
      });
      headers.append(
        "Set-Cookie",
        cookie("oauth_state", state, {
          httpOnly: true,
          secure: true,
          sameSite: "Lax",
          path: "/",
          maxAge: 300,
        })
      );
      return new Response(null, { status: 302, headers });
    }

    if (path === "/api/callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const cookies = parseCookies(req);
      if (!code || !state || !cookies.oauth_state || cookies.oauth_state !== state) {
        return new Response("Ogiltigt state eller saknad code", { status: 400 });
      }

      // Exchange code for token
      const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: env.DISCORD_CLIENT_ID,
          client_secret: env.DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
        }),
      });
      if (!tokenRes.ok) {
        return new Response("Fel vid token-utbyte", { status: 500 });
      }
      const token = await tokenRes.json();

      // Fetch user
      const userRes = await fetch("https://discord.com/api/users/@me", {
        headers: { Authorization: `Bearer ${token.access_token}` },
      });
      if (!userRes.ok) {
        return new Response("Fel vid hämtning av användare", { status: 500 });
      }
      const user = await userRes.json();
      const payload = {
        id: user.id,
        username: user.username,
        global_name: user.global_name || null,
        discriminator: user.discriminator || null,
        avatar: user.avatar || null,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7, // 7 dagar
      };

      const tokenSigned = await signSession(payload, env.COOKIE_SECRET);

      const headers = new Headers({ Location: url.origin + "/index.html" });
      headers.append("Set-Cookie", cookie("oauth_state", "", { path: "/", maxAge: 0 }));
      headers.append(
        "Set-Cookie",
        cookie("session", tokenSigned, {
          httpOnly: true,
          secure: true,
          sameSite: "Lax",
          path: "/",
          maxAge: 60 * 60 * 24 * 7,
        })
      );
      return new Response(null, { status: 302, headers });
    }

    if (path === "/api/me") {
      const cookies = parseCookies(req);
      const token = cookies.session;
      if (!token) return json({ error: "unauthenticated" }, 401);
      const data = await verifySession(token, env.COOKIE_SECRET).catch(() => null);
      if (!data || (data.exp && data.exp < Math.floor(Date.now() / 1000))) {
        return json({ error: "expired" }, 401);
      }
      return json(
        {
          id: data.id,
          username: data.username,
          global_name: data.global_name,
          avatar: data.avatar,
        },
        200,
        { "Cache-Control": "no-store" }
      );
    }

    if (path === "/api/logout") {
      const headers = new Headers({ Location: url.origin + "/index.html" });
      headers.append("Set-Cookie", cookie("session", "", { path: "/", maxAge: 0 }));
      return new Response(null, { status: 302, headers });
    }

    // Optional: webhook relay to hide Discord webhook URL from client
    if (path === "/api/relay" && req.method === "POST") {
      try {
        const body = await req.json();
        if (!body || !body.url || !body.payload) return json({ error: "bad request" }, 400);
        const r = await fetch(body.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body.payload),
        });
        return json({ ok: r.ok, status: r.status });
      } catch (e) {
        return json({ error: "relay failed" }, 500);
      }
    }

    return new Response("Not found", { status: 404 });
  },
};

function parseCookies(req) {
  const cookie = req.headers.get("Cookie") || "";
  const out = {};
  cookie.split(/;\s*/).forEach((kv) => {
    const idx = kv.indexOf("=");
    if (idx > -1) out[decodeURIComponent(kv.slice(0, idx))] = decodeURIComponent(kv.slice(idx + 1));
  });
  return out;
}

function cookie(name, value, opts = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    opts.maxAge != null ? `Max-Age=${opts.maxAge}` : null,
    opts.domain ? `Domain=${opts.domain}` : null,
    opts.path ? `Path=${opts.path}` : "Path=/",
    opts.httpOnly ? "HttpOnly" : null,
    opts.secure ? "Secure" : null,
    opts.sameSite ? `SameSite=${opts.sameSite}` : "SameSite=Lax",
  ].filter(Boolean);
  return parts.join("; ");
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function randomString(len = 24) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, (b) => (b % 36).toString(36)).join("");
}

async function importKey(secret) {
  const keyData = new TextEncoder().encode(secret);
  return crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function b64url(data) {
  let str = btoa(String.fromCharCode(...new Uint8Array(data)));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlText(str) {
  return b64url(new TextEncoder().encode(str));
}

function decodeB64UrlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = str.length % 4 ? 4 - (str.length % 4) : 0;
  str = str + "=".repeat(pad);
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function signSession(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = b64urlText(JSON.stringify(header));
  const encPayload = b64urlText(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;
  const key = await importKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${b64url(sig)}`;
}

async function verifySession(token, secret) {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) throw new Error("bad token");
  const data = `${h}.${p}`;
  const key = await importKey(secret);
  const sig = decodeB64UrlToBytes(s);
  const ok = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(data));
  if (!ok) throw new Error("bad signature");
  const payload = JSON.parse(new TextDecoder().decode(decodeB64UrlToBytes(p)));
  return payload;
}
