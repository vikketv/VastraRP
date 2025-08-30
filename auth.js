/* Discord Login (Implicit Grant) for static sites
 * How to use:
 * 1) Create a Discord Application → OAuth2 → enable "Implicit Grant"
 * 2) Add each page URL you use as a Redirect (e.g. https://example.com/index.html, /ansokan.html, /faq.html, /regler.html)
 * 3) Set DISCORD_CLIENT_ID below.
 * 4) Include this file on every page: <script src="auth.js"></script>
 *
 * The script adds a "Logga in med Discord" button automatically if #loginBtn isn't present.
 * After login, it shows avatar + username and a "Logga ut" button. User info is cached in localStorage.
 * If the Discord API blocks CORS for you, set RELAY_URL to a small proxy that fetches the URL server‑side.
 */
(function(){
  const CONFIG = {
    DISCORD_CLIENT_ID: "https://discord.gg/3wRYxTPCU8", // TODO: replace with your Discord app Client ID
    SCOPES: ["identify"],
    RELAY_URL: "" // optional: set to your CORS relay endpoint if direct fetch fails
  };

  const storage = {
    get token(){ return localStorage.getItem('discord_token') || null; },
    set token(v){ v ? localStorage.setItem('discord_token', v) : localStorage.removeItem('discord_token'); },
    get user(){ try{ return JSON.parse(localStorage.getItem('discord_user')||'null'); }catch(e){ return null; } },
    set user(u){ u ? localStorage.setItem('discord_user', JSON.stringify(u)) : localStorage.removeItem('discord_user'); }
  };

  function buildAuthorizeUrl(){
    const redirect = window.location.origin + window.location.pathname; // current page as redirect
    const p = new URLSearchParams({
      client_id: CONFIG.DISCORD_CLIENT_ID,
      redirect_uri: redirect,
      response_type: 'token',
      scope: CONFIG.SCOPES.join(' ')
    });
    return `https://discord.com/api/oauth2/authorize?${p.toString()}`;
  }

  function parseHashToken(){
    if(location.hash && location.hash.includes('access_token')){
      const h = new URLSearchParams(location.hash.substring(1));
      const token = h.get('access_token');
      if(token){ storage.token = token; }
      // Clean hash from URL
      history.replaceState({}, document.title, location.pathname + location.search);
      return true;
    }
    return false;
  }

  async function fetchDiscordUser(){
    if(!storage.token) return null;
    const url = 'https://discord.com/api/users/@me';
    try{
      let r;
      if(CONFIG.RELAY_URL){
        r = await fetch(CONFIG.RELAY_URL, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ url, headers:{ Authorization: `Bearer ${storage.token}` }})});
      }else{
        r = await fetch(url, { headers: { Authorization: `Bearer ${storage.token}` }});
      }
      if(!r.ok) throw new Error('HTTP '+r.status);
      const data = await r.json();
      storage.user = data;
      return data;
    }catch(err){
      console.warn('Discord API fetch failed. Consider setting RELAY_URL.', err);
      return null;
    }
  }

  function createFloatingLogin(){
    const wrap = document.createElement('div');
    wrap.id = 'authWidget';
    wrap.style.position = 'fixed';
    wrap.style.top = '12px';
    wrap.style.right = '12px';
    wrap.style.zIndex = '9999';
    const btn = document.createElement('button');
    btn.id = 'loginBtn';
    btn.textContent = 'Logga in med Discord';
    btn.className = 'btn alt';
    btn.style.backdropFilter = 'blur(6px)';
    wrap.appendChild(btn);
    document.body.appendChild(wrap);
    return btn;
  }

  function renderLoggedIn(){
    const widget = document.getElementById('authWidget') || (function(){
      const w = document.createElement('div');
      w.id='authWidget'; w.style.position='fixed'; w.style.top='12px'; w.style.right='12px'; w.style.zIndex='9999';
      document.body.appendChild(w); return w;
    })();
    const existing = document.getElementById('userMenu'); if(existing) existing.remove();
    const user = storage.user;
    const box = document.createElement('div');
    box.id = 'userMenu';
    box.style.display = 'inline-flex';
    box.style.alignItems = 'center';
    box.style.gap = '8px';
    box.style.padding = '6px 10px';
    box.style.border = '1px solid rgba(255,255,255,.08)';
    box.style.borderRadius = '999px';
    box.style.background = 'rgba(255,255,255,.06)';

    const img = document.createElement('img');
    img.style.width='24px'; img.style.height='24px'; img.style.borderRadius='50%';
    img.src = user && user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=64` : 'https://cdn.discordapp.com/embed/avatars/0.png';

    const name = document.createElement('span');
    name.textContent = user ? `${user.username}#${user.discriminator}` : 'Inloggad';

    const out = document.createElement('button');
    out.className = 'btn ghost';
    out.textContent = 'Logga ut';
    out.onclick = ()=>{ storage.token=null; storage.user=null; location.reload(); };

    box.append(img,name,out);

    const loginBtn = document.getElementById('loginBtn');
    if(loginBtn) loginBtn.style.display='none';
    widget.appendChild(box);
  }

  function attachLogin(){
    let btn = document.getElementById('loginBtn');
    if(!btn){ btn = createFloatingLogin(); }
    btn.addEventListener('click', ()=>{ window.location.href = buildAuthorizeUrl(); });
  }

  async function init(){
    parseHashToken();
    if(storage.token && !storage.user){ await fetchDiscordUser(); }
    if(storage.user){ renderLoggedIn(); }
    else { attachLogin(); }
  }

  if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
