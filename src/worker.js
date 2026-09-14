// worker.js — 富文本轻量备忘录（Cloudflare Workers + D1）
// 特性：HMAC 无状态会话 / 登录防爆破（按 IP 限流封禁）/ 富文本编辑 / HTML 消毒
// 加密：暂未启用，但接缝在服务端，密钥用 Secret（用户无需输入任何口令）。
//
// 绑定 / 机密：
//   D1 绑定名：DB
//   Secret：AUTH_PASSWORD    登录密码
//   Secret：SESSION_SECRET   会话签名密钥（随机长串）
//   Secret：ENC_KEY          （以后启用加密时再加；现在不需要）

// ===== 可调参数 =====
const COOKIE_NAME = 'session';
const SESSION_TTL = 7 * 24 * 60 * 60;        // 会话有效期（秒）

// 登录防爆破
const LOGIN_WINDOW_MIN = 10;                 // 统计窗口（分钟）
const LOGIN_MAX_FAILS  = 5;                  // 窗口内允许的失败次数
const LOGIN_BAN_SEC    = 900;                // 触发后封禁时长（秒）

// 加密总开关：以后置 true 并配置 Secret ENC_KEY 即可，数据库无需迁移
const ENC_ENABLED = false;
// ====================

const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const proto = request.headers.get('x-forwarded-proto') || 'https';
    if (proto === 'http' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
      url.protocol = 'https:';
      return Response.redirect(url.toString(), 301);
    }
    const p = url.pathname, method = request.method;
    try {
      if ((method === 'GET' || method === 'HEAD') && p === '/') return html(PAGE);
      if (p === '/api/login' && method === 'POST') return handleLogin(request, env);
      if (p === '/api/logout' && method === 'POST') return handleLogout();
      if (p.startsWith('/uploads/') && method === 'GET') return serveUpload(request, env, url);
      if (p.startsWith('/s/') && method === 'GET') return serveShare(request, env, url);
      if (p.startsWith('/api/')) {
        if (!(await isAuthed(request, env))) return json({ error: 'unauthorized' }, 401);
        return handleApi(request, env, url);
      }
      return new Response('Not Found', { status: 404 });
    } catch (e) {
      return json({ error: 'internal', detail: String(e) }, 500);
    }
  },
};

// ---------- 会话鉴权（HMAC 无状态） ----------

function timingSafeEqual(a, b) {
  const ab = enc.encode(a), bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}
function b64url(bytes) {
  let binary = '';
  const len = bytes.byteLength || bytes.length;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function safeAtob(str) {
  let base64 = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return atob(base64);
}
async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64url(new Uint8Array(sig));
}
async function makeToken(env) {
  const payload = b64url(enc.encode(JSON.stringify({ exp: Date.now() + SESSION_TTL * 1000 })));
  return payload + '.' + (await hmac(env.SESSION_SECRET, payload));
}
async function verifyToken(env, token) {
  if (!token || token.indexOf('.') < 0) return false;
  const parts = token.split('.');
  const expected = await hmac(env.SESSION_SECRET, parts[0]);
  if (!timingSafeEqual(parts[1], expected)) return false;
  try {
    const data = JSON.parse(safeAtob(parts[0]));
    return typeof data.exp === 'number' && data.exp > Date.now();
  } catch (e) { return false; }
}
function getCookie(request, name) {
  const c = request.headers.get('Cookie') || '';
  const m = c.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function isAuthed(request, env) { return verifyToken(env, getCookie(request, COOKIE_NAME)); }

function setCookie(token, ttl) {
  return COOKIE_NAME + '=' + token + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + ttl;
}
function banned(retrySec) {
  return new Response(JSON.stringify({ error: 'too_many_attempts', retry_after: retrySec }), {
    status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': String(retrySec) } });
}

// ---------- 登录 + 防爆破 ----------
// 用 CF-Connecting-IP 作为限流键：它由 Cloudflare 边缘写入，客户端无法伪造。
// 切勿用 X-Forwarded-For 之类客户端可控的头来做限流，那等于没限。

async function handleLogin(request, env) {
  const db = env.NOTE_DB;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const windowMs = LOGIN_WINDOW_MIN * 60 * 1000;

  const rec = await db.prepare(
    'SELECT fails, first_fail_at, banned_until FROM login_attempts WHERE ip = ?').bind(ip).first();

  // 封禁中：直接拒绝，不读 body、不验密码、不写库（封禁期间零写入，抗刷）
  if (rec && rec.banned_until > now) return banned(Math.ceil((rec.banned_until - now) / 1000));

  const body = await request.json().catch(() => ({}));
  const pw = typeof body.password === 'string' ? body.password : '';
  const cleanSecret = (env.AUTH_PASSWORD || '').trim();
  const ok = !!cleanSecret && (timingSafeEqual(pw, cleanSecret) || timingSafeEqual(pw.trim(), cleanSecret));

  if (ok) {
    if (rec) await db.prepare('DELETE FROM login_attempts WHERE ip = ?').bind(ip).run(); // 成功即清零
    const token = await makeToken(env);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': setCookie(token, SESSION_TTL) } });
  }

  // 失败：在窗口内累加，否则重置窗口；达到阈值则封禁
  let fails = 1, firstAt = now, bannedUntil = 0;
  if (rec && (now - rec.first_fail_at) <= windowMs) { fails = rec.fails + 1; firstAt = rec.first_fail_at; }
  if (fails >= LOGIN_MAX_FAILS) { bannedUntil = now + LOGIN_BAN_SEC * 1000; fails = 0; firstAt = now; }

  await db.prepare(
    'INSERT INTO login_attempts (ip, fails, first_fail_at, banned_until) VALUES (?,?,?,?) ' +
    'ON CONFLICT(ip) DO UPDATE SET fails=excluded.fails, first_fail_at=excluded.first_fail_at, banned_until=excluded.banned_until'
  ).bind(ip, fails, firstAt, bannedUntil).run();

  if (bannedUntil) return banned(LOGIN_BAN_SEC);
  return json({ error: 'bad_password', remaining: LOGIN_MAX_FAILS - fails }, 401);
}

function handleLogout() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': setCookie('', 0) } });
}

// ---------- 服务端加密接缝（密钥来自 Secret，用户不输入任何东西） ----------
// 现在 ENC_ENABLED=false，全程明文直通，行为和不加密完全一致。
// 启用时：把 ENC_ENABLED 置 true、配置 Secret ENC_KEY，按下方注释填充 AES-GCM 即可。
// 安全边界（务必清楚）：密钥在服务端，这是"静态加密"——能防 D1 数据被单独导出/泄露，
// 防不住 Worker 或账号本身被攻破（拿到 ENC_KEY 的人能解密）。它不是端到端、不是零知识。

async function getKey(env) {
  // 由 Secret 派生 AES-256-GCM 密钥（HKDF）。仅在启用加密时调用。
  const ikm = await crypto.subtle.importKey('raw', enc.encode(env.ENC_KEY), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('notes-v1'), info: enc.encode('content') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encStore(env, text) {
  if (!ENC_ENABLED) return { data: text, format: 0 };
  const key = await getKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text || ''));
  return { data: b64url(iv) + '.' + b64url(new Uint8Array(ct)), format: 1 };
}
async function decStore(env, data, format) {
  if (!format) return data || '';                 // format=0 旧明文，直接返回
  const key = await getKey(env);
  const parts = String(data).split('.');
  const iv = Uint8Array.from(safeAtob(parts[0]), c => c.charCodeAt(0));
  const ct = Uint8Array.from(safeAtob(parts[1]), c => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

// ---------- 服务端 HTML 过滤 (HTMLRewriter XSS 消毒) ----------

async function sanitizeHtmlOnServer(htmlStr) {
  const ALLOWED_TAGS = new Set([
    'a', 'b', 'strong', 'i', 'em', 'u', 's', 'strike', 'code', 'pre', 'span', 'div', 'p', 'br',
    'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'blockquote', 'img', 'font'
  ]);
  const ALLOWED_STYLES = new Set([
    'color', 'background-color', 'font-family', 'font-size', 'font-weight', 'font-style', 'text-decoration'
  ]);

  function safeUrl(u) {
    const val = String(u || '').trim();
    return /^(https?:|mailto:)/i.test(val) || val.startsWith('/uploads/');
  }

  function cleanStyle(s) {
    const out = [];
    String(s || '').split(';').forEach(d => {
      const i = d.indexOf(':');
      if (i < 0) return;
      const prop = d.slice(0, i).trim().toLowerCase();
      const val = d.slice(i + 1).trim();
      if (/url\(|expression|javascript:/i.test(val)) return;
      if (ALLOWED_STYLES.has(prop)) {
        out.push(prop + ': ' + val);
      }
    });
    return out.join('; ');
  }

  let transformed = new HTMLRewriter();
  transformed = transformed.on('*', {
    element(el) {
      const tag = el.tagName.toLowerCase();
      if (!ALLOWED_TAGS.has(tag)) {
        el.removeAndKeepContent();
        return;
      }

      const attrs = [...el.attributes];
      for (const [name, val] of attrs) {
        const lowerName = name.toLowerCase();
        if (lowerName === 'style') {
          const clean = cleanStyle(val);
          if (clean) el.setAttribute('style', clean);
          else el.removeAttribute('style');
        } else if (lowerName === 'href' && tag === 'a') {
          if (safeUrl(val)) {
            el.setAttribute('href', val);
          } else {
            el.removeAttribute('href');
          }
        } else if (lowerName === 'src' && tag === 'img') {
          if (safeUrl(val)) {
            el.setAttribute('src', val);
          } else {
            el.remove();
          }
        } else if (tag === 'a' && (lowerName === 'target' || lowerName === 'rel')) {
          // keep
        } else if (tag === 'font' && (lowerName === 'size' || lowerName === 'color' || lowerName === 'face')) {
          // keep
        } else {
          el.removeAttribute(name);
        }
      }

      if (tag === 'a') {
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      }
    }
  });

  const response = new Response(htmlStr, { headers: { 'content-type': 'text/html;charset=utf-8' } });
  const sanitizedResponse = transformed.transform(response);
  return await sanitizedResponse.text();
}

// ---------- R2 文件上传与服务 ----------

async function handleUpload(request, env) {
  if (!env.NOTE_R2) {
    return json({ error: 'R2 bucket not bound' }, 500);
  }
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file || !(file instanceof File)) {
      return json({ error: 'No file uploaded' }, 400);
    }
    const ext = file.name.split('.').pop() || 'bin';
    const filename = `${crypto.randomUUID()}.${ext}`;
    await env.NOTE_R2.put(filename, file.stream(), {
      httpMetadata: {
        contentType: file.type || 'application/octet-stream',
        cacheControl: 'public, max-age=31536000',
      }
    });
    return json({ url: `/uploads/${filename}` });
  } catch (e) {
    return json({ error: 'Upload failed', detail: String(e) }, 500);
  }
}

async function serveUpload(request, env, url) {
  if (!env.NOTE_R2) {
    return new Response('Not Found', { status: 404 });
  }
  const filename = url.pathname.slice('/uploads/'.length);
  const object = await env.NOTE_R2.get(filename);
  if (!object) {
    return new Response('Not Found', { status: 404 });
  }
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  headers.set('Cache-Control', 'public, max-age=31536000');
  return new Response(object.body, { headers });
}

function generateShortId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let result = '';
  for (let i = 0; i < 8; i++) {
    result += chars[bytes[i] % chars.length];
  }
  return result;
}

let checkedNotesSchema = false;
async function ensureNotesSchema(db) {
  if (checkedNotesSchema) return;
  try {
    const info = await db.prepare("PRAGMA table_info(notes)").all();
    const cols = (info.results || []).map(c => c.name);
    if (cols.length > 0) {
      if (!cols.includes('deleted_at')) {
        await db.prepare("ALTER TABLE notes ADD COLUMN deleted_at INTEGER DEFAULT NULL").run();
        try {
          await db.prepare("CREATE INDEX IF NOT EXISTS idx_notes_deleted_at ON notes(deleted_at)").run();
        } catch (_) {}
      }
      if (!cols.includes('kind')) {
        await db.prepare("ALTER TABLE notes ADD COLUMN kind INTEGER NOT NULL DEFAULT 0").run();
      }
    }
    checkedNotesSchema = true;
  } catch (e) {
    console.error("Notes schema migration check error:", e);
  }
}

let checkedNoteIdCol = false;
async function ensureSharedNotesSchema(db) {
  if (checkedNoteIdCol) return;
  try {
    const info = await db.prepare("PRAGMA table_info(shared_notes)").all();
    const cols = (info.results || []).map(c => c.name);
    if (cols.length > 0 && !cols.includes('note_id')) {
      await db.prepare("ALTER TABLE shared_notes ADD COLUMN note_id INTEGER").run();
      try {
        await db.prepare("CREATE INDEX IF NOT EXISTS idx_shared_notes_note_id ON shared_notes(note_id)").run();
      } catch (_) {}
    }
    checkedNoteIdCol = true;
  } catch (e) {
    console.error("Schema migration check error:", e);
  }
}

async function handleCreateShare(request, env) {
  const db = env.NOTE_DB;
  await ensureSharedNotesSchema(db);
  const body = await request.json().catch(() => ({}));
  const title = typeof body.title === 'string' ? body.title : '';
  const content = typeof body.content === 'string' ? body.content : '';
  const noteId = typeof body.note_id === 'number' ? body.note_id : null;
  const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : null;
  const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : null;
  
  if (!title && !content) {
    return json({ error: 'Content cannot be empty' }, 400);
  }

  const cleanContent = await sanitizeHtmlOnServer(content);

  let id = '';
  let success = false;
  for (let attempt = 0; attempt < 5; attempt++) {
    id = generateShortId();
    try {
      try {
        await db.prepare(
          'INSERT INTO shared_notes (id, title, content, created_at, expires_at, note_id) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(id, title, cleanContent, Date.now(), expiresAt, noteId).run();
      } catch (insertErr) {
        await db.prepare(
          'INSERT INTO shared_notes (id, title, content, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(id, title, cleanContent, Date.now(), expiresAt).run();
      }
      success = true;
      break;
    } catch (e) {
      console.error('ID collision or DB error in share:', e);
    }
  }

  if (!success) {
    return json({ error: 'Failed to generate a unique share link' }, 500);
  }

  return json({ id });
}

async function serveShare(request, env, url) {
  const db = env.NOTE_DB;
  const p = url.pathname;
  const id = p.slice('/s/'.length);
  if (!id) {
    return new Response('Not Found', { status: 404 });
  }

  const row = await db.prepare(
    'SELECT title, content, created_at, expires_at FROM shared_notes WHERE id = ?'
  ).bind(id).first();

  if (!row || (row.expires_at && row.expires_at < Date.now())) {
    return new Response('分享链接不存在或已失效', { status: 404, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
  }

  const escapeHtmlForTitle = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const htmlStr = SHARE_PAGE_TEMPLATE
    .replace('${TITLE}', escapeHtmlForTitle(row.title))
    .replace('${RAW_TITLE}', JSON.stringify(row.title))
    .replace('${RAW_DATE}', JSON.stringify(new Date(row.created_at).toLocaleString('zh-CN')))
    .replace('${RAW_CONTENT}', JSON.stringify(row.content));

  return html(htmlStr);
}

const SHARE_PAGE_TEMPLATE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<title>\${TITLE} - 备忘录分享</title>
<style>
  :root{--bg:#f4f4f6;--panel:#fff;--ink:#1d1d1f;--muted:#8a8a8f;--line:#e6e6ea;--accent:#c8932f;--code-bg:#f0f0f3}
  @media (prefers-color-scheme:dark){:root{--bg:#1a1a1c;--panel:#232326;--ink:#ededef;--muted:#8d8d93;--line:#34343a;--accent:#e0b25a;--code-bg:#2b2b30}}
  *{box-sizing:border-box}html,body{min-height:100%;margin:0;overflow-x:hidden}
  body{font:16px/1.65 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",Segoe UI,sans-serif;color:var(--ink);background:var(--bg);-webkit-font-smoothing:antialiased;display:flex;flex-direction:column;align-items:center;padding:24px 16px}
  .container{width:100%;max-width:680px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:32px 28px;box-shadow:0 8px 30px rgba(0,0,0,.04);margin-top:20px;min-width:0;overflow-wrap:anywhere;word-break:break-word}
  h1{margin:0 0 16px 0;font-size:24px;font-weight:700;border-bottom:1px solid var(--line);padding-bottom:12px;overflow-wrap:anywhere;word-break:break-word}
  .meta{font-size:13px;color:var(--muted);margin-bottom:24px;display:flex;gap:12px;flex-wrap:wrap}
  .content{outline:none;line-height:1.7;overflow-wrap:anywhere;word-break:break-word}
  .content p, .content div, .content span{overflow-wrap:anywhere;word-break:break-word}
  .content img{max-width:100%;border-radius:6px;margin:8px 0;height:auto}
  .content a{color:var(--accent);text-decoration:none;overflow-wrap:anywhere;word-break:break-all}
  .content a:hover{text-decoration:underline}
  .content code{background:var(--code-bg);padding:2px 5px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92em;overflow-wrap:anywhere;word-break:break-all}
  .content pre{background:var(--code-bg);padding:12px 14px;border-radius:9px;overflow-x:auto;margin:12px 0;max-width:100%;white-space:pre-wrap;word-break:break-all}
  .content pre code{background:none;padding:0;white-space:pre-wrap;word-break:break-all}
  .footer{margin-top:40px;margin-bottom:20px;font-size:12px;color:var(--muted);text-align:center}
  @media (max-width:600px){
    body{padding:16px 12px}
    .container{padding:20px 16px;margin-top:10px;border-radius:12px}
    h1{font-size:20px}
  }
</style>
</head>
<body>
  <div class="container">
    <h1 id="title"></h1>
    <div class="meta">
      <span id="date"></span>
    </div>
    <div class="content" id="content"></div>
  </div>
  <div class="footer">
    <div>由 <a href="/" style="color:var(--muted);text-decoration:none;font-weight:600">备忘录 (Cloud-Note)</a> 安全驱动</div>
    <div style="margin-top:8px">
      端到端加密 &bull; 纯私有部署
    </div>
  </div>
  <script>
    document.getElementById('title').textContent = \${RAW_TITLE};
    document.getElementById('date').textContent = '分享于 ' + \${RAW_DATE};
    document.getElementById('content').innerHTML = \${RAW_CONTENT};
  </script>
</body>
</html>`;

// ---------- 业务 API ----------

async function handleApi(request, env, url) {
  const p = url.pathname, method = request.method, db = env.NOTE_DB;
  await ensureNotesSchema(db);
  await ensureSharedNotesSchema(db);

  if (p === '/api/upload' && method === 'POST') {
    return handleUpload(request, env);
  }

  if (p === '/api/share' && method === 'POST') {
    return handleCreateShare(request, env);
  }

  if (p === '/api/shares' && method === 'GET') {
    let r;
    try {
      r = await db.prepare(
        'SELECT id, title, created_at, expires_at, note_id FROM shared_notes ORDER BY created_at DESC'
      ).all();
    } catch (e) {
      r = await db.prepare(
        'SELECT id, title, created_at, expires_at FROM shared_notes ORDER BY created_at DESC'
      ).all();
    }
    return json(r.results || []);
  }

  const mShareDetail = p.match(/^\/api\/shares\/([A-Za-z0-9]+)$/);
  if (mShareDetail) {
    const shareId = mShareDetail[1];
    if (method === 'GET') {
      let row;
      try {
        row = await db.prepare(
          'SELECT id, title, content, created_at, expires_at, note_id FROM shared_notes WHERE id = ?'
        ).bind(shareId).first();
      } catch (e) {
        row = await db.prepare(
          'SELECT id, title, content, created_at, expires_at FROM shared_notes WHERE id = ?'
        ).bind(shareId).first();
      }
      if (!row) return json({ error: 'Share not found' }, 404);
      return json(row);
    }
    if (method === 'PUT') {
      const body = await request.json().catch(() => ({}));
      const title = typeof body.title === 'string' ? body.title : '';
      const content = typeof body.content === 'string' ? body.content : '';
      const cleanContent = await sanitizeHtmlOnServer(content);
      await db.prepare('UPDATE shared_notes SET title = ?, content = ? WHERE id = ?').bind(title, cleanContent, shareId).run();
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await db.prepare('DELETE FROM shared_notes WHERE id = ?').bind(shareId).run();
      return json({ ok: true });
    }
  }

  const mShareExtend = p.match(/^\/api\/shares\/([A-Za-z0-9]+)\/extend$/);
  if (mShareExtend && method === 'POST') {
    const shareId = mShareExtend[1];
    const body = await request.json().catch(() => ({}));
    const expiresAt = typeof body.expires_at === 'number' ? body.expires_at : null;
    await db.prepare('UPDATE shared_notes SET expires_at = ? WHERE id = ?').bind(expiresAt, shareId).run();
    return json({ ok: true });
  }

  // 清空回收站
  if (p === '/api/notes/trash/empty' && method === 'POST') {
    try {
      await db.prepare('DELETE FROM shared_notes WHERE note_id IN (SELECT id FROM notes WHERE deleted_at IS NOT NULL)').run();
    } catch (_) {}
    await db.prepare('DELETE FROM notes WHERE deleted_at IS NOT NULL').run();
    return json({ ok: true });
  }

  // 恢复笔记
  const mRestore = p.match(/^\/api\/notes\/(\d+)\/restore$/);
  if (mRestore && method === 'POST') {
    const id = parseInt(mRestore[1], 10);
    await db.prepare('UPDATE notes SET deleted_at = NULL WHERE id = ?').bind(id).run();
    return json({ ok: true });
  }

  if (p === '/api/notes') {
    if (method === 'GET') {
      const isTrash = url.searchParams.get('trash') === '1';
      const sql = isTrash
        ? 'SELECT id, title, format, kind, updated_at, deleted_at FROM notes WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC'
        : 'SELECT id, title, format, kind, updated_at, deleted_at FROM notes WHERE deleted_at IS NULL ORDER BY updated_at DESC';
      const r = await db.prepare(sql).all();
      const rows = r.results || [], out = [];
      for (const row of rows) {
        const title = row.format === 1 ? await decStore(env, row.title, row.format) : row.title;
        out.push({
          id: row.id,
          title,
          format: row.format,
          kind: row.kind || 0,
          updated_at: row.updated_at,
          deleted_at: row.deleted_at || null
        });
      }
      return json(out);
    }
    if (method === 'POST') {
      const b = await request.json().catch(() => ({}));
      const format = typeof b.format === 'number' ? b.format : 0;
      const kind = b.kind === 1 ? 1 : 0;
      const now = Date.now();
      
      let finalTitle = '';
      let finalContent = '';
      let finalFormat = 0;
      
      if (format === 2) {
        finalTitle = typeof b.title === 'string' ? b.title : '';
        finalContent = typeof b.content === 'string' ? b.content : '';
        finalFormat = 2;
      } else {
        const e = await encStore(env, '');
        finalTitle = e.data;
        finalContent = e.data;
        finalFormat = e.format;
      }
      const r = await db.prepare(
        'INSERT INTO notes (title, content, format, kind, updated_at, deleted_at) VALUES (?,?,?,?,?,NULL)'
      ).bind(finalTitle, finalContent, finalFormat, kind, now).run();
      return json({ id: r.meta.last_row_id, updated_at: now, kind });
    }
  }

  const m = p.match(/^\/api\/notes\/(\d+)$/);
  if (m) {
    const id = parseInt(m[1], 10);
    if (method === 'GET') {
      const row = await db.prepare(
        'SELECT id, title, content, format, kind, updated_at, deleted_at FROM notes WHERE id = ?').bind(id).first();
      if (!row) return json({ error: 'not_found' }, 404);
      const isFormat1 = row.format === 1;
      return json({
        id: row.id,
        title: isFormat1 ? await decStore(env, row.title, row.format) : row.title,
        content: isFormat1 ? await decStore(env, row.content, row.format) : row.content,
        format: row.format,
        kind: row.kind || 0,
        updated_at: row.updated_at,
        deleted_at: row.deleted_at || null,
      });
    }
    if (method === 'PUT') {
      const b = await request.json().catch(() => ({}));
      const title = typeof b.title === 'string' ? b.title.slice(0, 2000) : '';
      let content = typeof b.content === 'string' ? b.content : '';
      const format = typeof b.format === 'number' ? b.format : 0;
      const kind = b.kind === 1 ? 1 : 0;
      let finalTitle, finalContent, finalFormat;
      if (format === 2) {
        finalTitle = title;
        finalContent = content;
        finalFormat = 2;
      } else {
        if (kind === 0) {
          content = await sanitizeHtmlOnServer(content);
        }
        const et = await encStore(env, title);
        const ec = await encStore(env, content);
        finalTitle = et.data;
        finalContent = ec.data;
        finalFormat = et.format;
      }
      const now = Date.now();
      await db.prepare(
        'UPDATE notes SET title=?, content=?, format=?, kind=?, updated_at=? WHERE id=?'
      ).bind(finalTitle, finalContent, finalFormat, kind, now, id).run();
      return json({ ok: true, updated_at: now, kind });
    }
    if (method === 'DELETE') {
      const isHard = url.searchParams.get('hard') === '1';
      if (isHard) {
        await db.prepare('DELETE FROM notes WHERE id = ?').bind(id).run();
        try {
          await db.prepare('DELETE FROM shared_notes WHERE note_id = ?').bind(id).run();
        } catch (_) {}
      } else {
        await db.prepare('UPDATE notes SET deleted_at = ? WHERE id = ?').bind(Date.now(), id).run();
      }
      return json({ ok: true });
    }
  }
  return json({ error: 'not_found' }, 404);
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
}
function html(body) { return new Response(body, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); }

// ---------- 前端（无外部依赖；模板内禁用反引号与 ${}，字面换行写成 \\n） ----------

const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<title>备忘录</title>
<style>
  :root{--bg:#f4f4f6;--panel:#fff;--ink:#1d1d1f;--muted:#8a8a8f;--line:#e6e6ea;--sel:#fbf2dd;--accent:#c8932f;--code-bg:#f0f0f3}
  @media (prefers-color-scheme:dark){:root{--bg:#1a1a1c;--panel:#232326;--ink:#ededef;--muted:#8d8d93;--line:#34343a;--sel:#3a3220;--accent:#e0b25a;--code-bg:#2b2b30}}
  *{box-sizing:border-box}html,body{height:100%;margin:0}
  [hidden]{display:none !important}
  body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",Segoe UI,sans-serif;color:var(--ink);background:var(--bg);-webkit-font-smoothing:antialiased}
  button{font:inherit;cursor:pointer}
  #login{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:24px}
  #login .card{width:100%;max-width:320px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:28px 24px;box-shadow:0 8px 30px rgba(0,0,0,.06)}
  #login h1{margin:0 0 4px;font-size:20px;font-weight:600}
  #login p{margin:0 0 18px;color:var(--muted);font-size:13px}
  #login input{width:100%;padding:11px 13px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink);font-size:16px}
  #login input:focus{outline:none;border-color:var(--accent)}
  #login #loginBtn{width:100%;margin-top:14px;padding:11px;border:none;border-radius:10px;background:var(--accent);color:#1d1d1f;font-weight:600}
  #login #loginBtn:disabled{opacity:.5;cursor:not-allowed}
  #login .err{color:#d4584a;font-size:13px;min-height:18px;margin-top:10px}
  #app{display:flex;height:100vh;height:100dvh}
  .sidebar{width:300px;flex:0 0 300px;border-right:1px solid var(--line);background:var(--panel);display:flex;flex-direction:column}
  .sb-head{display:flex;align-items:center;gap:6px;padding:12px 14px;border-bottom:1px solid var(--line);position:relative}
  .sb-head .grow{flex:1;font-weight:600;font-size:16px}
  .icon-btn{border:none;background:transparent;color:var(--muted);width:32px;height:32px;border-radius:8px;line-height:1;font-size:18px;display:inline-flex;align-items:center;justify-content:center;transition:background .15s, color .15s}
  .icon-btn:hover{background:var(--bg);color:var(--ink)}
  .search{margin:10px 12px;padding:8px 11px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:14px}
  .search:focus{outline:none;border-color:var(--accent)}
  .filter-tabs{display:flex;padding:0 12px 10px;gap:4px;border-bottom:1px solid var(--line)}
  .filter-tab{flex:1;padding:6px 2px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--muted);font-size:11px;font-weight:500;text-align:center;cursor:pointer;transition:all .15s;outline:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .filter-tab:hover{color:var(--ink);background:var(--panel)}
  .filter-tab.active{background:var(--panel);color:var(--ink);border-color:var(--accent);font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,0.05)}
  .trash-header{display:none;padding:8px 12px;background:rgba(212,88,74,0.08);border-bottom:1px solid var(--line);justify-content:space-between;align-items:center;font-size:12px;color:#d4584a}
  .list{flex:1;overflow:auto}
  .item{padding:8px 12px;border-bottom:1px solid var(--line);cursor:pointer;transition:background .15s}
  .item:hover{background:var(--bg)}.item.active{background:var(--sel)}
  .item .t-wrap{display:flex;align-items:center;justify-content:space-between;gap:6px}
  .item .t{flex:1;min-width:0;font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .badge-share{display:inline-flex;align-items:center;font-size:10px;line-height:1;padding:3px 6px;border-radius:4px;background:rgba(45,164,78,0.12);color:#2da44e;font-weight:600;flex-shrink:0}
  .badge-share.expired{background:rgba(212,88,74,0.12);color:#d4584a}
  .badge-md{display:inline-flex;align-items:center;font-size:10px;line-height:1;padding:2px 5px;border-radius:4px;background:var(--code-bg);color:var(--muted);font-weight:600;flex-shrink:0;font-family:monospace}
  .item .d{font-size:11px;color:var(--muted);margin-top:3px}
  .empty-list{padding:24px 14px;color:var(--muted);font-size:13px;line-height:1.6;text-align:center}
  .main{flex:1;display:flex;flex-direction:column;min-width:0}
  .toolbar{display:flex;align-items:center;gap:8px;padding:10px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
  .toolbar .back{display:none}.toolbar .status{flex:1;color:var(--muted);font-size:13px;min-width:60px}
  .toolbar .btn{padding:6px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font-size:13px}
  .toolbar .btn.primary{background:var(--accent);border-color:var(--accent);color:#1d1d1f;font-weight:600}
  .toolbar .btn.danger:hover{border-color:#d4584a;color:#d4584a}
  .share-banner{display:none;align-items:center;justify-content:space-between;gap:8px;padding:8px 16px;background:rgba(200,147,47,0.09);border-bottom:1px solid rgba(200,147,47,0.22);font-size:12px;color:var(--ink);flex-wrap:wrap}
  .share-banner.show{display:flex}
  .share-banner .info{display:flex;align-items:center;gap:6px;flex:1;min-width:180px}
  .share-banner .actions{display:flex;align-items:center;gap:6px}
  .fmtbar{display:none;flex-wrap:wrap;align-items:center;gap:6px;padding:8px 16px;border-bottom:1px solid var(--line);background:var(--panel)}
  .fmtbar.show{display:flex}
  .fmtbar select,.fmtbar input[type=color]{height:30px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--ink);padding:0 6px}
  .fmtbar input[type=color]{width:34px;padding:2px;cursor:pointer}
  .fmtbar .fb{min-width:30px;height:30px;padding:0 9px;border:1px solid var(--line);border-radius:7px;background:var(--panel);color:var(--ink)}
  .fmtbar .fb:hover{background:var(--bg)}
  .fmtbar .sep{width:1px;height:20px;background:var(--line);margin:0 2px}
  .edit-wrap{flex:1;overflow:auto;padding:22px clamp(16px,5vw,48px);display:flex;flex-direction:column}
  #noteTitle{overflow-wrap:anywhere;word-break:break-word}
  #editor{min-height:200px;flex:1;outline:none;font:16px/1.7 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",Segoe UI,sans-serif;color:var(--ink);overflow-wrap:anywhere;word-break:break-word}
  #editor.is-empty:before{content:attr(data-placeholder);color:var(--muted);pointer-events:none}
  #editor img{max-width:100%;border-radius:6px}
  #editor a{color:var(--accent);overflow-wrap:anywhere;word-break:break-all}
  #editor code{background:var(--code-bg);padding:1px 5px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92em;overflow-wrap:anywhere;word-break:break-all}
  #editor pre{background:var(--code-bg);padding:12px 14px;border-radius:9px;overflow:auto;white-space:pre-wrap;word-break:break-all}
  #editor pre code{background:none;padding:0;white-space:pre-wrap;word-break:break-all}
  #mdInput{display:none;width:100%;flex:1;min-height:280px;border:none;outline:none;font:15px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;background:transparent;color:var(--ink);resize:none;overflow-wrap:anywhere;word-break:break-word}
  #mdPreview{display:none;flex:1;outline:none;line-height:1.7;overflow-wrap:anywhere;word-break:break-word}
  #mdPreview p,#mdPreview div,#mdPreview span{overflow-wrap:anywhere;word-break:break-word}
  #mdPreview img{max-width:100%;border-radius:6px;margin:8px 0}
  #mdPreview a{color:var(--accent);text-decoration:none;overflow-wrap:anywhere;word-break:break-all}
  #mdPreview a:hover{text-decoration:underline}
  #mdPreview code{background:var(--code-bg);padding:2px 5px;border-radius:5px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92em;overflow-wrap:anywhere;word-break:break-all}
  #mdPreview pre{background:var(--code-bg);padding:12px 14px;border-radius:9px;overflow-x:auto;margin:12px 0;white-space:pre-wrap;word-break:break-all}
  #mdPreview pre code{background:none;padding:0;white-space:pre-wrap;word-break:break-all}
  #mdPreview blockquote{border-left:3px solid var(--accent);margin:12px 0;padding:6px 14px;background:rgba(200,147,47,0.06);border-radius:0 8px 8px 0;color:var(--muted)}
  #mdPreview h1,#mdPreview h2,#mdPreview h3{margin:18px 0 8px;font-weight:700}
  #mdPreview ul,#mdPreview ol{padding-left:22px;margin:8px 0}
  @media (max-width:720px){.sidebar{flex-basis:100%;width:100%}.main{display:none}#app.viewing .sidebar{display:none}#app.viewing .main{display:flex}.toolbar .back{display:inline-block}}
  .main.empty .edit-wrap,
  .main.empty .toolbar,
  .main.empty .fmtbar,
  .main.empty .share-banner {
    display: none !important;
  }
  .main.empty::after {
    content: '请选择或新建备忘录';
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--muted);
    font-size: 15px;
  }
  .modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.45);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;z-index:1000;opacity:0;pointer-events:none;transition:opacity 0.25s ease}
  .modal-overlay.show{opacity:1;pointer-events:auto}
  .modal-card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;width:90%;max-width:440px;box-shadow:0 12px 40px rgba(0,0,0,0.15);transform:scale(0.9);transition:transform 0.25s ease;color:var(--ink)}
  .modal-overlay.show .modal-card{transform:scale(1)}
  .modal-card h3{margin:0 0 12px;font-size:18px;font-weight:600}
  .modal-card p{margin:0 0 16px;color:var(--muted);font-size:13px}
  .modal-card input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font-size:14px;margin-bottom:16px}
  .modal-card input:focus{outline:none;border-color:var(--accent)}
  .modal-actions{display:flex;justify-content:flex-end;gap:10px}
  .modal-actions .btn{padding:8px 16px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink)}
  .modal-actions .btn.primary{background:var(--accent);border-color:var(--accent);color:#1d1d1f;font-weight:600}
  .modal-card select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font-size:14px;margin-bottom:16px}
  .modal-card select:focus{outline:none;border-color:var(--accent)}
  .share-item{display:flex;flex-direction:column;padding:8px 12px;border-bottom:1px solid var(--line);gap:4px;color:var(--ink)}
  .share-item:last-child{border-bottom:none}
  .share-item .t{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px;font-size:13px}
  .share-item .meta-row{display:flex;gap:12px;font-size:11px;color:var(--muted);flex-wrap:wrap}
  .share-item .actions{display:flex;gap:6px;justify-content:flex-end;margin-top:2px}
  .btn.mini{padding:3px 8px;font-size:11px;border-radius:5px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}
  .btn.mini.primary{background:var(--accent);border-color:var(--accent);color:#1d1d1f;font-weight:600}
  .btn.mini.danger:hover{border-color:#d4584a;color:#d4584a}
  /* 更多下拉菜单 */
  .more-dropdown{position:absolute;right:0;top:calc(100% + 4px);width:175px;background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.16);z-index:200;padding:6px;display:none;flex-direction:column;gap:2px}
  .more-dropdown.show{display:flex}
  .more-item{width:100%;text-align:left;padding:8px 10px;border:none;background:transparent;color:var(--ink);border-radius:7px;font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer;transition:background .12s}
  .more-item:hover{background:var(--bg)}
  .more-item.danger{color:#d4584a}
  .more-item.danger:hover{background:rgba(212,88,74,0.1)}
  .more-sep{height:1px;background:var(--line);margin:4px 2px}
  /* 自研弹窗组件 */
  .dlg-mask{position:fixed;inset:0;background:rgba(0,0,0,0.45);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:20px;z-index:1100}
  .dlg-mask.show{display:flex}
  .dlg-card{width:100%;max-width:360px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px 20px 18px;box-shadow:0 12px 40px rgba(0,0,0,0.22);animation:dlgpop .15s ease-out;color:var(--ink)}
  @keyframes dlgpop{from{transform:translateY(8px) scale(.96);opacity:0}to{transform:none;opacity:1}}
  .dlg-title{font-size:16px;font-weight:600;margin-bottom:8px}
  .dlg-msg{color:var(--ink);font-size:14px;line-height:1.55;white-space:pre-wrap;word-break:break-word}
  .dlg-input{width:100%;margin-top:14px;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font-size:14px}
  .dlg-input:focus{outline:none;border-color:var(--accent)}
  .dlg-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:20px}
  .dlg-btn{padding:7px 15px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font-size:13px}
  .dlg-btn:hover{background:var(--bg)}
  .dlg-btn.primary{background:var(--accent);border-color:var(--accent);color:#1d1d1f;font-weight:600}
  .dlg-btn.primary.danger{background:#d4584a;border-color:#d4584a;color:#fff}
  /* Toast 浮动提示 */
  #toastContainer{position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:2000;display:flex;flex-direction:column;gap:8px;pointer-events:none}
  .toast{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 16px;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,0.12);color:var(--ink);opacity:0;transform:translateY(-8px);transition:all 0.2s ease;pointer-events:auto}
  .toast.show{opacity:1;transform:translateY(0)}
  .toast.success{border-color:#2da44e;color:#2da44e}
  .toast.error{border-color:#d4584a;color:#d4584a}
</style>
</head>
<body>
  <div id="login">
    <div class="card">
      <h1>备忘录</h1>
      <p>输入密码以解锁</p>
      <div style="position: relative; width: 100%;">
        <input id="pw" type="password" autocomplete="current-password" placeholder="密码" style="padding-right: 42px;">
        <button id="togglePw" type="button" style="position: absolute; right: 12px; top: 50%; transform: translateY(-50%); border: none; background: transparent; cursor: pointer; color: var(--muted); padding: 0; display: flex; align-items: center; justify-content: center; width: 24px; height: 24px; outline: none; margin: 0;">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
        </button>
      </div>
      <button id="loginBtn">解锁</button>
      <div class="err" id="loginErr"></div>
    </div>
  </div>

  <div id="app" hidden>
    <input type="file" id="fileInput" accept="image/*" style="display:none">
    <input type="file" id="importFile" accept=".json,application/json" style="display:none">
    <aside class="sidebar">
      <div class="sb-head">
        <span class="grow" id="sbTitle">备忘录</span>
        <button class="icon-btn" id="newBtn" title="新建备忘">+</button>
        <button class="icon-btn" id="shareManageBtn" title="已分享列表" style="display:inline-flex; align-items:center; justify-content:center;">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
          </svg>
        </button>
        <div style="position:relative; display:inline-block;">
          <button class="icon-btn" id="moreBtn" title="更多功能" style="font-weight:bold;">⋯</button>
          <div id="moreMenu" class="more-dropdown" hidden>
            <button class="more-item" id="exportBtn" type="button">📤 导出备份 (JSON)</button>
            <button class="more-item" id="importBtn" type="button">📥 导入数据 (JSON)</button>
            <div class="more-sep"></div>
            <button class="more-item" id="settingsBtn" type="button">⚙️ 偏好设置</button>
            <div class="more-sep"></div>
            <button class="more-item danger" id="logoutBtn" type="button">🚪 退出登录</button>
          </div>
        </div>
      </div>
      <input class="search" id="search" placeholder="搜索标题…">
      <div class="filter-tabs" id="filterTabs">
        <button class="filter-tab active" id="tabAll" type="button">全部 (0)</button>
        <button class="filter-tab" id="tabShared" type="button">已分享 (0)</button>
        <button class="filter-tab" id="tabTrash" type="button">回收站 (0)</button>
      </div>
      <div id="trashHeader" class="trash-header">
        <span>🗑️ 回收站</span>
        <button class="btn mini danger" id="emptyTrashBtn" type="button">清空回收站</button>
      </div>
      <div class="list" id="list"></div>
    </aside>
    <section class="main">
      <div class="toolbar">
        <button class="btn back" id="backBtn">返回</button>
        <span class="status" id="status"></span>
        <button class="btn" id="mdToggle" title="切换编辑模式">MD</button>
        <button class="btn" id="previewToggle" title="预览/编辑切换" style="display:none;">预览</button>
        <button class="btn" id="shareBtn">分享</button>
        <button class="btn danger" id="delBtn">删除</button>
        <button class="btn primary" id="saveBtn">保存</button>
      </div>
      <div class="share-banner" id="shareBanner">
        <div class="info">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;">
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
          </svg>
          <span id="shareBannerText">已公开分享</span>
        </div>
        <div class="actions">
          <button class="btn mini" id="sbCopyBtn" type="button">复制链接</button>
          <button class="btn mini primary" id="sbExtendBtn" type="button">管理分享</button>
          <button class="btn mini danger" id="sbCancelBtn" type="button">取消分享</button>
        </div>
      </div>
      <div class="fmtbar" id="fmtbar">
        <select id="fFont" title="字体">
          <option value="">默认</option>
          <option value="-apple-system,Segoe UI,sans-serif">无衬线</option>
          <option value="Georgia,Times New Roman,serif">衬线</option>
          <option value="ui-monospace,Consolas,monospace">等宽</option>
          <option value="KaiTi,STKaiti,serif">楷体</option>
          <option value="SimSun,serif">宋体</option>
        </select>
        <select id="fSize" title="字号">
          <option value="">字号</option>
          <option value="12px">12</option><option value="14px">14</option>
          <option value="16px">16</option><option value="18px">18</option>
          <option value="20px">20</option><option value="24px">24</option>
          <option value="32px">32</option>
        </select>
        <input type="color" id="fColor" title="文字颜色" value="#1d1d1f">
        <span class="sep"></span>
        <button class="fb" data-cmd="bold" title="加粗"><b>B</b></button>
        <button class="fb" data-cmd="italic" title="斜体"><i>I</i></button>
        <button class="fb" data-cmd="underline" title="下划线"><u>U</u></button>
        <span class="sep"></span>
        <button class="fb" id="bCode" title="行内代码">&lt;/&gt;</button>
        <button class="fb" id="bPre" title="代码块">[ ]</button>
        <span class="sep"></span>
        <button class="fb" id="bLink" title="超链接">链接</button>
        <button class="fb" id="bImg" title="图片链接">图片</button>
        <span class="sep"></span>
        <button class="fb" id="bClear" title="清除格式">清除</button>
      </div>
      <div class="edit-wrap">
        <input id="noteTitle" type="text" placeholder="输入标题…" style="width: 100%; border: none; outline: none; font-size: 20px; font-weight: 600; background: transparent; color: var(--ink); margin-bottom: 16px; padding: 0 0 8px 0; border-bottom: 1px solid var(--line);">
        <div id="editor" contenteditable="true" spellcheck="false" data-placeholder="开始输入…"></div>
        <textarea id="mdInput" spellcheck="false" placeholder="在此输入 Markdown 内容…"></textarea>
        <div id="mdPreview"></div>
      </div>
    </section>
  </div>

  <div id="shareModal" class="modal-overlay">
    <div class="modal-card">
      <h3 id="shareModalTitle">分享此备忘录</h3>
      <p id="shareModalDesc">生成只读分享链接。未分享的备忘录保持端到端加密。</p>
      
      <!-- 已有分享管理区域 -->
      <div id="shareExistingArea" style="display:none; margin-bottom: 16px;">
        <div style="font-size: 13px; color: var(--muted); margin-bottom: 6px;">分享链接：</div>
        <div style="display:flex; gap:6px; margin-bottom: 12px;">
          <input type="text" id="shareExistingUrlInput" readonly style="margin-bottom:0; flex:1;">
          <button class="btn" id="shareExistingCopyBtn" type="button" style="white-space:nowrap;">复制</button>
        </div>
        <div id="shareExistingStatus" style="font-size: 13px; margin-bottom: 12px; color: var(--muted);"></div>
        <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom: 8px;">
          <button class="btn mini primary" id="shareQuickExtend7Btn" type="button">+7天</button>
          <button class="btn mini primary" id="shareQuickExtend30Btn" type="button">+30天</button>
          <button class="btn mini" id="shareQuickExtendForeverBtn" type="button">设为永久</button>
          <button class="btn mini" id="shareSyncContentBtn" type="button">更新分享内容</button>
          <button class="btn mini danger" id="shareExistingCancelBtn" type="button">取消分享</button>
        </div>
      </div>

      <!-- 新建分享配置区域 -->
      <div id="shareConfigArea" style="margin-bottom: 16px;">
        <label for="shareExpireSelect" style="font-size: 13px; color: var(--muted); display: block; margin-bottom: 6px;">有效期限制：</label>
        <select id="shareExpireSelect">
          <option value="0">永久</option>
          <option value="86400">1天</option>
          <option value="604800">7天</option>
          <option value="2592000">30天</option>
          <option value="custom">自定义天数</option>
        </select>
        <div id="shareCustomDaysWrap" style="display:none; margin-top: 8px;">
          <input type="number" id="shareCustomDaysInput" min="1" placeholder="输入自定义天数" style="margin-bottom:0;">
        </div>
      </div>
      <div id="shareResultArea" style="display:none; margin-bottom: 16px;">
        <input type="text" id="shareUrlInput" readonly style="margin-bottom:0;">
      </div>
      <div class="modal-actions">
        <button class="btn" id="closeShareBtn">关闭</button>
        <button class="btn primary" id="shareActionBtn">生成分享链接</button>
        <button class="btn primary" id="copyShareBtn" style="display:none;">复制链接</button>
      </div>
    </div>
  </div>

  <div id="shareManageModal" class="modal-overlay">
    <div class="modal-card" style="max-width: 540px; width: 95%;">
      <h3>管理已分享的备忘录</h3>
      <div id="shareListContainer" style="max-height: 320px; overflow-y: auto; margin-bottom: 20px; border: 1px solid var(--line); border-radius: 10px; background: var(--bg);">
        <!-- 动态载入列表 -->
      </div>
      <div class="modal-actions">
        <button class="btn" id="closeShareManageBtn">关闭</button>
      </div>
    </div>
  </div>

  <!-- 偏好设置模态框 -->
  <div id="settingsModal" class="modal-overlay">
    <div class="modal-card">
      <h3>偏好设置</h3>
      <p>调整前端压缩与编辑体验（设置保存在本机浏览器）。</p>
      <div style="margin-bottom: 14px;">
        <label style="font-size: 13px; color: var(--muted); display: block; margin-bottom: 6px;">图片最长边限制：</label>
        <select id="settingImgDim">
          <option value="1200">1200 px（更小体积）</option>
          <option value="1600" selected>1600 px（推荐高清）</option>
          <option value="2000">2000 px（超大高清）</option>
          <option value="0">不限制（保留原尺寸）</option>
        </select>
      </div>
      <div style="margin-bottom: 14px;">
        <label style="font-size: 13px; color: var(--muted); display: block; margin-bottom: 6px;">图片 WebP 压缩质量：</label>
        <select id="settingImgQuality">
          <option value="0.75">较小体积 (75%)</option>
          <option value="0.82" selected>平衡品质 (82% 推荐)</option>
          <option value="0.92">极高画质 (92%)</option>
        </select>
      </div>
      <div style="margin-bottom: 18px;">
        <label style="font-size: 13px; color: var(--muted); display: block; margin-bottom: 6px;">新建备忘默认格式：</label>
        <select id="settingDefaultKind">
          <option value="0" selected>富文本编辑器</option>
          <option value="1">Markdown 编辑器</option>
        </select>
      </div>
      <div class="modal-actions">
        <button class="btn" id="closeSettingsBtn">取消</button>
        <button class="btn primary" id="saveSettingsBtn">保存设置</button>
      </div>
    </div>
  </div>

  <!-- 自研磨砂弹窗组件 -->
  <div id="dlg" class="dlg-mask" hidden>
    <div class="dlg-card">
      <div id="dlgTitle" class="dlg-title"></div>
      <div id="dlgMsg" class="dlg-msg"></div>
      <input id="dlgInput" class="dlg-input" hidden>
      <div class="dlg-actions">
        <button id="dlgCancel" class="dlg-btn">取消</button>
        <button id="dlgOk" class="dlg-btn primary">确定</button>
      </div>
    </div>
  </div>

  <!-- 浮动 Toast 容器 -->
  <div id="toastContainer"></div>

<script>
(function(){
  var notes = [], shares = [], trashNotes = [], currentTab = 'all', currentId = null, currentSnapshotShareId = null;
  var curKind = 0, mdPreviewing = false, dirty = false, query = '', savedRange = null, autoSaveTimer = null;
  var editor = document.getElementById('editor');
  var mdInput = document.getElementById('mdInput');
  var mdPreview = document.getElementById('mdPreview');
  var $ = function(id){ return document.getElementById(id); };
  var sessionKey = null;

  // ---- 偏好设置管理 ----
  var defaultSettings = {
    imgDim: '1600',
    imgQuality: '0.82',
    defaultKind: '0'
  };
  function getSettings() {
    try {
      var s = localStorage.getItem('cloud_note_settings');
      if (s) return Object.assign({}, defaultSettings, JSON.parse(s));
    } catch (_) {}
    return Object.assign({}, defaultSettings);
  }
  function saveSettings(s) {
    try {
      localStorage.setItem('cloud_note_settings', JSON.stringify(s));
    } catch (_) {}
  }

  // ---- Toast 浮动气泡提示 ----
  function showToast(msg, type) {
    var c = $('toastContainer');
    if (!c) return;
    var t = document.createElement('div');
    t.className = 'toast' + (type ? (' ' + type) : '');
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(function(){ t.classList.add('show'); }, 10);
    setTimeout(function(){
      t.classList.remove('show');
      setTimeout(function(){ if (t.parentNode) t.parentNode.removeChild(t); }, 250);
    }, 2400);
  }

  // ---- 自研磨砂统一弹窗 (替代原生 alert / confirm / prompt)，返回 Promise ----
  var dlgResolve = null;
  function openDlg(opts) {
    return new Promise(function(resolve) {
      dlgResolve = resolve;
      var hasTitle = !!opts.title;
      $('dlgTitle').textContent = opts.title || '';
      $('dlgTitle').style.display = hasTitle ? 'block' : 'none';
      $('dlgMsg').textContent = opts.msg || '';
      var withInput = !!opts.input;
      $('dlgInput').style.display = withInput ? 'block' : 'none';
      if (withInput) {
        $('dlgInput').value = opts.value || '';
        $('dlgInput').placeholder = opts.placeholder || '';
      }
      $('dlgCancel').style.display = opts.cancel ? 'inline-block' : 'none';
      $('dlgOk').textContent = opts.okText || '确定';
      $('dlgCancel').textContent = opts.cancelText || '取消';
      $('dlgOk').className = 'dlg-btn primary' + (opts.danger ? ' danger' : '');
      $('dlg').classList.add('show');
      $('dlg').style.display = 'flex';
      $('dlg').hidden = false;
      setTimeout(function(){ (withInput ? $('dlgInput') : $('dlgOk')).focus(); }, 30);
    });
  }
  function closeDlg(result) {
    $('dlg').classList.remove('show');
    $('dlg').style.display = 'none';
    $('dlg').hidden = true;
    var r = dlgResolve;
    dlgResolve = null;
    if (r) r(result);
  }
  function uiAlert(msg, title) { return openDlg({ msg: msg, title: title, cancel: false }).then(function(){}); }
  function uiConfirm(msg, opts) {
    opts = opts || {};
    return openDlg({ msg: msg, title: opts.title, cancel: true, okText: opts.okText, danger: opts.danger }).then(function(r){ return !!r; });
  }
  function uiPrompt(msg, value, title) {
    return openDlg({ msg: msg, title: title, input: true, value: value, cancel: true }).then(function(r){ return r; });
  }
  $('dlgOk').onclick = function(){ closeDlg($('dlgInput').style.display === 'none' ? true : $('dlgInput').value); };
  $('dlgCancel').onclick = function(){ closeDlg(null); };
  $('dlg').addEventListener('mousedown', function(e){ if (e.target === $('dlg')) closeDlg(null); });
  $('dlgInput').addEventListener('keydown', function(e){ if (e.key === 'Enter'){ e.preventDefault(); $('dlgOk').click(); } });
  document.addEventListener('keydown', function(e){ if ($('dlg').classList.contains('show') && e.key === 'Escape') closeDlg(null); });

  // ---- 更多功能菜单 ----
  function closeMore() {
    $('moreMenu').classList.remove('show');
    $('moreMenu').style.display = 'none';
    $('moreMenu').hidden = true;
  }
  $('moreBtn').onclick = function(e){
    e.stopPropagation();
    var m = $('moreMenu');
    var isShown = m.classList.toggle('show');
    m.style.display = isShown ? 'flex' : 'none';
    m.hidden = !isShown;
  };
  document.addEventListener('click', closeMore);

  // ---- 偏好设置弹窗 ----
  function openSettingsModal() {
    var s = getSettings();
    $('settingImgDim').value = s.imgDim;
    $('settingImgQuality').value = s.imgQuality;
    $('settingDefaultKind').value = s.defaultKind;
    $('settingsModal').classList.add('show');
  }
  $('settingsBtn').onclick = function(){ closeMore(); openSettingsModal(); };
  $('closeSettingsBtn').onclick = function(){ $('settingsModal').classList.remove('show'); };
  $('settingsModal').onclick = function(e){ if (e.target === this) this.classList.remove('show'); };
  $('saveSettingsBtn').onclick = function(){
    saveSettings({
      imgDim: $('settingImgDim').value,
      imgQuality: $('settingImgQuality').value,
      defaultKind: $('settingDefaultKind').value
    });
    $('settingsModal').classList.remove('show');
    showToast('设置已保存', 'success');
  };

  // ---- 端到端加密与编解码 ----
  function base64urlEncode(arrayBuffer) {
    var binary = '';
    var bytes = new Uint8Array(arrayBuffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }

  function base64urlDecode(str) {
    var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function deriveKey(password) {
    if (!window.crypto || !window.crypto.subtle) {
      return Promise.reject(new Error('浏览器不支持 Web Crypto API，请确保使用 HTTPS 访问'));
    }
    try {
      var enc = new TextEncoder();
      var passwordBuffer = enc.encode(password);
      var salt = enc.encode('cloud-note-pbkdf2-salt');
      return window.crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      ).then(function(baseKey) {
        return window.crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
          },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
      }).then(function(key) {
        sessionKey = key;
        return window.crypto.subtle.exportKey('raw', key);
      }).then(function(raw) {
        sessionStorage.setItem('session_key', base64urlEncode(raw));
      });
    } catch(e) {
      return Promise.reject(e);
    }
  }

  function encryptData(text) {
    if (!sessionKey) return Promise.resolve(text || '');
    var enc = new TextEncoder();
    var iv = window.crypto.getRandomValues(new Uint8Array(12));
    return window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      sessionKey,
      enc.encode(text || '')
    ).then(function(ciphertext) {
      return 'v2.' + base64urlEncode(iv) + '.' + base64urlEncode(ciphertext);
    });
  }

  function decryptData(encryptedStr) {
    if (!sessionKey) return Promise.resolve(encryptedStr || '');
    if (!encryptedStr || !encryptedStr.startsWith('v2.')) return Promise.resolve(encryptedStr || '');
    var parts = encryptedStr.split('.');
    if (parts.length !== 3) return Promise.resolve(encryptedStr || '');
    try {
      var iv = base64urlDecode(parts[1]);
      var ct = base64urlDecode(parts[2]);
      return window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) },
        sessionKey,
        ct
      ).then(function(pt) {
        return new TextDecoder().decode(pt);
      }).catch(function() {
        return '[解密失败：密码错误]';
      });
    } catch(e) {
      return Promise.resolve('[解密失败：密文损坏]');
    }
  }

  function api(path, opts){
    opts = opts || {}; opts.credentials = 'same-origin';
    opts.headers = opts.headers || {};
    if (!(opts.body instanceof FormData)) {
      opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/json';
    }
    return fetch(path, opts).then(function(res){
      if (res.status === 401){ showLogin(); throw new Error('unauthorized'); }
      return res.json();
    });
  }

  // ---- HTML 消毒（防存储型 XSS） ----
  var ALLOWED = {A:1,B:1,STRONG:1,I:1,EM:1,U:1,S:1,STRIKE:1,CODE:1,PRE:1,SPAN:1,DIV:1,P:1,BR:1,
    UL:1,OL:1,LI:1,H1:1,H2:1,H3:1,BLOCKQUOTE:1,IMG:1,FONT:1};
  var STYLE_PROPS = {'color':1,'background-color':1,'font-family':1,'font-size':1,
    'font-weight':1,'font-style':1,'text-decoration':1};
  function safeUrl(u){
    var val = String(u||'').trim();
    return /^(https?:|mailto:)/i.test(val) || val.indexOf('/uploads/') === 0;
  }
  function cleanStyle(s){
    var out=[];
    String(s||'').split(';').forEach(function(d){
      var i=d.indexOf(':'); if(i<0) return;
      var prop=d.slice(0,i).trim().toLowerCase(), val=d.slice(i+1).trim();
      if (/url\\(|expression|javascript:/i.test(val)) return;
      if (STYLE_PROPS[prop]) out.push(prop+': '+val);
    });
    return out.join('; ');
  }
  function cleanNode(node){
    Array.prototype.slice.call(node.childNodes).forEach(function(c){
      if (c.nodeType === 8){ node.removeChild(c); return; }
      if (c.nodeType !== 1) return;
      var tag=c.tagName;
      if (!ALLOWED[tag]){ node.replaceChild(document.createTextNode(c.textContent||''), c); return; }
      Array.prototype.slice.call(c.attributes).forEach(function(a){
        var name=a.name.toLowerCase();
        if (name==='style'){ var v=cleanStyle(a.value); if(v) c.setAttribute('style',v); else c.removeAttribute('style'); return; }
        if (name==='href' && tag==='A'){ if(!safeUrl(a.value)) c.removeAttribute('href'); return; }
        if (name==='src' && tag==='IMG'){ if(!safeUrl(a.value)){ c.parentNode.removeChild(c); } return; }
        if (tag==='A' && (name==='target'||name==='rel')) return;
        if (tag==='FONT' && (name==='size'||name==='color'||name==='face')) return;
        c.removeAttribute(a.name);
      });
      if (c.parentNode) cleanNode(c);
      if (c.parentNode && tag==='A'){ c.setAttribute('target','_blank'); c.setAttribute('rel','noopener noreferrer'); }
    });
  }
  function sanitize(htmlStr){
    var doc=new DOMParser().parseFromString('<body>'+(htmlStr||'')+'</body>','text/html');
    cleanNode(doc.body); return doc.body.innerHTML;
  }
  function escapeHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function escapeAttr(s){ return escapeHtml(s).replace(/"/g,'&quot;'); }

  // ---- 轻量零依赖 Markdown 解析器 ----
  function mdToHtml(src) {
    var F = String.fromCharCode(96);
    var lines = String(src || '').split('\\n');
    var out = [], i = 0;
    var codeRe = new RegExp(F + '([^' + F + ']+)' + F, 'g');
    function inline(s) {
      s = escapeHtml(s);
      s = s.replace(codeRe, '<code>$1</code>');
      s = s.replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>');
      s = s.replace(/\\*([^*]+)\\*/g, '<em>$1</em>');
      s = s.replace(/~~([^~]+)~~/g, '<del>$1</del>');
      s = s.replace(/!\\[([^\\]]*)\\]\\((https?:[^)\\s]+|\\/uploads\\/[^)\\s]+)\\)/g, '<img src="$2" alt="$1">');
      s = s.replace(/\\[([^\\]]+)\\]\\((https?:[^)\\s]+|\\/uploads\\/[^)\\s]+)\\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
      return s;
    }
    function isBlockStart(l) {
      return /^#{1,3}\\s/.test(l) || /^\\s*[-*]\\s/.test(l) || /^\\s*\\d+\\.\\s/.test(l) || /^\\s*>\\s?/.test(l) || l.slice(0, 3) === F + F + F;
    }
    while (i < lines.length) {
      var line = lines[i];
      if (line.slice(0, 3) === F + F + F) {
        var buf = []; i++;
        while (i < lines.length && lines[i].slice(0, 3) !== F + F + F) { buf.push(lines[i]); i++; }
        i++; out.push('<pre><code>' + escapeHtml(buf.join('\\n')) + '</code></pre>'); continue;
      }
      var h = line.match(/^(#{1,3})\\s+(.*)$/);
      if (h) { var lv = h[1].length; out.push('<h' + lv + '>' + inline(h[2]) + '</h' + lv + '>'); i++; continue; }
      if (/^\\s*>\\s?/.test(line)) { out.push('<blockquote>' + inline(line.replace(/^\\s*>\\s?/, '')) + '</blockquote>'); i++; continue; }
      if (/^\\s*[-*]\\s+/.test(line)) {
        var ul = [];
        while (i < lines.length && /^\\s*[-*]\\s+/.test(lines[i])) { ul.push('<li>' + inline(lines[i].replace(/^\\s*[-*]\\s+/, '')) + '</li>'); i++; }
        out.push('<ul>' + ul.join('') + '</ul>'); continue;
      }
      if (/^\\s*\\d+\\.\\s+/.test(line)) {
        var ol = [];
        while (i < lines.length && /^\\s*\\d+\\.\\s+/.test(lines[i])) { ol.push('<li>' + inline(lines[i].replace(/^\\s*\\d+\\.\\s+/, '')) + '</li>'); i++; }
        out.push('<ol>' + ol.join('') + '</ol>'); continue;
      }
      if (line.trim() === '') { i++; continue; }
      var para = [line]; i++;
      while (i < lines.length && lines[i].trim() !== '' && !isBlockStart(lines[i])) { para.push(lines[i]); i++; }
      out.push('<p>' + para.map(inline).join('<br>') + '</p>');
    }
    return out.join('');
  }

  // ---- 图片前端 Canvas WebP 智能压缩 ----
  function compressImage(file) {
    return new Promise(function(resolve) {
      if (!file || !file.type || file.type.indexOf('image/') !== 0) {
        return resolve(file);
      }
      var settings = getSettings();
      var maxDim = parseInt(settings.imgDim, 10);
      if (isNaN(maxDim)) maxDim = 1600;
      if (maxDim <= 0) return resolve(file);
      var quality = parseFloat(settings.imgQuality);
      if (isNaN(quality)) quality = 0.82;

      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function() {
        URL.revokeObjectURL(url);
        var w = img.naturalWidth || img.width;
        var h = img.naturalHeight || img.height;
        if (!w || !h) { return resolve(file); }
        var scale = Math.min(1, maxDim / Math.max(w, h));
        var cw = Math.max(1, Math.round(w * scale));
        var ch = Math.max(1, Math.round(h * scale));
        var canvas = document.createElement('canvas');
        canvas.width = cw; canvas.height = ch;
        var ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, cw, ch);

        canvas.toBlob(function(blob) {
          if (!blob) return resolve(file);
          var newName = (file.name || 'image').replace(/\\.[^.]+$/, '') + '.webp';
          var compressedFile = new File([blob], newName, { type: 'image/webp' });
          resolve(compressedFile);
        }, 'image/webp', quality);
      };
      img.onerror = function() {
        URL.revokeObjectURL(url);
        resolve(file);
      };
      img.src = url;
    });
  }

  function deriveTitle(){
    var t = ($('noteTitle').value || '').trim();
    if (t) return t.slice(0, 80);
    if (curKind === 1) {
      var mlines = (mdInput.value || '').split('\\n');
      for (var k = 0; k < mlines.length; k++) {
        var mline = mlines[k].replace(/^[\\s#>*-]+/, '').trim();
        if (mline) return mline.slice(0, 80);
      }
      return '新建备忘录';
    }
    var lines=(editor.innerText||'').split('\\n');
    for (var i=0;i<lines.length;i++){ var line=lines[i].trim(); if(line) return line.slice(0,80); }
    return '新建备忘录';
  }
  function fmt(ts){
    if (!ts) return '';
    var d=new Date(ts), now=new Date();
    if (d.toDateString()===now.toDateString()) return d.toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});
    return d.toLocaleDateString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit'});
  }
  function refreshPlaceholder(){
    var empty=(editor.innerText||'').trim()===''&&editor.querySelectorAll('img').length===0;
    editor.classList.toggle('is-empty', empty);
  }
  function showLogin(){ $('login').style.display='flex'; $('app').hidden=true; $('loginBtn').disabled=false; setTimeout(function(){$('pw').focus();},0); }
  function showApp(){ $('login').style.display='none'; $('app').hidden=false; }
  function setStatus(s){ $('status').textContent=s||''; }
  function showFmt(on){ $('fmtbar').classList.toggle('show', !!on && curKind === 0); }
  function markDirty(){
    dirty = true;
    setStatus('未保存');
    clearTimeout(autoSaveTimer);
    autoSaveTimer = setTimeout(function(){ if (dirty) saveNote(); }, 2500);
  }

  // 驱动富文本与 Markdown 编辑区显隐
  function renderEditorMode() {
    var open = currentId !== null;
    var isMd = curKind === 1;
    $('mdToggle').textContent = isMd ? '富文本' : 'MD';
    $('mdToggle').style.display = open ? 'inline-block' : 'none';
    $('previewToggle').style.display = (open && isMd) ? 'inline-block' : 'none';
    $('previewToggle').textContent = mdPreviewing ? '编辑' : '预览';

    if (!open) {
      $('fmtbar').classList.remove('show');
      editor.style.display = 'none';
      mdInput.style.display = 'none';
      mdPreview.style.display = 'none';
      return;
    }

    if (isMd) {
      $('fmtbar').classList.remove('show');
      editor.style.display = 'none';
      mdInput.style.display = mdPreviewing ? 'none' : 'block';
      mdPreview.style.display = mdPreviewing ? 'block' : 'none';
      if (mdPreviewing) {
        mdPreview.innerHTML = sanitize(mdToHtml(mdInput.value));
      }
    } else {
      $('fmtbar').classList.add('show');
      editor.style.display = 'block';
      mdInput.style.display = 'none';
      mdPreview.style.display = 'none';
      refreshPlaceholder();
    }
  }

  function updateEditorState() {
    var mainEl = document.querySelector('.main');
    if (currentId === null) {
      mainEl.classList.add('empty');
    } else {
      mainEl.classList.remove('empty');
    }
  }

  function loadNotes(){
    api('/api/notes').then(function(data){
      var promises = (data || []).map(function(n){
        if (n.format === 2) {
          return decryptData(n.title).then(function(decryptedTitle) {
            n.titlePlain = decryptedTitle;
            return n;
          });
        } else {
          n.titlePlain = n.title || '';
          return Promise.resolve(n);
        }
      });
      Promise.all(promises).then(function(decryptedNotes) {
        notes = decryptedNotes;
        showApp();
        renderList();
        loadShares(true);
        loadTrashNotes(false);
        updateEditorState();
      });
    }).catch(function(err){
      $('loginBtn').disabled = false;
      $('loginErr').textContent = '加载失败: ' + (err.message || err);
    });
  }

  function loadShares(andRender){
    return api('/api/shares').then(function(data){
      shares = Array.isArray(data) ? data : [];
      updateTabCounts();
      if (andRender && currentTab !== 'trash') renderList();
      updateShareBanner();
      return shares;
    }).catch(function(err){
      console.error('加载分享列表失败:', err);
    });
  }

  function loadTrashNotes(andRender){
    return api('/api/notes?trash=1').then(function(data){
      var promises = (data || []).map(function(n){
        if (n.format === 2) {
          return decryptData(n.title).then(function(decryptedTitle) {
            n.titlePlain = decryptedTitle;
            return n;
          });
        } else {
          n.titlePlain = n.title || '';
          return Promise.resolve(n);
        }
      });
      return Promise.all(promises).then(function(decryptedTrash){
        trashNotes = decryptedTrash;
        updateTabCounts();
        if (andRender && currentTab === 'trash') renderList();
        return trashNotes;
      });
    }).catch(function(err){
      console.error('加载回收站失败:', err);
    });
  }

  function updateTabCounts(){
    var tabAll = $('tabAll'), tabShared = $('tabShared'), tabTrash = $('tabTrash');
    if (tabAll) tabAll.textContent = '全部 (' + notes.length + ')';
    if (tabShared) tabShared.textContent = '已分享 (' + shares.length + ')';
    if (tabTrash) tabTrash.textContent = '回收站 (' + trashNotes.length + ')';
  }

  function getShareForNote(noteId, titlePlain) {
    if (!shares || !shares.length) return null;
    var found = null;
    if (noteId !== null && noteId !== undefined) {
      found = shares.find(function(s){ return s.note_id === noteId; });
    }
    if (!found && titlePlain) {
      found = shares.find(function(s){ return !s.note_id && s.title === titlePlain; });
    }
    return found;
  }

  function renderList(){
    var list=$('list'); list.innerHTML='';
    var q=query.trim().toLowerCase();
    updateTabCounts();

    // 1. 回收站视图
    if (currentTab === 'trash') {
      $('trashHeader').style.display = 'flex';
      $('search').style.display = 'none';
      var shownTrash = trashNotes.filter(function(n){
        return !q || (n.titlePlain || '').toLowerCase().indexOf(q) >= 0;
      });
      if (!shownTrash.length) {
        var te = document.createElement('div'); te.className = 'empty-list';
        te.textContent = q ? '没有匹配的已删除备忘录' : '回收站是空的';
        list.appendChild(te); return;
      }
      shownTrash.forEach(function(n){
        var item = document.createElement('div');
        item.className = 'item' + (n.id === currentId ? ' active' : '');
        var tWrap = document.createElement('div'); tWrap.className = 't-wrap';
        var t = document.createElement('div'); t.className = 't';
        var titleStr = (n.titlePlain && n.titlePlain.trim()) ? n.titlePlain : '无标题备忘录';
        t.textContent = titleStr; t.title = titleStr;
        tWrap.appendChild(t);
        if (n.kind === 1) {
          var mdBadge = document.createElement('span');
          mdBadge.className = 'badge-md'; mdBadge.textContent = 'MD';
          tWrap.appendChild(mdBadge);
        }

        var d = document.createElement('div'); d.className = 'd';
        d.textContent = '删除于 ' + fmt(n.deleted_at || n.updated_at);

        var actRow = document.createElement('div'); actRow.className = 'actions';
        actRow.style.cssText = 'display:flex; gap:6px; margin-top:6px; justify-content:flex-end;';

        var restoreBtn = document.createElement('button');
        restoreBtn.className = 'btn mini primary';
        restoreBtn.textContent = '恢复';
        restoreBtn.onclick = function(ev){
          ev.stopPropagation();
          restoreNote(n.id);
        };

        var purgeBtn = document.createElement('button');
        purgeBtn.className = 'btn mini danger';
        purgeBtn.textContent = '彻底删除';
        purgeBtn.onclick = function(ev){
          ev.stopPropagation();
          purgeNote(n.id);
        };

        actRow.appendChild(restoreBtn);
        actRow.appendChild(purgeBtn);

        item.appendChild(tWrap);
        item.appendChild(d);
        item.appendChild(actRow);

        item.onclick = function(){
          openNote(n.id, true);
        };
        list.appendChild(item);
      });
      return;
    }

    $('trashHeader').style.display = 'none';
    $('search').style.display = 'block';

    // 2. 已分享视图
    if (currentTab === 'shared') {
      var shownShares = shares.filter(function(s){
        return !q || (s.title || '').toLowerCase().indexOf(q) >= 0;
      });
      if (!shownShares.length) {
        var se = document.createElement('div'); se.className = 'empty-list';
        se.textContent = q ? '没有匹配的已分享备忘录' : '暂无已分享的备忘录。在编辑时点击“分享”即可生成公开链接。';
        list.appendChild(se); return;
      }
      shownShares.forEach(function(s){
        var isExpired = s.expires_at && s.expires_at < Date.now();
        var isSelected = (s.note_id && s.note_id === currentId) || (currentSnapshotShareId === s.id);
        var item = document.createElement('div');
        item.className = 'item' + (isSelected ? ' active' : '');

        var tWrap = document.createElement('div'); tWrap.className = 't-wrap';
        var t = document.createElement('div'); t.className = 't';
        var titleStr = (s.title && s.title.trim()) ? s.title : '无标题备忘录';
        t.textContent = titleStr; t.title = titleStr;
        var badge = document.createElement('span');
        badge.className = 'badge-share' + (isExpired ? ' expired' : '');
        badge.textContent = isExpired ? '已过期' : '分享中';
        tWrap.appendChild(t);
        tWrap.appendChild(badge);

        var d = document.createElement('div'); d.className = 'd';
        var expStr = s.expires_at ? ('到期: ' + fmt(s.expires_at)) : '到期: 永久有效';
        d.textContent = '分享于 ' + fmt(s.created_at) + ' · ' + expStr;

        var actRow = document.createElement('div'); actRow.className = 'actions';
        actRow.style.cssText = 'display:flex; gap:6px; margin-top:6px; justify-content:flex-end;';

        var copyBtn = document.createElement('button');
        copyBtn.className = 'btn mini';
        copyBtn.textContent = '复制链接';
        copyBtn.onclick = function(ev){
          ev.stopPropagation();
          copyShareUrl(s.id, copyBtn);
        };

        var extBtn = document.createElement('button');
        extBtn.className = 'btn mini primary';
        extBtn.textContent = '延长7天';
        extBtn.onclick = function(ev){
          ev.stopPropagation();
          extendShare(s.id, s.expires_at, 7 * 86400, extBtn);
        };

        var cancelBtn = document.createElement('button');
        cancelBtn.className = 'btn mini danger';
        cancelBtn.textContent = '取消分享';
        cancelBtn.onclick = function(ev){
          ev.stopPropagation();
          cancelShare(s.id, s.title);
        };

        actRow.appendChild(copyBtn);
        actRow.appendChild(extBtn);
        actRow.appendChild(cancelBtn);

        item.appendChild(tWrap);
        item.appendChild(d);
        item.appendChild(actRow);

        item.onclick = function(){
          openShareItem(s);
        };
        list.appendChild(item);
      });
      return;
    }

    // 3. 全部备忘录视图
    var shown=notes.filter(function(n){ return !q||(n.titlePlain||'').toLowerCase().indexOf(q)>=0; });
    if (!shown.length){
      var e=document.createElement('div'); e.className='empty-list';
      e.textContent=q?'没有匹配的备忘录':'还没有备忘录，点右上角 + 新建';
      list.appendChild(e); return;
    }
    shown.forEach(function(n){
      var item=document.createElement('div'); item.className='item'+(n.id===currentId?' active':'');
      var tWrap = document.createElement('div'); tWrap.className = 't-wrap';
      var t = document.createElement('div'); t.className = 't';
      var titleStr = (n.titlePlain&&n.titlePlain.trim())?n.titlePlain:'新建备忘录';
      t.textContent = titleStr; t.title = titleStr;
      tWrap.appendChild(t);

      if (n.kind === 1) {
        var mdBadge = document.createElement('span');
        mdBadge.className = 'badge-md'; mdBadge.textContent = 'MD';
        tWrap.appendChild(mdBadge);
      }

      var share = getShareForNote(n.id, n.titlePlain);
      if (share) {
        var sBadge = document.createElement('span');
        var isExpired = share.expires_at && share.expires_at < Date.now();
        sBadge.className = 'badge-share' + (isExpired ? ' expired' : '');
        sBadge.textContent = isExpired ? '分享过期' : '已分享';
        sBadge.title = isExpired ? '分享链接已过期' : (share.expires_at ? ('有效期至 ' + fmt(share.expires_at)) : '永久有效');
        tWrap.appendChild(sBadge);
      }

      var d=document.createElement('div'); d.className='d'; d.textContent=fmt(n.updated_at);
      item.appendChild(tWrap); item.appendChild(d);
      item.onclick=function(){ openNote(n.id); };
      list.appendChild(item);
    });
  }

  function openNote(id, isTrashPreview){
    currentSnapshotShareId = null;
    function load(){
      api('/api/notes/'+id).then(function(note){
        var titlePromise = note.format === 2 ? decryptData(note.title) : Promise.resolve(note.title || '');
        var contentPromise = note.format === 2 ? decryptData(note.content) : Promise.resolve(note.content || '');
        Promise.all([titlePromise, contentPromise]).then(function(decrypted) {
          currentId=id; dirty=false;
          curKind = note.kind || 0;
          mdPreviewing = false;
          $('noteTitle').value = decrypted[0];
          if (curKind === 1) {
            mdInput.value = decrypted[1] || '';
            editor.innerHTML = '';
          } else {
            editor.innerHTML = sanitize(decrypted[1] || '');
            mdInput.value = '';
          }
          refreshPlaceholder();
          renderEditorMode();
          var timePrefix = isTrashPreview ? '（已删除）' : '编辑于 ';
          setStatus(timePrefix + fmt(note.updated_at));
          renderList();
          $('app').classList.add('viewing');
          if (!isTrashPreview) {
            if (curKind === 1) mdInput.focus(); else editor.focus();
          }
          updateEditorState();
          updateShareBanner();
        });
      });
    }
    if (dirty) saveNote(load); else load();
  }

  function newNote(){
    currentSnapshotShareId = null;
    function go(){
      var s = getSettings();
      var defaultKind = parseInt(s.defaultKind, 10) || 0;
      Promise.all([
        encryptData(''),
        encryptData('')
      ]).then(function(encrypted) {
        return api('/api/notes',{
          method:'POST',
          body: JSON.stringify({ title: encrypted[0], content: encrypted[1], format: 2, kind: defaultKind })
        });
      }).then(function(n){
        notes.unshift({ id:n.id, title:'', updated_at:n.updated_at, titlePlain:'新建备忘录', format: 2, kind: defaultKind });
        currentId=n.id; dirty=false;
        curKind = defaultKind; mdPreviewing = false;
        $('noteTitle').value = '';
        editor.innerHTML=''; mdInput.value=''; mdPreview.innerHTML='';
        refreshPlaceholder();
        renderEditorMode();
        setStatus('新建'); renderList();
        $('app').classList.add('viewing');
        if (curKind === 1) mdInput.focus(); else editor.focus();
        updateEditorState();
        updateShareBanner();
      });
    }
    if (dirty) saveNote(go); else go();
  }

  function saveNote(after){
    if (currentId===null) return;
    var content = curKind === 1 ? mdInput.value : sanitize(editor.innerHTML);
    var titleText = deriveTitle();
    setStatus('保存中…');
    Promise.all([
      encryptData(titleText),
      encryptData(content)
    ]).then(function(encrypted) {
      return api('/api/notes/'+currentId,{
        method:'PUT',
        body: JSON.stringify({ title: encrypted[0], content: encrypted[1], format: 2, kind: curKind })
      });
    }).then(function(r){
      dirty=false;
      var n=notes.find(function(x){return x.id===currentId;});
      if(n){ n.titlePlain=titleText; n.updated_at=r.updated_at; n.format=2; n.kind=curKind; }
      notes.sort(function(a,b){return b.updated_at-a.updated_at;});
      renderList(); setStatus('已保存 '+fmt(r.updated_at));
      updateShareBanner();
      if (typeof after==='function') after();
    }).catch(function(err) {
      setStatus('保存错误: ' + err);
    });
  }

  function deleteNote(){
    if (currentId===null) return;
    uiConfirm('将这条备忘录移入回收站？其公开分享也将暂停生效。', { okText:'移入回收站' }).then(function(ok){
      if (!ok) return;
      var id=currentId;
      api('/api/notes/'+id,{method:'DELETE'}).then(function(){
        notes=notes.filter(function(x){return x.id!==id;});
        shares=shares.filter(function(s){return s.note_id!==id;});
        currentId=null; currentSnapshotShareId=null; dirty=false;
        $('noteTitle').value = '';
        editor.innerHTML=''; mdInput.value=''; mdPreview.innerHTML='';
        refreshPlaceholder();
        setStatus(''); renderEditorMode(); renderList(); $('app').classList.remove('viewing');
        updateEditorState();
        updateShareBanner();
        loadShares(false);
        loadTrashNotes(true);
        showToast('已移入回收站', 'info');
      }).catch(function(err){
        uiAlert('移入回收站失败: ' + err);
      });
    });
  }

  function restoreNote(id){
    api('/api/notes/'+id+'/restore', { method:'POST' }).then(function(){
      showToast('备忘录已恢复', 'success');
      loadNotes();
      loadTrashNotes(true);
    }).catch(function(err){
      uiAlert('恢复失败: ' + err);
    });
  }

  function purgeNote(id){
    uiConfirm('彻底删除后将无法恢复，确定彻底删除？', { danger: true, okText: '彻底删除' }).then(function(ok){
      if (!ok) return;
      api('/api/notes/'+id+'?hard=1', { method: 'DELETE' }).then(function(){
        trashNotes = trashNotes.filter(function(x){ return x.id !== id; });
        if (currentId === id) {
          currentId = null; dirty = false;
          $('noteTitle').value = ''; editor.innerHTML = ''; mdInput.value = ''; mdPreview.innerHTML = '';
          updateEditorState(); renderEditorMode();
        }
        showToast('已彻底删除', 'info');
        updateTabCounts();
        renderList();
      }).catch(function(err){
        uiAlert('删除失败: ' + err);
      });
    });
  }

  function emptyTrash(){
    if (!trashNotes.length) {
      uiAlert('回收站已经是空的');
      return;
    }
    uiConfirm('确定清空回收站吗？回收站内的所有备忘录将被彻底销毁且无法找回！', { danger: true, okText: '一键清空' }).then(function(ok){
      if (!ok) return;
      api('/api/notes/trash/empty', { method: 'POST' }).then(function(){
        trashNotes = [];
        if (currentId !== null && !notes.some(function(n){ return n.id === currentId; })) {
          currentId = null; dirty = false;
          $('noteTitle').value = ''; editor.innerHTML = ''; mdInput.value = ''; mdPreview.innerHTML = '';
          updateEditorState(); renderEditorMode();
        }
        showToast('回收站已清空', 'info');
        updateTabCounts();
        renderList();
      }).catch(function(err){
        uiAlert('清空失败: ' + err);
      });
    });
  }

  // ---- 备份导出与恢复 ----
  function exportNotes(){
    if (!notes.length) {
      uiAlert('当前没有可导出的备忘录');
      return;
    }
    showToast('正在导出备忘录…', 'info');
    setStatus('正在生成备份…');
    var promises = notes.map(function(n){
      return api('/api/notes/' + n.id).then(function(fullNote){
        var tp = fullNote.format === 2 ? decryptData(fullNote.title) : Promise.resolve(fullNote.title || '');
        var cp = fullNote.format === 2 ? decryptData(fullNote.content) : Promise.resolve(fullNote.content || '');
        return Promise.all([tp, cp]).then(function(dec){
          return {
            title: dec[0],
            content: dec[1],
            kind: fullNote.kind || 0,
            updated_at: fullNote.updated_at
          };
        });
      });
    });
    Promise.all(promises).then(function(exportedArr){
      var payload = {
        version: 1,
        generator: 'cloud-note',
        exported_at: Date.now(),
        notes: exportedArr
      };
      var jsonStr = JSON.stringify(payload, null, 2);
      var blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      var now = new Date();
      var pad = function(num){ return (num < 10 ? '0' : '') + num; };
      var dateStr = now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-' + pad(now.getDate());
      a.href = url;
      a.download = 'cloud-note-backup-' + dateStr + '.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function(){ URL.revokeObjectURL(url); }, 100);
      setStatus('导出完成');
      showToast('已成功导出 ' + exportedArr.length + ' 条备忘录', 'success');
    }).catch(function(err){
      uiAlert('导出失败: ' + err);
      setStatus('导出失败');
    });
  }

  function handleImportFile(file){
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(){
      try {
        var data = JSON.parse(reader.result);
        var arr = Array.isArray(data.notes) ? data.notes : (Array.isArray(data) ? data : null);
        if (!arr || !arr.length) {
          uiAlert('备份文件中没有可导入的笔记数据');
          return;
        }
        uiConfirm('检测到 ' + arr.length + ' 条备忘录，确定全部导入吗？将以端到端加密追加写入您的数据库。', { okText: '开始导入' }).then(function(ok){
          if (!ok) return;
          setStatus('正在导入 0/' + arr.length + '…');
          showToast('开始导入备忘录…', 'info');
          var count = 0;
          function importNext(index){
            if (index >= arr.length) {
              setStatus('导入完成！共 ' + count + ' 条');
              showToast('成功导入 ' + count + ' 条备忘录！', 'success');
              currentTab = 'all';
              $('tabAll').click();
              loadNotes();
              return;
            }
            var item = arr[index];
            var title = typeof item.title === 'string' ? item.title : '';
            var content = typeof item.content === 'string' ? item.content : '';
            var kind = item.kind === 1 ? 1 : 0;
            Promise.all([
              encryptData(title),
              encryptData(content)
            ]).then(function(enc){
              return api('/api/notes', {
                method: 'POST',
                body: JSON.stringify({
                  title: enc[0],
                  content: enc[1],
                  format: 2,
                  kind: kind
                })
              });
            }).then(function(){
              count++;
              setStatus('正在导入 ' + count + '/' + arr.length + '…');
              importNext(index + 1);
            }).catch(function(err){
              console.error('单条导入出错:', err);
              importNext(index + 1);
            });
          }
          importNext(0);
        });
      } catch (e) {
        uiAlert('解析备份文件失败，请确保是有效的 JSON 文件');
      }
    };
    reader.readAsText(file);
  }

  // ---- Markdown 模式切换与预览 ----
  $('mdToggle').onclick = function(){
    if (currentId === null) return;
    if (curKind === 0) {
      mdInput.value = editor.innerText.replace(/\\n$/, '');
      curKind = 1;
    } else {
      editor.innerHTML = sanitize(mdToHtml(mdInput.value));
      curKind = 0;
    }
    mdPreviewing = false;
    markDirty();
    renderEditorMode();
    if (curKind === 1) mdInput.focus(); else editor.focus();
  };

  $('previewToggle').onclick = function(){
    if (curKind !== 1) return;
    mdPreviewing = !mdPreviewing;
    renderEditorMode();
    if (!mdPreviewing) mdInput.focus();
  };

  mdInput.addEventListener('input', function(){ markDirty(); });
  mdInput.addEventListener('blur', function(){ if (dirty) saveNote(); });

  function openShareItem(s){
    if (s.note_id) {
      var n = notes.find(function(x){ return x.id === s.note_id; });
      if (n) {
        openNote(n.id);
        return;
      }
    }
    if (s.title) {
      var nByTitle = notes.find(function(x){ return x.titlePlain === s.title; });
      if (nByTitle) {
        openNote(nByTitle.id);
        return;
      }
    }
    function loadSnapshot() {
      api('/api/shares/' + s.id).then(function(detail){
        currentId = null;
        currentSnapshotShareId = s.id;
        dirty = false;
        curKind = 0;
        mdPreviewing = false;
        $('noteTitle').value = detail.title || '';
        editor.innerHTML = sanitize(detail.content || '');
        mdInput.value = '';
        refreshPlaceholder();
        renderEditorMode();
        setStatus('只读分享快照 (' + fmt(detail.created_at) + ')');
        renderList();
        showFmt(false);
        $('app').classList.add('viewing');
        updateEditorState();
        updateShareBanner();
      }).catch(function(err){
        uiAlert('加载分享快照失败: ' + err);
      });
    }
    if (dirty) saveNote(loadSnapshot); else loadSnapshot();
  }

  function updateShareBanner(){
    var banner = $('shareBanner');
    if (!banner) return;
    var share = null;
    if (currentId !== null) {
      share = getShareForNote(currentId, $('noteTitle').value);
    } else if (currentSnapshotShareId) {
      share = shares.find(function(s){ return s.id === currentSnapshotShareId; });
    }
    var shareBtn = $('shareBtn');
    if (!share) {
      banner.classList.remove('show');
      if (shareBtn) {
        shareBtn.textContent = '分享';
        shareBtn.classList.remove('primary');
      }
      return;
    }
    banner.classList.add('show');
    if (shareBtn) {
      shareBtn.textContent = '已分享';
      shareBtn.classList.add('primary');
    }
    var isExpired = share.expires_at && share.expires_at < Date.now();
    var expStr = share.expires_at ? ('到期: ' + fmt(share.expires_at)) : '永久有效';
    var statusHtml = isExpired
      ? '<span style="color:#d4584a;font-weight:600;">已过期</span> (' + expStr + ')'
      : '<span style="color:#2da44e;font-weight:600;">分享中</span> (' + expStr + ')';
    $('shareBannerText').innerHTML = '公开分享：' + statusHtml;

    $('sbCopyBtn').onclick = function(){
      copyShareUrl(share.id, $('sbCopyBtn'));
    };
    $('sbExtendBtn').onclick = function(){
      openShareModal(share);
    };
    $('sbCancelBtn').onclick = function(){
      cancelShare(share.id, share.title);
    };
  }

  function copyShareUrl(id, btnEl) {
    var url = window.location.origin + '/s/' + id;
    function done() {
      if (!btnEl) return;
      var old = btnEl.textContent;
      btnEl.textContent = '已复制！';
      btnEl.disabled = true;
      setTimeout(function() {
        btnEl.textContent = old;
        btnEl.disabled = false;
      }, 1500);
      showToast('分享链接已复制到剪贴板', 'success');
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(done).catch(function() {
        fallbackCopy(url, done);
      });
    } else {
      fallbackCopy(url, done);
    }
  }

  function fallbackCopy(text, cb) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch(e){}
    document.body.removeChild(ta);
    if (cb) cb();
  }

  function extendShare(shareId, currentExpires, addSeconds, btnEl) {
    var baseTime = (currentExpires && currentExpires > Date.now()) ? currentExpires : Date.now();
    var newExpires = addSeconds === 0 ? null : (baseTime + addSeconds * 1000);
    var oldText = btnEl ? btnEl.textContent : '';
    if (btnEl) {
      btnEl.disabled = true;
      btnEl.textContent = '延长中…';
    }
    api('/api/shares/' + shareId + '/extend', {
      method: 'POST',
      body: JSON.stringify({ expires_at: newExpires })
    }).then(function() {
      setStatus('分享有效期已更新');
      showToast('分享有效期已更新', 'success');
      loadShares(true);
      if ($('shareModal').classList.contains('show')) {
        var updatedShare = shares.find(function(s){ return s.id === shareId; });
        if (updatedShare) openShareModal(updatedShare);
      }
    }).catch(function(err) {
      uiAlert('延长失败: ' + err);
    }).finally(function() {
      if (btnEl) {
        btnEl.disabled = false;
        btnEl.textContent = oldText;
      }
    });
  }

  function cancelShare(shareId, title) {
    var name = title ? ('“' + title + '”') : '该备忘录';
    uiConfirm('确定要取消' + name + '的公开分享吗？分享链接将即刻失效。', { danger: true, okText: '取消分享' }).then(function(ok){
      if (!ok) return;
      setStatus('正在取消分享…');
      api('/api/shares/' + shareId, {
        method: 'DELETE'
      }).then(function() {
        setStatus('分享已取消');
        showToast('已取消分享链接', 'info');
        if (currentSnapshotShareId === shareId) {
          currentSnapshotShareId = null;
        }
        $('shareModal').classList.remove('show');
        loadShares(true);
      }).catch(function(err) {
        uiAlert('取消失败: ' + err);
        setStatus('取消失败: ' + err);
      });
    });
  }

  function syncShareContent(shareId) {
    var content = curKind === 1 ? mdToHtml(mdInput.value) : sanitize(editor.innerHTML);
    var titleText = deriveTitle();
    setStatus('正在更新分享内容…');
    api('/api/shares/' + shareId, {
      method: 'PUT',
      body: JSON.stringify({ title: titleText, content: content })
    }).then(function() {
      setStatus('分享内容已同步更新');
      loadShares(true);
      showToast('已成功同步最新内容到分享链接！', 'success');
    }).catch(function(err) {
      uiAlert('更新失败: ' + err);
      setStatus('更新失败: ' + err);
    });
  }

  function openShareModal(existingShare) {
    var share = existingShare || (currentId !== null ? getShareForNote(currentId, $('noteTitle').value) : null);
    if (!share && currentSnapshotShareId) {
      share = shares.find(function(s){ return s.id === currentSnapshotShareId; });
    }

    if (share) {
      $('shareModalTitle').textContent = '管理已分享备忘录';
      $('shareModalDesc').textContent = '此备忘录已公开分享，可在下方管理链接、延长有效期或取消分享。';
      $('shareExistingArea').style.display = 'block';
      $('shareConfigArea').style.display = 'none';
      $('shareResultArea').style.display = 'none';
      $('shareActionBtn').style.display = 'none';
      $('copyShareBtn').style.display = 'none';

      var shareUrl = window.location.origin + '/s/' + share.id;
      $('shareExistingUrlInput').value = shareUrl;

      var isExpired = share.expires_at && share.expires_at < Date.now();
      var expStr = share.expires_at ? ('有效期至 ' + fmt(share.expires_at)) : '永久有效';
      $('shareExistingStatus').innerHTML = '当前状态：' + (isExpired
        ? '<strong style="color:#d4584a;">已过期</strong> (' + expStr + ')'
        : '<strong style="color:#2da44e;">分享中</strong> (' + expStr + ')');

      $('shareExistingCopyBtn').onclick = function(){
        copyShareUrl(share.id, $('shareExistingCopyBtn'));
      };
      $('shareQuickExtend7Btn').onclick = function(){
        extendShare(share.id, share.expires_at, 7 * 86400, $('shareQuickExtend7Btn'));
      };
      $('shareQuickExtend30Btn').onclick = function(){
        extendShare(share.id, share.expires_at, 30 * 86400, $('shareQuickExtend30Btn'));
      };
      $('shareQuickExtendForeverBtn').onclick = function(){
        extendShare(share.id, share.expires_at, 0, $('shareQuickExtendForeverBtn'));
      };
      $('shareSyncContentBtn').onclick = function(){
        syncShareContent(share.id);
      };
      $('shareExistingCancelBtn').onclick = function(){
        cancelShare(share.id, share.title);
      };
    } else {
      $('shareModalTitle').textContent = '分享此备忘录';
      $('shareModalDesc').textContent = '生成只读分享链接。未分享的备忘录保持端到端加密。';
      $('shareExistingArea').style.display = 'none';
      $('shareConfigArea').style.display = 'block';
      $('shareResultArea').style.display = 'none';
      $('shareActionBtn').style.display = 'inline-block';
      $('shareActionBtn').textContent = '生成分享链接';
      $('copyShareBtn').style.display = 'none';
      $('shareExpireSelect').value = '0';
      $('shareCustomDaysWrap').style.display = 'none';
      $('shareCustomDaysInput').value = '';
    }
    $('shareModal').classList.add('show');
  }

  function shareNote() {
    if (currentId === null && !currentSnapshotShareId) return;
    if (dirty) {
      saveNote(function(){ openShareModal(); });
    } else {
      openShareModal();
    }
  }

  function executeCreateShare() {
    var content = curKind === 1 ? mdToHtml(mdInput.value) : sanitize(editor.innerHTML);
    var titleText = deriveTitle();
    var expireVal = $('shareExpireSelect').value;
    var expires_in = 0;

    if (expireVal === 'custom') {
      var days = parseInt($('shareCustomDaysInput').value, 10);
      if (isNaN(days) || days <= 0) {
        uiAlert('请输入有效的自定义天数（大于0的整数）');
        return;
      }
      expires_in = days * 86400;
    } else {
      expires_in = parseInt(expireVal, 10);
    }

    setStatus('准备分享…');
    api('/api/share', {
      method: 'POST',
      body: JSON.stringify({
        title: titleText,
        content: content,
        expires_in: expires_in,
        note_id: currentId
      })
    }).then(function(res) {
      if (res.id) {
        var shareUrl = window.location.origin + '/s/' + res.id;
        $('shareUrlInput').value = shareUrl;

        $('shareConfigArea').style.display = 'none';
        $('shareExistingArea').style.display = 'none';
        $('shareResultArea').style.display = 'block';
        $('shareActionBtn').style.display = 'none';
        $('copyShareBtn').style.display = 'inline-block';

        setStatus('分享链接已生成');
        showToast('分享链接生成成功！', 'success');
        loadShares(true);
      } else {
        setStatus('生成分享链接失败: ' + (res.error || '未知错误'));
      }
    }).catch(function(err) {
      setStatus('分享失败: ' + err);
    });
  }

  // ---- 富文本（contenteditable + execCommand） ----
  function saveSel(){ var s=window.getSelection(); if (s.rangeCount && editor.contains(s.anchorNode)) savedRange=s.getRangeAt(0).cloneRange(); }
  function withSel(fn){
    editor.focus();
    if (savedRange){ var s=window.getSelection(); s.removeAllRanges(); s.addRange(savedRange); }
    fn(); saveSel(); markDirty(); refreshPlaceholder();
  }
  function exec(cmd,val){ document.execCommand('styleWithCSS',false,true); document.execCommand(cmd,false,val); }
  document.addEventListener('selectionchange', saveSel);

  Array.prototype.forEach.call(document.querySelectorAll('.fmtbar .fb'), function(b){
    b.addEventListener('mousedown', function(e){ e.preventDefault(); });
  });
  Array.prototype.forEach.call(document.querySelectorAll('.fmtbar [data-cmd]'), function(b){
    b.addEventListener('click', function(){ withSel(function(){ exec(b.getAttribute('data-cmd')); }); });
  });
  $('fFont').addEventListener('change', function(e){ var v=e.target.value; withSel(function(){ if(v) exec('fontName',v); }); e.target.selectedIndex=0; });
  $('fColor').addEventListener('input', function(e){ var v=e.target.value; withSel(function(){ exec('foreColor',v); }); });
  $('fSize').addEventListener('change', function(e){
    var px=e.target.value; e.target.selectedIndex=0; if(!px) return;
    withSel(function(){
      document.execCommand('fontSize',false,'7');
      var marks=editor.querySelectorAll('font[size="7"]');
      for (var i=0;i<marks.length;i++){ marks[i].removeAttribute('size'); marks[i].style.fontSize=px; }
    });
  });
  $('bCode').addEventListener('click', function(){ withSel(function(){
    var t=window.getSelection().toString();
    if (t) document.execCommand('insertHTML',false,'<code>'+escapeHtml(t)+'</code>');
  }); });
  $('bPre').addEventListener('click', function(){ withSel(function(){
    var t=window.getSelection().toString();
    document.execCommand('insertHTML',false,'<pre><code>'+escapeHtml(t||'')+'</code></pre><p><br></p>');
  }); });
  $('bLink').addEventListener('click', function(){
    uiPrompt('请输入超链接地址（http/https）', '', '插入超链接').then(function(url){
      if(!url) return;
      if(!/^https?:\\/\\//i.test(url)) url='https://'+url;
      if (curKind === 1) {
        var md = $('mdInput');
        var start = md.selectionStart, end = md.selectionEnd;
        var text = md.value;
        var sel = text.slice(start, end) || '链接描述';
        var mdLink = '[' + sel + '](' + url + ')';
        md.value = text.slice(0, start) + mdLink + text.slice(end);
        md.selectionStart = md.selectionEnd = start + mdLink.length;
        markDirty();
      } else {
        withSel(function(){
          var sel=window.getSelection();
          if (sel && sel.toString()) document.execCommand('createLink',false,url);
          else document.execCommand('insertHTML',false,'<a href="'+escapeAttr(url)+'" target="_blank" rel="noopener noreferrer">'+escapeHtml(url)+'</a>');
        });
      }
    });
  });

  function uploadFile(file) {
    if (!file) return;
    if (file.size > 25 * 1024 * 1024) {
      uiAlert('图片过大（超过 25MB），请先裁剪缩小再上传');
      return;
    }
    setStatus('图片压缩并上传中…');
    compressImage(file).then(function(processedFile) {
      var fd = new FormData();
      fd.append('file', processedFile);
      return api('/api/upload', {
        method: 'POST',
        body: fd
      });
    }).then(function(res) {
      if (res.url) {
        if (curKind === 1) {
          var md = $('mdInput');
          var start = md.selectionStart, end = md.selectionEnd;
          var text = md.value;
          var mdImg = '![](' + res.url + ')';
          md.value = text.slice(0, start) + mdImg + text.slice(end);
          md.selectionStart = md.selectionEnd = start + mdImg.length;
          markDirty();
        } else {
          withSel(function() {
            document.execCommand('insertImage', false, res.url);
          });
          refreshPlaceholder();
          markDirty();
        }
        setStatus('图片上传成功');
        showToast('图片已上传', 'success');
      } else {
        setStatus('图片上传失败: ' + (res.error || '未知错误'));
        showToast('图片上传失败', 'error');
      }
    }).catch(function(e) {
      setStatus('图片上传网络错误: ' + e);
      showToast('上传错误: ' + e, 'error');
    });
  }

  $('fileInput').addEventListener('change', function(e) {
    var file = e.target.files[0];
    if (file) {
      uploadFile(file);
      e.target.value = '';
    }
  });

  $('importFile').addEventListener('change', function(e) {
    var file = e.target.files[0];
    if (file) {
      handleImportFile(file);
      e.target.value = '';
    }
  });

  $('bImg').addEventListener('click', function(){
    uiConfirm('选择本地图片压缩上传？（点取消可手动输入图片 URL）', { okText: '本地图片', cancelText: '网络 URL' }).then(function(useLocal){
      if (useLocal) {
        $('fileInput').click();
      } else {
        uiPrompt('请输入图片地址（http/https）', '', '插入网络图片').then(function(url){
          if (!url) return;
          if (!/^https?:\\/\\//i.test(url)) url = 'https://' + url;
          if (curKind === 1) {
            var md = $('mdInput');
            var start = md.selectionStart, end = md.selectionEnd;
            var text = md.value;
            var mdImg = '![](' + url + ')';
            md.value = text.slice(0, start) + mdImg + text.slice(end);
            md.selectionStart = md.selectionEnd = start + mdImg.length;
            markDirty();
          } else {
            withSel(function(){ document.execCommand('insertImage', false, url); });
          }
        });
      }
    });
  });

  $('bClear').addEventListener('click', function(){ withSel(function(){ document.execCommand('removeFormat'); document.execCommand('unlink'); }); });

  editor.addEventListener('paste', function(e){
    var items = (e.clipboardData || window.clipboardData).items;
    for (var i = 0; i < items.length; i++) {
      if (items[i].type.indexOf('image') !== -1) {
        e.preventDefault();
        var file = items[i].getAsFile();
        uploadFile(file);
        return;
      }
    }
    e.preventDefault();
    var cd=e.clipboardData||window.clipboardData;
    var htmlStr=cd.getData('text/html');
    var clean=htmlStr?sanitize(htmlStr):escapeHtml(cd.getData('text/plain')).replace(/\\n/g,'<br>');
    document.execCommand('insertHTML',false,clean);
    markDirty(); refreshPlaceholder();
  });

  editor.addEventListener('drop', function(e){
    var files = e.dataTransfer.files;
    if (files && files.length > 0) {
      for (var i = 0; i < files.length; i++) {
        if (files[i].type.indexOf('image') !== -1) {
          e.preventDefault();
          uploadFile(files[i]);
          return;
        }
      }
    }
  });

  editor.addEventListener('input', function(){ markDirty(); refreshPlaceholder(); });
  editor.addEventListener('blur', function(){ if (dirty) saveNote(); });
  $('noteTitle').addEventListener('input', function(){ markDirty(); });
  $('noteTitle').addEventListener('blur', function(){ if (dirty) saveNote(); });

  $('saveBtn').onclick=function(){ saveNote(); };
  $('delBtn').onclick=deleteNote;
  $('newBtn').onclick=newNote;
  $('backBtn').onclick=function(){ if(dirty) saveNote(); $('app').classList.remove('viewing'); };
  $('shareBtn').onclick = shareNote;
  $('closeShareBtn').onclick = function() { $('shareModal').classList.remove('show'); };
  $('shareModal').onclick = function(e) { if (e.target === this) this.classList.remove('show'); };
  $('shareActionBtn').onclick = executeCreateShare;
  $('shareExpireSelect').onchange = function() {
    $('shareCustomDaysWrap').style.display = this.value === 'custom' ? 'block' : 'none';
    if (this.value === 'custom') { $('shareCustomDaysInput').focus(); }
  };

  // ---- 标签切换 ----
  $('tabAll').onclick = function() {
    currentTab = 'all';
    $('tabAll').classList.add('active');
    $('tabShared').classList.remove('active');
    $('tabTrash').classList.remove('active');
    renderList();
  };
  $('tabShared').onclick = function() {
    currentTab = 'shared';
    $('tabShared').classList.add('active');
    $('tabAll').classList.remove('active');
    $('tabTrash').classList.remove('active');
    renderList();
  };
  $('tabTrash').onclick = function() {
    currentTab = 'trash';
    $('tabTrash').classList.add('active');
    $('tabAll').classList.remove('active');
    $('tabShared').classList.remove('active');
    loadTrashNotes(true);
  };
  $('emptyTrashBtn').onclick = emptyTrash;
  $('shareManageBtn').onclick = function() { $('tabShared').click(); };

  // ---- 导出与导入备份按钮 ----
  $('exportBtn').onclick = function(){ closeMore(); exportNotes(); };
  $('importBtn').onclick = function(){ closeMore(); $('importFile').click(); };

  $('copyShareBtn').onclick = function() {
    var input = $('shareUrlInput');
    input.select();
    input.setSelectionRange(0, 99999);
    var self = this;
    function done() {
      var old = self.textContent;
      self.textContent = '已复制！';
      self.disabled = true;
      setTimeout(function() {
        self.textContent = old;
        self.disabled = false;
      }, 2000);
      showToast('分享链接已复制！', 'success');
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(input.value).then(done).catch(function() {
        document.execCommand('copy');
        done();
      });
    } else {
      document.execCommand('copy');
      done();
    }
  };

  $('logoutBtn').onclick = function(){
    closeMore();
    uiConfirm('确定要退出登录吗？').then(function(ok){
      if (ok) {
        sessionStorage.removeItem('session_key');
        api('/api/logout', { method:'POST' }).then(function(){ location.reload(); });
      }
    });
  };

  $('search').addEventListener('input', function(e){ query=e.target.value; renderList(); });
  document.addEventListener('keydown', function(e){
    if ((e.metaKey||e.ctrlKey) && e.key.toLowerCase()==='s'){ e.preventDefault(); saveNote(); }
  });
  window.addEventListener('beforeunload', function(e){ if(dirty){ e.preventDefault(); e.returnValue=''; } });
  setInterval(function(){ if (dirty) saveNote(); }, 30000);

  function doLogin(){
    var pwVal = $('pw').value;
    $('loginErr').textContent=''; $('loginBtn').disabled=true;
    fetch('/api/login',{ method:'POST', credentials:'same-origin',
      headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({ password:pwVal }) })
      .then(function(res){
        if (res.ok){
          deriveKey(pwVal).then(function() {
            $('pw').value=''; $('loginBtn').disabled=false; loadNotes();
          }).catch(function(e) {
            $('loginBtn').disabled=false;
            $('loginErr').textContent='密钥派生错误: ' + (e.message || e);
          });
          return;
        }
        return res.json().then(function(d){
          $('loginBtn').disabled=false;
          if (res.status===429) $('loginErr').textContent='尝试过多，请约 '+(d.retry_after||60)+' 秒后再试';
          else if (typeof d.remaining==='number') $('loginErr').textContent='密码错误，还可尝试 '+d.remaining+' 次';
          else $('loginErr').textContent=d.error || '密码错误';
        }).catch(function(){
          $('loginBtn').disabled=false;
          $('loginErr').textContent='服务器错误 (状态码 ' + res.status + ')';
        });
      })
      .catch(function(err){
        $('loginBtn').disabled=false;
        $('loginErr').textContent='网络错误: ' + (err.message || err);
      });
  }
  $('loginBtn').onclick=doLogin;
  $('pw').addEventListener('keydown', function(e){ if(e.key==='Enter') doLogin(); });
  $('togglePw').onclick=function(){
    var pw=$('pw');
    var isPw=pw.type==='password';
    pw.type=isPw?'text':'password';
    this.innerHTML=isPw
      ?'<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle><line x1="1" y1="1" x2="23" y2="23"></line></svg>'
      :'<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
  };

  var keyStr = sessionStorage.getItem('session_key');
  if (keyStr) {
    window.crypto.subtle.importKey(
      'raw',
      base64urlDecode(keyStr),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    ).then(function(key) {
      sessionKey = key;
      loadNotes();
    }).catch(function() {
      showLogin();
    });
  } else {
    showLogin();
  }
})();
</script>
</body>
</html>`;