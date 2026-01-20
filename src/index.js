/**
 * Cloudflare Worker (单文件版) - 邮箱注册/登录 + 套餐/订单 + USDT(地址收款)支付页
 *
 * 入口建议：src/index.js（wrangler.jsonc 里 main 指向它）
 *
 * 需要绑定（Bindings）：
 * - D1 Database：DB
 *
 * 建议设置的环境变量（Variables / Secrets）：
 * - SESSION_SECRET        （必填，用于签名 session id）
 * - ALLOW_REGISTER        （可选，默认 true）
 * - ADMIN_TOKEN           （可选，后台接口/页面鉴权用）
 * - USDT_ADDRESS          （必填，你的收款地址）
 * - USDT_NETWORK          （可选，默认 "TRC20"）
 * - USDT_RATE             （可选，USDT 对 USD 汇率，默认 1）
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // ========= 基础配置 =========
    const ALLOW_REGISTER = (env.ALLOW_REGISTER ?? "true").toLowerCase() === "true";
    const SESSION_SECRET = env.SESSION_SECRET || "";
    const ADMIN_TOKEN = env.ADMIN_TOKEN || "";
    const USDT_ADDRESS = env.USDT_ADDRESS || "";
    const USDT_NETWORK = env.USDT_NETWORK || "TRC20";
    const USDT_RATE = Number(env.USDT_RATE || "1") || 1;

    // ========= 工具函数 =========
    const json = (data, status = 200, headers = {}) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
      });

    const html = (body, status = 200, headers = {}) =>
      new Response(body, {
        status,
        headers: { "Content-Type": "text/html; charset=utf-8", ...headers },
      });

    const redirect = (to, status = 302, headers = {}) =>
      new Response(null, {
        status,
        headers: { Location: to, ...headers },
      });

    const badRequest = (msg = "Bad Request") => json({ ok: false, error: msg }, 400);
    const unauthorized = (msg = "Unauthorized") => json({ ok: false, error: msg }, 401);
    const forbidden = (msg = "Forbidden") => json({ ok: false, error: msg }, 403);
    const notFound = () => new Response("Not Found", { status: 404 });

    const escapeHtml = (s = "") =>
      String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const parseJSON = async (req) => {
      try {
        return await req.json();
      } catch {
        return null;
      }
    };

    const sha256hex = async (str) => {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
    };

    const timingSafeEq = (a, b) => {
      const aa = new TextEncoder().encode(String(a));
      const bb = new TextEncoder().encode(String(b));
      if (aa.length !== bb.length) return false;
      let out = 0;
      for (let i = 0; i < aa.length; i++) out |= aa[i] ^ bb[i];
      return out === 0;
    };

    const sign = async (payload) => {
      if (!SESSION_SECRET) return "";
      return sha256hex(`${payload}.${SESSION_SECRET}`);
    };

    const nowIso = () => new Date().toISOString();
    const addDays = (days) => new Date(Date.now() + days * 86400000).toISOString();

    const parseCookie = (cookieHeader = "") => {
      const out = {};
      cookieHeader.split(";").forEach((part) => {
        const [k, ...v] = part.trim().split("=");
        if (!k) return;
        out[k] = decodeURIComponent(v.join("=") || "");
      });
      return out;
    };

    const setCookie = (name, value, opts = {}) => {
      const { path = "/", httpOnly = true, sameSite = "Lax", secure = true, maxAge } = opts;
      let s = `${name}=${encodeURIComponent(value)}; Path=${path}; SameSite=${sameSite}`;
      if (secure) s += `; Secure`;
      if (httpOnly) s += `; HttpOnly`;
      if (typeof maxAge === "number") s += `; Max-Age=${maxAge}`;
      return s;
    };

    const getClientIp = (req) =>
      req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "";

    const getUA = (req) => req.headers.get("User-Agent") || "";

    const requireAdmin = (req) => {
      if (!ADMIN_TOKEN) return false;
      const token =
        req.headers.get("X-Admin-Token") ||
        new URL(req.url).searchParams.get("token") ||
        "";
      return timingSafeEq(token, ADMIN_TOKEN);
    };

    // ========= D1 初始化检查 =========
    if (!env.DB)
      return html(
        `<h1>DB 绑定缺失</h1><p>请在 Worker 的 Bindings 里绑定 D1 Database：DB</p>`,
        500
      );

    // ========= DB 建表 SQL（后台页面展示用） =========
    const schemaSql = `-- Users
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Sessions
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  ip TEXT,
  ua TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);

-- Plans
CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  data_gb INTEGER NOT NULL,
  days INTEGER NOT NULL,
  price_usd REAL NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1
);

-- Orders
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  plan_id INTEGER NOT NULL,
  status TEXT NOT NULL,               -- created / paid / cancelled
  amount_usd REAL NOT NULL,
  amount_usdt REAL NOT NULL,
  tx_hash TEXT,                       -- 可空（不填 hash 就留空）
  created_at TEXT NOT NULL,
  paid_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(plan_id) REFERENCES plans(id)
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
`;

    // ========= 会话 =========
    const cookies = parseCookie(request.headers.get("Cookie") || "");
    const sid = cookies.sid || "";

    const getSession = async () => {
      if (!sid) return null;
      const parts = sid.split(".");
      if (parts.length !== 2) return null;
      const [id, sig] = parts;
      const expect = await sign(id);
      if (!expect || !timingSafeEq(sig, expect)) return null;

      const row = await env.DB.prepare(
        `SELECT s.id, s.user_id, s.expires_at, u.email
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.id = ?`
      )
        .bind(id)
        .first();

      if (!row) return null;
      if (row.expires_at && Date.parse(row.expires_at) < Date.now()) return null;
      return row;
    };

    const requireLogin = async () => {
      const sess = await getSession();
      return sess || null;
    };

    const createSession = async (userId, req) => {
      const id = crypto.randomUUID();
      const created_at = nowIso();
      const expires_at = addDays(30);

      await env.DB.prepare(
        `INSERT INTO sessions (id, user_id, created_at, expires_at, ip, ua)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(id, userId, created_at, expires_at, getClientIp(req), getUA(req))
        .run();

      const sig = await sign(id);
      return `${id}.${sig}`;
    };

    const destroySession = async (req) => {
      const c = parseCookie(req.headers.get("Cookie") || "");
      const v = c.sid || "";
      const parts = v.split(".");
      if (parts.length === 2) {
        const [id] = parts;
        await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(id).run();
      }
    };

    // ========= 页面布局 =========
    const pageShell = ({ title, body, userEmail = "" }) => {
      const nav = `
        <div class="nav">
          <a href="/">首页</a>
          <a href="/pay">购买/支付</a>
          <a href="/order">我的订单</a>
          <div class="spacer"></div>
          ${
            userEmail
              ? `<span class="muted">${escapeHtml(userEmail)}</span> <a href="/logout">退出</a>`
              : `<a href="/login">登录</a> <a href="/register">注册</a>`
          }
        </div>
      `;

      return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root{--bg:#0b1020;--card:#111a33;--text:#e8ecff;--muted:#aab3d6;--btn:#2f6bff;}
    body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:linear-gradient(180deg,#070b16,#0b1020);color:var(--text);}
    a{color:#bcd1ff;text-decoration:none}
    .wrap{max-width:980px;margin:0 auto;padding:24px}
    .nav{display:flex;gap:14px;align-items:center;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:12px 14px;border-radius:14px}
    .spacer{flex:1}
    .card{margin-top:16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:18px;padding:18px}
    .row{display:flex;gap:14px;flex-wrap:wrap}
    .col{flex:1;min-width:280px}
    .h1{font-size:28px;margin:0 0 10px 0}
    .muted{color:var(--muted)}
    .line{height:1px;background:rgba(255,255,255,.08);margin:14px 0}
    .btn{display:inline-block;background:var(--btn);color:white;padding:10px 14px;border-radius:12px;border:0;cursor:pointer}
    .btn.gray{background:rgba(255,255,255,.14)}
    input{width:100%;padding:11px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.25);color:var(--text);outline:none}
    label{display:block;margin:10px 0 6px 0;color:var(--muted);font-size:13px}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
    code{background:rgba(0,0,0,.35);padding:2px 6px;border-radius:8px}
    .ok{color:#6dffa8}
    .bad{color:#ff6d6d}
    .chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.25)}
  </style>
</head>
<body>
  <div class="wrap">
    ${nav}
    <div class="card">${body}</div>
    <div class="muted" style="margin-top:14px;font-size:12px">Powered by Cloudflare Workers + D1</div>
  </div>
</body>
</html>`;
    };

    // ========= 业务：用户 =========
    const findUserByEmail = async (email) => {
      return env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
    };

    const createUser = async (email, password) => {
      const id = crypto.randomUUID();
      const pwdHash = await sha256hex(`pwd:${email}:${password}`);
      await env.DB.prepare(
        `INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`
      )
        .bind(id, email, pwdHash, nowIso())
        .run();
      return { id, email };
    };

    const verifyPassword = async (user, password) => {
      const pwdHash = await sha256hex(`pwd:${user.email}:${password}`);
      return timingSafeEq(pwdHash, user.password_hash);
    };

    // ========= 业务：套餐/订单 =========
    const listPlans = async () => {
      const rs = await env.DB.prepare(
        `SELECT * FROM plans WHERE is_active = 1 ORDER BY price_usd ASC`
      ).all();
      return rs.results || [];
    };

    const getPlan = async (planId) => {
      return env.DB.prepare(`SELECT * FROM plans WHERE id = ? AND is_active = 1`)
        .bind(planId)
        .first();
    };

    const createOrder = async ({ userId, plan }) => {
      const id = crypto.randomUUID();
      const amount_usd = Number(plan.price_usd);
      const amount_usdt = Number((amount_usd / USDT_RATE).toFixed(2));
      await env.DB.prepare(
        `INSERT INTO orders (id, user_id, plan_id, status, amount_usd, amount_usdt, created_at)
         VALUES (?, ?, ?, 'created', ?, ?, ?)`
      )
        .bind(id, userId, plan.id, amount_usd, amount_usdt, nowIso())
        .run();
      return { id, amount_usd, amount_usdt };
    };

    const listOrdersByUser = async (userId) => {
      const rs = await env.DB.prepare(
        `SELECT o.*, p.name AS plan_name, p.data_gb, p.days
         FROM orders o
         JOIN plans p ON p.id = o.plan_id
         WHERE o.user_id = ?
         ORDER BY o.created_at DESC`
      )
        .bind(userId)
        .all();
      return rs.results || [];
    };

    const getOrderById = async (orderId) => {
      return env.DB.prepare(
        `SELECT o.*, p.name AS plan_name, p.data_gb, p.days
         FROM orders o
         JOIN plans p ON p.id = o.plan_id
         WHERE o.id = ?`
      )
        .bind(orderId)
        .first();
    };

    const markOrderPaid = async ({ orderId, txHash = null }) => {
      await env.DB.prepare(
        `UPDATE orders SET status='paid', paid_at=?, tx_hash=COALESCE(?, tx_hash) WHERE id=?`
      )
        .bind(nowIso(), txHash, orderId)
        .run();
    };

    // ========= API 路由 =========
    if (path === "/api/health") return json({ ok: true });

    if (method === "GET" && path === "/api/plans") {
      const plans = await listPlans();
      return json({ ok: true, plans });
    }

    if (method === "POST" && path === "/api/register") {
      if (!ALLOW_REGISTER) return forbidden("Register disabled");
      const body = await parseJSON(request);
      if (!body) return badRequest("bad json");

      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!email || !password) return badRequest("email/password required");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return badRequest("invalid email");
      if (password.length < 6) return badRequest("password too short (>=6)");

      const existed = await findUserByEmail(email);
      if (existed) return badRequest("email already exists");

      const user = await createUser(email, password);
      const sidVal = await createSession(user.id, request);

      return json(
        { ok: true, user: { email: user.email } },
        200,
        { "Set-Cookie": setCookie("sid", sidVal, { maxAge: 60 * 60 * 24 * 30 }) }
      );
    }

    if (method === "POST" && path === "/api/login") {
      const body = await parseJSON(request);
      if (!body) return badRequest("bad json");

      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!email || !password) return badRequest("email/password required");

      const user = await findUserByEmail(email);
      if (!user) return badRequest("invalid email or password");

      const ok = await verifyPassword(user, password);
      if (!ok) return badRequest("invalid email or password");

      const sidVal = await createSession(user.id, request);

      return json(
        { ok: true, user: { email: user.email } },
        200,
        { "Set-Cookie": setCookie("sid", sidVal, { maxAge: 60 * 60 * 24 * 30 }) }
      );
    }

    if (method === "POST" && path === "/api/logout") {
      await destroySession(request);
      return json({ ok: true }, 200, { "Set-Cookie": setCookie("sid", "", { maxAge: 0 }) });
    }

    if (method === "GET" && path === "/api/me") {
      const sess = await getSession();
      return json({ ok: true, user: sess ? { email: sess.email, user_id: sess.user_id } : null });
    }

    // 创建订单（登录后）
    if (method === "POST" && path === "/api/order/create") {
      const sess = await requireLogin();
      if (!sess) return unauthorized("login required");
      if (!USDT_ADDRESS) return json({ ok: false, error: "USDT_ADDRESS not set" }, 500);

      const body = await parseJSON(request);
      if (!body) return badRequest("bad json");

      const planId = Number(body.plan_id);
      if (!planId) return badRequest("plan_id required");

      const plan = await getPlan(planId);
      if (!plan) return badRequest("plan not found");

      const order = await createOrder({ userId: sess.user_id, plan });

      return json({
        ok: true,
        order: {
          id: order.id,
          plan_id: plan.id,
          plan_name: plan.name,
          amount_usd: order.amount_usd,
          amount_usdt: order.amount_usdt,
          usdt_address: USDT_ADDRESS,
          usdt_network: USDT_NETWORK,
        },
      });
    }

    // 我的订单（登录后）
    if (method === "GET" && path === "/api/orders") {
      const sess = await requireLogin();
      if (!sess) return unauthorized("login required");
      const orders = await listOrdersByUser(sess.user_id);
      return json({ ok: true, orders });
    }

    // 单个订单（登录后）
    if (method === "GET" && path.startsWith("/api/order/")) {
      const seg = path.split("/").filter(Boolean); // api order {id}
      if (seg.length === 3) {
        const orderId = seg[2];
        const sess = await requireLogin();
        if (!sess) return unauthorized("login required");

        const order = await getOrderById(orderId);
        if (!order || order.user_id !== sess.user_id) return forbidden("no access");

        return json({
          ok: true,
          order: {
            id: order.id,
            status: order.status,
            created_at: order.created_at,
            paid_at: order.paid_at,
            tx_hash: order.tx_hash,
            plan_name: order.plan_name,
            data_gb: order.data_gb,
            days: order.days,
            amount_usd: order.amount_usd,
            amount_usdt: order.amount_usdt,
            usdt_address: USDT_ADDRESS,
            usdt_network: USDT_NETWORK,
          },
        });
      }
    }

    // 管理员标记支付成功：POST /api/admin/order/paid {order_id, tx_hash?}
    if (method === "POST" && path === "/api/admin/order/paid") {
      if (!requireAdmin(request)) return forbidden("admin token required");
      const body = await parseJSON(request);
      if (!body) return badRequest("bad json");
      const order_id = String(body.order_id || "");
      const tx_hash = body.tx_hash ? String(body.tx_hash) : null;
      if (!order_id) return badRequest("order_id required");

      const order = await getOrderById(order_id);
      if (!order) return badRequest("order not found");

      await markOrderPaid({ orderId: order_id, txHash: tx_hash });
      return json({ ok: true });
    }

    // ========= 页面路由 =========
    const sess = await getSession();
    const userEmail = sess?.email || "";

    // 首页
    if (method === "GET" && path === "/") {
      const plans = await listPlans();
      const planRows = plans
        .map(
          (p) => `<tr>
<td>${escapeHtml(p.name)}</td>
<td>${p.data_gb}GB / ${p.days}天</td>
<td>$${Number(p.price_usd).toFixed(2)}</td>
<td><button class="btn" onclick="buy(${p.id})">购买</button></td>
</tr>`
        )
        .join("");

      const body = `
        <div class="h1">ESIM 套餐中心</div>
        <div class="muted">注册/登录后可创建订单并使用 USDT（${escapeHtml(USDT_NETWORK)}）付款。</div>
        <div class="line"></div>

        <div class="row">
          <div class="col">
            <div class="card" style="margin:0">
              <div style="font-weight:700;margin-bottom:8px">可用套餐</div>
              <table>
                <thead><tr><th>套餐</th><th>规格</th><th>价格</th><th></th></tr></thead>
                <tbody>${
                  planRows ||
                  `<tr><td colspan="4" class="muted">暂无套餐（请在 D1 的 plans 表插入数据）</td></tr>`
                }</tbody>
              </table>
            </div>
          </div>

          <div class="col">
            <div class="card" style="margin:0">
              <div style="font-weight:700;margin-bottom:8px">快速入口</div>
              <div class="muted">账户：${
                userEmail ? `<span class="ok">${escapeHtml(userEmail)}</span>` : `<span class="bad">未登录</span>`
              }</div>
              <div class="line"></div>
              <div class="row" style="gap:10px">
                <a class="btn gray" href="/register">注册</a>
                <a class="btn gray" href="/login">登录</a>
                <a class="btn" href="/order">我的订单</a>
                <a class="btn" href="/pay">支付页面</a>
              </div>
              <div class="line"></div>
              <div class="muted" style="font-size:12px">
                收款地址：<code id="addr">${escapeHtml(USDT_ADDRESS || "(未配置 USDT_ADDRESS)")}</code>
              </div>
            </div>
          </div>
        </div>

        <script>
          async function buy(planId){
            const me = await fetch('/api/me').then(r=>r.json());
            if(!me.user){ location.href='/login?next=/'; return; }
            const res = await fetch('/api/order/create',{
              method:'POST',
              headers:{'Content-Type':'application/json'},
              body:JSON.stringify({plan_id:planId})
            }).then(r=>r.json());
            if(!res.ok){ alert(res.error||'创建订单失败'); return; }
            location.href='/pay?order=' + encodeURIComponent(res.order.id);
          }
        </script>
      `;
      return html(pageShell({ title: "ESIM 套餐中心", body, userEmail }));
    }

    // 注册页
    if (method === "GET" && path === "/register") {
      const body = `
        <div class="h1">注册</div>
        <div class="muted">仅邮箱注册（密码至少 6 位）。</div>
        <div class="line"></div>
        <div class="row">
          <div class="col">
            <label>邮箱</label>
            <input id="email" placeholder="name@example.com" />
          </div>
          <div class="col">
            <label>密码</label>
            <input id="password" type="password" placeholder="******" />
          </div>
        </div>
        <div style="margin-top:14px">
          <button class="btn" onclick="go()">注册</button>
          <span id="msg" class="muted" style="margin-left:10px"></span>
        </div>
        <div class="line"></div>
        <div class="muted">已有账号？ <a href="/login">去登录</a></div>

        <script>
          async function go(){
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const msg = document.getElementById('msg');
            msg.textContent='';
            const res = await fetch('/api/register',{
              method:'POST',
              headers:{'Content-Type':'application/json'},
              body:JSON.stringify({email,password})
            }).then(r=>r.json());
            if(!res.ok){ msg.textContent = res.error || '注册失败'; return; }
            location.href='/';
          }
        </script>
      `;
      return html(pageShell({ title: "注册", body, userEmail }));
    }

    // 登录页
    if (method === "GET" && path === "/login") {
      const next = url.searchParams.get("next") || "/";
      const body = `
        <div class="h1">登录</div>
        <div class="muted">使用邮箱 + 密码登录。</div>
        <div class="line"></div>
        <div class="row">
          <div class="col">
            <label>邮箱</label>
            <input id="email" placeholder="name@example.com" />
          </div>
          <div class="col">
            <label>密码</label>
            <input id="password" type="password" placeholder="******" />
          </div>
        </div>
        <div style="margin-top:14px">
          <button class="btn" onclick="go()">登录</button>
          <span id="msg" class="muted" style="margin-left:10px"></span>
        </div>
        <div class="line"></div>
        <div class="muted">没有账号？ <a href="/register">去注册</a></div>

        <script>
          async function go(){
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const msg = document.getElementById('msg');
            msg.textContent='';
            const res = await fetch('/api/login',{
              method:'POST',
              headers:{'Content-Type':'application/json'},
              body:JSON.stringify({email,password})
            }).then(r=>r.json());
            if(!res.ok){ msg.textContent = res.error || '登录失败'; return; }
            location.href=${JSON.stringify(next)};
          }
        </script>
      `;
      return html(pageShell({ title: "登录", body, userEmail }));
    }

    // 退出
    if (method === "GET" && path === "/logout") {
      await destroySession(request);
      return redirect("/", 302, { "Set-Cookie": setCookie("sid", "", { maxAge: 0 }) });
    }

    // 我的订单页
    if (method === "GET" && path === "/order") {
      if (!sess) return redirect("/login?next=/order");

      const orders = await listOrdersByUser(sess.user_id);
      const rows =
        orders
          .map((o) => {
            const st =
              o.status === "paid"
                ? `<span class="chip ok">已支付</span>`
                : `<span class="chip bad">未支付</span>`;
            return `<tr>
<td><a href="/pay?order=${escapeHtml(o.id)}"><code>${escapeHtml(o.id)}</code></a></td>
<td>${escapeHtml(o.plan_name)} (${o.data_gb}GB/${o.days}天)</td>
<td>$${Number(o.amount_usd).toFixed(2)} / ${Number(o.amount_usdt).toFixed(2)} USDT</td>
<td>${st}</td>
<td>${escapeHtml(o.created_at)}</td>
</tr>`;
          })
          .join("") || `<tr><td colspan="5" class="muted">暂无订单</td></tr>`;

      const body = `
        <div class="h1">我的订单</div>
        <div class="muted">点击订单号进入支付/详情页面。</div>
        <div class="line"></div>
        <table>
          <thead><tr><th>订单号</th><th>套餐</th><th>金额</th><th>状态</th><th>创建时间</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;
      return html(pageShell({ title: "我的订单", body, userEmail }));
    }

    // 支付页
    if (method === "GET" && path === "/pay") {
      if (!sess) return redirect("/login?next=/pay");

      if (!USDT_ADDRESS) {
        const body = `<div class="h1">支付配置缺失</div><div class="muted">请设置环境变量 <code>USDT_ADDRESS</code>（你的收款地址）</div>`;
        return html(pageShell({ title: "支付", body, userEmail }), 500);
      }

      const orderId = url.searchParams.get("order") || "";
      let order = null;
      if (orderId) {
        order = await getOrderById(orderId);
        if (!order || order.user_id !== sess.user_id) order = null;
      }

      const address = USDT_ADDRESS;
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(
        address
      )}`;

      const orderBox = order
        ? `
          <div class="card" style="margin:0">
            <div style="font-weight:700">订单信息</div>
            <div class="line"></div>
            <div class="muted">订单号：<code>${escapeHtml(order.id)}</code></div>
            <div class="muted">套餐：${escapeHtml(order.plan_name)} (${order.data_gb}GB / ${order.days}天)</div>
            <div class="muted">金额：<b>$${Number(order.amount_usd).toFixed(2)}</b> ≈ <b>${Number(
              order.amount_usdt
            ).toFixed(2)} USDT</b></div>
            <div class="muted">状态：${
              order.status === "paid"
                ? `<span class="chip ok">已支付</span>`
                : `<span class="chip bad">未支付</span>`
            }</div>
            ${order.paid_at ? `<div class="muted">支付时间：${escapeHtml(order.paid_at)}</div>` : ""}
          </div>
        `
        : `
          <div class="card" style="margin:0">
            <div style="font-weight:700">创建订单</div>
            <div class="muted">请选择一个套餐创建订单后付款。</div>
            <div class="line"></div>
            <div id="plans" class="muted">加载中...</div>
          </div>
        `;

      const body = `
        <div class="h1">USDT 支付</div>
        <div class="muted">网络：<b>${escapeHtml(USDT_NETWORK)}</b>（请确保转账网络与收款地址一致）</div>
        <div class="line"></div>

        <div class="row">
          <div class="col">${orderBox}</div>

          <div class="col">
            <div class="card" style="margin:0">
              <div style="font-weight:700">收款信息</div>
              <div class="line"></div>

              <div class="muted">收款地址</div>
              <div style="display:flex;gap:10px;align-items:center;margin-top:8px;flex-wrap:wrap">
                <code id="addr" style="word-break:break-all">${escapeHtml(address)}</code>
                <button class="btn gray" onclick="copyAddr()">复制</button>
              </div>

              <div class="line"></div>

              <div class="muted">二维码</div>
              <div style="margin-top:10px">
                <img src="${escapeHtml(qrUrl)}" width="220" height="220" style="border-radius:14px;border:1px solid rgba(255,255,255,.12)" />
              </div>

              <div class="line"></div>

              <div class="muted" style="font-size:12px">
                说明：若要“自动确认到账”，必须接入链上查询/回调（第三方 API/节点）。当前版本支持：创建订单 → 转账 → 管理员确认。
              </div>
            </div>
          </div>
        </div>

        <script>
          async function copyAddr(){
            const t = document.getElementById('addr').textContent;
            await navigator.clipboard.writeText(t);
            alert('已复制');
          }

          async function loadPlans(){
            const res = await fetch('/api/plans').then(r=>r.json());
            if(!res.ok){ document.getElementById('plans').textContent = res.error || '加载失败'; return; }
            const plans = res.plans || [];
            if(!plans.length){ document.getElementById('plans').textContent='暂无套餐'; return; }

            document.getElementById('plans').innerHTML = \`
              <div class="row" style="gap:10px">\${plans.map(p=>\`
                <div class="card" style="margin:0;flex:1;min-width:220px">
                  <div style="font-weight:700">\${p.name}</div>
                  <div class="muted">\${p.data_gb}GB / \${p.days}天</div>
                  <div style="margin-top:8px"><b>$\${Number(p.price_usd).toFixed(2)}</b></div>
                  <div style="margin-top:10px">
                    <button class="btn" onclick="createOrder(\${p.id})">创建订单</button>
                  </div>
                </div>\`).join('')}
              </div>
            \`;
          }

          async function createOrder(planId){
            const res = await fetch('/api/order/create',{
              method:'POST',
              headers:{'Content-Type':'application/json'},
              body:JSON.stringify({plan_id:planId})
            }).then(r=>r.json());
            if(!res.ok){ alert(res.error||'创建订单失败'); return; }
            location.href='/pay?order=' + encodeURIComponent(res.order.id);
          }

          ${order ? "" : "loadPlans();"}
        </script>
      `;
      return html(pageShell({ title: "支付", body, userEmail }));
    }

    // 后台页：/admin?token=ADMIN_TOKEN（展示建表 SQL）
    if (method === "GET" && path === "/admin") {
      if (!requireAdmin(request)) {
        const body = `
          <div class="h1">后台</div>
          <div class="muted">需要管理员令牌。请在 URL 加 <code>?token=...</code> 或 Header 里传 <code>X-Admin-Token</code>。</div>
        `;
        return html(pageShell({ title: "后台", body, userEmail }), 403);
      }

      const body = `
        <div class="h1">后台工具</div>
        <div class="muted">在 D1 Studio 执行建表 SQL；插入 plans；用接口标记订单 paid。</div>
        <div class="line"></div>

        <div style="font-weight:700;margin-bottom:8px">建表 SQL</div>
        <pre style="white-space:pre-wrap;background:rgba(0,0,0,.35);padding:14px;border-radius:14px;border:1px solid rgba(255,255,255,.08)">${escapeHtml(
          schemaSql
        )}</pre>

        <div class="line"></div>

        <div style="font-weight:700;margin-bottom:8px">示例：插入套餐（在 D1 执行）</div>
        <pre style="white-space:pre-wrap;background:rgba(0,0,0,.35);padding:14px;border-radius:14px;border:1px solid rgba(255,255,255,.08)">${escapeHtml(`INSERT INTO plans (name,data_gb,days,price_usd,is_active) VALUES
('套餐 01 / Plan 01',10,30,19,1),
('套餐 02 / Plan 02',5,15,12,1),
('套餐 03 / Plan 03',3,7,7,1);`)}</pre>

        <div class="line"></div>

        <div style="font-weight:700;margin-bottom:8px">示例：标记订单已支付</div>
        <div class="muted">POST <code>/api/admin/order/paid</code>，Header <code>X-Admin-Token</code>，Body：</div>
        <pre style="white-space:pre-wrap;background:rgba(0,0,0,.35);padding:14px;border-radius:14px;border:1px solid rgba(255,255,255,.08)">${escapeHtml(`{
  "order_id": "订单ID",
  "tx_hash": "可选"
}`)}</pre>
      `;
      return html(pageShell({ title: "后台", body, userEmail }));
    }

    // 其他路径 404
    return notFound();
  },
};
