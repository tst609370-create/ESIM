export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // ----------------- 基础配置（用环境变量覆盖） -----------------
    const ALLOW_REGISTER = (env.ALLOW_REGISTER ?? "true") === "true";
    const SESSION_SECRET = env.SESSION_SECRET || "CHANGE_ME_SESSION_SECRET";
    const USDT_ADDRESS = env.USDT_ADDRESS || "(未配置USDT_ADDRESS)";
    const ADMIN_TOKEN = env.ADMIN_TOKEN || "";
    const TRONGRID_API_KEY = env.TRONGRID_API_KEY || ""; // 可选，不填则不自动查链

    // TRC20 USDT 合约地址（TRON）
    const TRC20_USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
    const USDT_DECIMALS = 6;

    // ----------------- 工具函数 -----------------
    const now = () => Math.floor(Date.now() / 1000);

    const json = (data, status = 200, headers = {}) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          ...headers,
        },
      });

    const html = (body, status = 200, headers = {}) =>
      new Response(body, {
        status,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          ...headers,
        },
      });

    const redirect = (to) =>
      new Response("", { status: 302, headers: { Location: to } });

    const bad = (msg, status = 400) => json({ ok: false, error: msg }, status);

    const requireDB = () => {
      if (!env.DB) throw new Error("Missing D1 binding: env.DB");
      return env.DB;
    };

    const hash = async (str) => {
      const buf = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(str)
      );
      return [...new Uint8Array(buf)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    };

    const hmac = async (data) => {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(SESSION_SECRET),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(data)
      );
      return [...new Uint8Array(sig)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    };

    const b64url = (bytes) =>
      btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    const randomId = (len = 24) => {
      const bytes = new Uint8Array(len);
      crypto.getRandomValues(bytes);
      return b64url(bytes);
    };

    const parseBody = async (req) => {
      const ct = (req.headers.get("Content-Type") || "").toLowerCase();
      if (ct.includes("application/json")) {
        try {
          return await req.json();
        } catch {
          return null;
        }
      }
      if (
        ct.includes("application/x-www-form-urlencoded") ||
        ct.includes("multipart/form-data")
      ) {
        try {
          const form = await req.formData();
          const obj = {};
          for (const [k, v] of form.entries()) obj[k] = String(v);
          return obj;
        } catch {
          return null;
        }
      }
      try {
        const t = await req.text();
        if (!t) return {};
        try {
          return JSON.parse(t);
        } catch {
          return { raw: t };
        }
      } catch {
        return null;
      }
    };

    const getCookie = (req, name) => {
      const c = req.headers.get("Cookie") || "";
      const m = c.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
      return m ? decodeURIComponent(m[1]) : null;
    };

    const setCookie = (name, value, maxAgeSec) =>
      `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}`;

    const clearCookie = (name) =>
      `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;

    const getUserBySession = async (req) => {
      const sid = getCookie(req, "sid");
      if (!sid) return null;
      const DB = requireDB();
      const row = await DB.prepare(
        `SELECT s.id AS sid, s.user_id AS user_id, s.expires_at AS expires_at, u.email AS email
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.id = ? LIMIT 1`
      )
        .bind(sid)
        .first();
      if (!row) return null;
      if (row.expires_at <= now()) return null;
      return { id: row.user_id, email: row.email, sid: row.sid };
    };

    const requireLogin = async (req) => {
      const u = await getUserBySession(req);
      if (!u) return null;
      return u;
    };

    const fmtUsd = (n) => Number(n).toFixed(2);

    // ----------------- 页面模板 -----------------
    const layout = (title, content, user) => `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root{color-scheme:dark}
    body{margin:0;background:#0b1220;color:#e8eefc;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial}
    a{color:#8ab4ff;text-decoration:none}
    .wrap{max-width:1000px;margin:40px auto;padding:0 16px}
    .nav{display:flex;gap:16px;align-items:center;justify-content:space-between;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:12px 14px}
    .nav .left{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
    .nav .right{display:flex;gap:10px;align-items:center}
    .card{margin-top:16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:18px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    @media (max-width:900px){.grid{grid-template-columns:1fr}}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
    .btn{display:inline-block;background:#2b6cff;border:none;color:#fff;padding:10px 14px;border-radius:12px;cursor:pointer}
    .btn.gray{background:rgba(255,255,255,.14)}
    .muted{opacity:.75}
    .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    input{width:100%;padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(0,0,0,.25);color:#fff}
    .msg{margin-top:10px;color:#ffb4b4}
    code{background:rgba(0,0,0,.25);padding:2px 6px;border-radius:8px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <div class="left">
        <strong>ESIM 套餐中心</strong>
        <a href="/">首页</a>
        <a href="/order">我的订单</a>
        <a href="/pay">支付页面</a>
        ${ADMIN_TOKEN ? `<a href="/admin">后台</a>` : ``}
      </div>
      <div class="right">
        <span class="muted">账户：${user ? escapeHtml(user.email) : "未登录"}</span>
        ${
          user
            ? `<form method="post" action="/api/logout"><button class="btn gray" type="submit">退出</button></form>`
            : `<a class="btn gray" href="/login">登录</a><a class="btn" href="/register">注册</a>`
        }
      </div>
    </div>

    <div class="card">
      ${content}
    </div>

    <div class="muted" style="margin-top:14px;font-size:12px">
      Powered by Cloudflare Workers + D1
    </div>
  </div>
</body>
</html>`;

    const escapeHtml = (s) =>
      String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");

    // ----------------- 首页 -----------------
    if (method === "GET" && path === "/") {
      const user = await getUserBySession(request);
      const DB = requireDB();
      const plans = await DB.prepare(
        `SELECT id,name,data_gb,days,price_usd FROM plans WHERE is_active=1 ORDER BY id ASC`
      ).all();

      const rows = (plans.results || [])
        .map(
          (p) => `<tr>
<td>${escapeHtml(p.name)}</td>
<td>${p.data_gb}GB / ${p.days}天</td>
<td>$${fmtUsd(p.price_usd)}</td>
<td>
  <form method="post" action="/api/order/create">
    <input type="hidden" name="plan_id" value="${p.id}" />
    <button class="btn" type="submit">购买</button>
  </form>
</td>
</tr>`
        )
        .join("");

      const content = `
      <h2 style="margin:0 0 8px">ESIM 套餐中心</h2>
      <div class="muted">注册/登录后下单，使用 USDT (TRC20) 付款。</div>
      <div class="grid" style="margin-top:14px">
        <div class="card" style="margin:0">
          <h3 style="margin:0 0 10px">可用套餐</h3>
          <table>
            <thead><tr><th>套餐</th><th>规格</th><th>价格</th><th></th></tr></thead>
            <tbody>
              ${rows || `<tr><td colspan="4" class="muted">暂无套餐</td></tr>`}
            </tbody>
          </table>
        </div>
        <div class="card" style="margin:0">
          <h3 style="margin:0 0 10px">快速入口</h3>
          <div class="muted">收款地址：<code>${escapeHtml(USDT_ADDRESS)}</code></div>
          <div style="margin-top:12px" class="row">
            <a class="btn gray" href="/register">注册</a>
            <a class="btn gray" href="/login">登录</a>
            <a class="btn" href="/order">我的订单</a>
            <a class="btn" href="/pay">支付页面</a>
          </div>
          <div class="muted" style="margin-top:10px;font-size:12px">
            自动查链：${TRONGRID_API_KEY ? "已开启" : "未开启（可选）"}
          </div>
        </div>
      </div>
      `;
      return html(layout("首页", content, user));
    }

    // ----------------- 注册页 -----------------
    if (method === "GET" && path === "/register") {
      const user = await getUserBySession(request);
      const content = `
        <h2 style="margin:0 0 10px">注册</h2>
        <div class="muted">仅邮箱注册（密码至少 6 位）</div>
        <form id="f" method="post" action="/api/register" style="margin-top:14px;max-width:520px">
          <div class="row" style="gap:12px">
            <div style="flex:1">
              <div class="muted" style="margin-bottom:6px">邮箱</div>
              <input name="email" placeholder="name@example.com" />
            </div>
            <div style="flex:1">
              <div class="muted" style="margin-bottom:6px">密码</div>
              <input name="password" type="password" placeholder="******" />
            </div>
          </div>
          <div style="margin-top:12px" class="row">
            <button class="btn" type="submit">注册</button>
            <a class="btn gray" href="/login">去登录</a>
          </div>
          <div id="msg" class="msg"></div>
        </form>
        <script>
          const f=document.getElementById('f');
          f.addEventListener('submit', async (e)=>{
            e.preventDefault();
            const fd=new FormData(f);
            const r=await fetch('/api/register',{method:'POST',body:fd});
            const j=await r.json().catch(()=>null);
            if(!j||!j.ok){document.getElementById('msg').textContent=(j&&j.error)||'注册失败';return;}
            location.href='/login';
          });
        </script>
      `;
      return html(layout("注册", content, user));
    }

    // ----------------- 登录页 -----------------
    if (method === "GET" && path === "/login") {
      const user = await getUserBySession(request);
      const content = `
        <h2 style="margin:0 0 10px">登录</h2>
        <form id="f" method="post" action="/api/login" style="margin-top:14px;max-width:520px">
          <div class="row" style="gap:12px">
            <div style="flex:1">
              <div class="muted" style="margin-bottom:6px">邮箱</div>
              <input name="email" placeholder="name@example.com" />
            </div>
            <div style="flex:1">
              <div class="muted" style="margin-bottom:6px">密码</div>
              <input name="password" type="password" placeholder="******" />
            </div>
          </div>
          <div style="margin-top:12px" class="row">
            <button class="btn" type="submit">登录</button>
            <a class="btn gray" href="/register">去注册</a>
          </div>
          <div id="msg" class="msg"></div>
        </form>
        <script>
          const f=document.getElementById('f');
          f.addEventListener('submit', async (e)=>{
            e.preventDefault();
            const fd=new FormData(f);
            const r=await fetch('/api/login',{method:'POST',body:fd});
            const j=await r.json().catch(()=>null);
            if(!j||!j.ok){document.getElementById('msg').textContent=(j&&j.error)||'登录失败';return;}
            location.href='/';
          });
        </script>
      `;
      return html(layout("登录", content, user));
    }

    // ----------------- 我的订单 -----------------
    if (method === "GET" && path === "/order") {
      const user = await requireLogin(request);
      if (!user) return redirect("/login");

      const DB = requireDB();
      const rows = await DB.prepare(
        `SELECT o.id,o.plan_id,o.amount_usd,o.status,o.created_at,o.expires_at,o.txid,
                p.name as plan_name,p.data_gb,p.days
         FROM orders o
         JOIN plans p ON p.id=o.plan_id
         WHERE o.user_id=?
         ORDER BY o.created_at DESC
         LIMIT 50`
      )
        .bind(user.id)
        .all();

      const trs = (rows.results || [])
        .map((o) => {
          const expLeft = o.expires_at - now();
          const expTxt =
            expLeft <= 0 ? "已过期" : `${Math.floor(expLeft / 60)} 分钟`;
          return `<tr>
<td><a href="/pay?order=${encodeURIComponent(o.id)}">${escapeHtml(o.id)}</a></td>
<td>${escapeHtml(o.plan_name)} (${o.data_gb}GB/${o.days}天)</td>
<td>$${fmtUsd(o.amount_usd)}</td>
<td>${escapeHtml(o.status)}</td>
<td>${expTxt}</td>
<td>${o.txid ? `<code>${escapeHtml(o.txid)}</code>` : ""}</td>
</tr>`;
        })
        .join("");

      const content = `
        <h2 style="margin:0 0 10px">我的订单</h2>
        <div class="muted">点击订单号进入支付页面。</div>
        <table style="margin-top:10px">
          <thead><tr><th>订单</th><th>套餐</th><th>金额</th><th>状态</th><th>剩余</th><th>Tx</th></tr></thead>
          <tbody>${trs || `<tr><td colspan="6" class="muted">暂无订单</td></tr>`}</tbody>
        </table>
      `;
      return html(layout("我的订单", content, user));
    }

    // ----------------- 支付页 -----------------
    if (method === "GET" && path === "/pay") {
      const user = await getUserBySession(request);
      const orderId = url.searchParams.get("order") || "";

      let order = null;
      if (orderId) {
        const DB = requireDB();
        order = await DB.prepare(
          `SELECT id,user_id,plan_id,amount_usd,status,pay_address,pay_network,created_at,expires_at,txid
           FROM orders WHERE id=? LIMIT 1`
        )
          .bind(orderId)
          .first();
      }

      const content = `
        <h2 style="margin:0 0 10px">支付页面</h2>
        <div class="muted">USDT (TRC20) 付款。系统会轮询订单状态。</div>

        ${
          order
            ? `
          <div style="margin-top:12px">
            <div class="row"><div class="muted">订单号：</div><code>${escapeHtml(order.id)}</code></div>
            <div class="row"><div class="muted">金额：</div><code>${fmtUsd(order.amount_usd)} USDT</code></div>
            <div class="row"><div class="muted">网络：</div><code>${escapeHtml(order.pay_network)}</code></div>
            <div class="row"><div class="muted">收款地址：</div><code id="addr">${escapeHtml(order.pay_address)}</code></div>
            <div class="row" style="margin-top:10px">
              <button class="btn gray" id="copy">复制地址</button>
              <button class="btn" id="refresh">刷新状态</button>
            </div>
            <div class="muted" style="margin-top:10px">状态：<span id="st">${escapeHtml(
              order.status
            )}</span></div>
            <div id="msg" class="msg"></div>
          </div>

          <script>
            const orderId=${JSON.stringify(order.id)};
            document.getElementById('copy').onclick=async ()=>{
              const t=document.getElementById('addr').textContent;
              try{await navigator.clipboard.writeText(t);}catch(e){}
            };
            async function poll(){
              const r=await fetch('/api/order/status?id='+encodeURIComponent(orderId),{method:'GET'});
              const j=await r.json().catch(()=>null);
              if(!j||!j.ok){document.getElementById('msg').textContent=(j&&j.error)||'查询失败';return;}
              document.getElementById('st').textContent=j.order.status;
              if(j.order.status==='paid'){
                document.getElementById('msg').textContent='已确认到账';
                return;
              }
              if(j.order.status==='expired'){
                document.getElementById('msg').textContent='订单已过期，请重新下单';
                return;
              }
            }
            document.getElementById('refresh').onclick=poll;
            setInterval(poll, 6000);
            poll();
          </script>
        `
            : `
          <div class="muted" style="margin-top:12px">
            你可以从 <a href="/order">我的订单</a> 进入某个订单的支付页面。
          </div>
        `
        }
      `;
      return html(layout("支付页面", content, user));
    }

    // ----------------- API: 注册 -----------------
    if (method === "POST" && path === "/api/register") {
      if (!ALLOW_REGISTER) return bad("register disabled", 403);

      const body = await parseBody(request);
      if (!body) return bad("bad json");

      const email = (body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (!email || !email.includes("@")) return bad("email invalid");
      if (password.length < 6) return bad("password too short (>=6)");

      const DB = requireDB();
      const pass_hash = await hash(password);
      const created_at = now();

      try {
        const r = await DB.prepare(
          `INSERT INTO users (email, pass_hash, created_at) VALUES (?,?,?)`
        )
          .bind(email, pass_hash, created_at)
          .run();

        return json({ ok: true, id: r.meta?.last_row_id ?? null });
      } catch (e) {
        const msg = String(e?.message || e);
        if (msg.toLowerCase().includes("unique"))
          return bad("email already exists", 409);
        return bad("db error: " + msg, 500);
      }
    }

    // ----------------- API: 登录 -----------------
    if (method === "POST" && path === "/api/login") {
      const body = await parseBody(request);
      if (!body) return bad("bad json");

      const email = (body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const DB = requireDB();
      const u = await DB.prepare(
        `SELECT id,email,pass_hash FROM users WHERE email=? LIMIT 1`
      )
        .bind(email)
        .first();

      if (!u) return bad("invalid email or password", 401);

      const ph = await hash(password);
      if (ph !== u.pass_hash) return bad("invalid email or password", 401);

      const sid = "s_" + randomId(24) + "_" + (await hmac(email + ":" + now()));
      const created_at = now();
      const expires_at = created_at + 30 * 24 * 3600;

      await DB.prepare(
        `INSERT INTO sessions (id,user_id,created_at,expires_at) VALUES (?,?,?,?)`
      )
        .bind(sid, u.id, created_at, expires_at)
        .run();

      return json(
        { ok: true, email: u.email },
        200,
        { "Set-Cookie": setCookie("sid", sid, 30 * 24 * 3600) }
      );
    }

    // ----------------- API: 退出 -----------------
    if (method === "POST" && path === "/api/logout") {
      const sid = getCookie(request, "sid");
      if (sid) {
        try {
          const DB = requireDB();
          await DB.prepare(`DELETE FROM sessions WHERE id=?`).bind(sid).run();
        } catch {}
      }
      return json({ ok: true }, 200, { "Set-Cookie": clearCookie("sid") });
    }

    // ----------------- API: 下单 -----------------
    if (method === "POST" && path === "/api/order/create") {
      const user = await requireLogin(request);
      if (!user) return bad("not logged in", 401);

      const body = await parseBody(request);
      if (!body) return bad("bad body");

      const plan_id = Number(body.plan_id || 0);
      if (!plan_id) return bad("plan_id required");

      const DB = requireDB();
      const plan = await DB.prepare(
        `SELECT id,name,price_usd,is_active FROM plans WHERE id=? LIMIT 1`
      )
        .bind(plan_id)
        .first();

      if (!plan || plan.is_active !== 1) return bad("plan not available", 404);

      const created_at = now();
      const expires_at = created_at + 30 * 60; // 30 分钟有效
      const orderId = "o_" + randomId(20);

      await DB.prepare(
        `INSERT INTO orders (id,user_id,plan_id,amount_usd,status,pay_address,pay_network,created_at,expires_at)
         VALUES (?,?,?,?,?,?,?,?,?)`
      )
        .bind(
          orderId,
          user.id,
          plan.id,
          Number(plan.price_usd),
          "pending",
          USDT_ADDRESS,
          "TRC20",
          created_at,
          expires_at
        )
        .run();

      // 直接跳转到支付页
      return redirect(`/pay?order=${encodeURIComponent(orderId)}`);
    }

    // ----------------- API: 订单状态（含可选自动查链） -----------------
    if (method === "GET" && path === "/api/order/status") {
      const id = url.searchParams.get("id") || "";
      if (!id) return bad("id required");

      const DB = requireDB();
      const o = await DB.prepare(
        `SELECT id,user_id,amount_usd,status,pay_address,pay_network,created_at,expires_at,paid_at,txid
         FROM orders WHERE id=? LIMIT 1`
      )
        .bind(id)
        .first();

      if (!o) return bad("order not found", 404);

      // 过期处理
      if (o.status === "pending" && o.expires_at <= now()) {
        await DB.prepare(`UPDATE orders SET status='expired' WHERE id=?`)
          .bind(o.id)
          .run();
        o.status = "expired";
      }

      // 自动查链（可选）
      if (o.status === "pending" && TRONGRID_API_KEY && USDT_ADDRESS !== "(未配置USDT_ADDRESS)") {
        const found = await tryAutoConfirmTrc20Usdt(env, {
          apiKey: TRONGRID_API_KEY,
          contract: TRC20_USDT_CONTRACT,
          address: o.pay_address,
          amountUsd: Number(o.amount_usd),
          since: o.created_at - 60,   // 容错
          until: o.expires_at + 60
        });

        if (found) {
          await DB.prepare(
            `UPDATE orders SET status='paid', paid_at=?, txid=? WHERE id=?`
          )
            .bind(now(), found.txid, o.id)
            .run();
          o.status = "paid";
          o.txid = found.txid;
        }
      }

      return json({ ok: true, order: o });
    }

    // ----------------- 后台（手动确认） -----------------
    if (method === "GET" && path === "/admin") {
      const user = await getUserBySession(request);

      const token = url.searchParams.get("token") || "";
      if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
        const content = `
          <h2 style="margin:0 0 10px">后台</h2>
          <div class="muted">需要 token 参数：<code>/admin?token=ADMIN_TOKEN</code></div>
        `;
        return html(layout("后台", content, user), 403);
      }

      const DB = requireDB();
      const rows = await DB.prepare(
        `SELECT o.id,o.user_id,o.amount_usd,o.status,o.created_at,o.expires_at,o.txid,u.email
         FROM orders o
         LEFT JOIN users u ON u.id=o.user_id
         ORDER BY o.created_at DESC
         LIMIT 80`
      ).all();

      const trs = (rows.results || [])
        .map((o) => {
          return `<tr>
<td><code>${escapeHtml(o.id)}</code></td>
<td>${escapeHtml(o.email || "-")}</td>
<td>$${fmtUsd(o.amount_usd)}</td>
<td>${escapeHtml(o.status)}</td>
<td>${o.txid ? `<code>${escapeHtml(o.txid)}</code>` : ""}</td>
<td>
  <form method="post" action="/api/admin/mark-paid?token=${encodeURIComponent(
    ADMIN_TOKEN
  )}">
    <input name="order_id" value="${escapeHtml(o.id)}" />
    <input name="txid" placeholder="txid(可空)" />
    <button class="btn" type="submit">标记已支付</button>
  </form>
</td>
</tr>`;
        })
        .join("");

      const content = `
        <h2 style="margin:0 0 10px">后台订单</h2>
        <div class="muted">用于手动确认（没有 TronGrid Key 时也能用）</div>
        <table style="margin-top:10px">
          <thead><tr><th>订单</th><th>用户</th><th>金额</th><th>状态</th><th>Tx</th><th>操作</th></tr></thead>
          <tbody>${trs || `<tr><td colspan="6" class="muted">暂无</td></tr>`}</tbody>
        </table>
      `;
      return html(layout("后台", content, user));
    }

    if (method === "POST" && path === "/api/admin/mark-paid") {
      const token = url.searchParams.get("token") || "";
      if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return bad("forbidden", 403);

      const body = await parseBody(request);
      if (!body) return bad("bad body");
      const order_id = String(body.order_id || "");
      const txid = String(body.txid || "");

      const DB = requireDB();
      await DB.prepare(
        `UPDATE orders SET status='paid', paid_at=?, txid=? WHERE id=?`
      )
        .bind(now(), txid || null, order_id)
        .run();

      return redirect(`/admin?token=${encodeURIComponent(ADMIN_TOKEN)}`);
    }

    // ----------------- Not Found -----------------
    return new Response("Not Found", { status: 404 });

    // ----------------- 自动查链：TronGrid TRC20 USDT -----------------
    async function tryAutoConfirmTrc20Usdt(env, cfg) {
      // TronGrid: GET /v1/accounts/{address}/transactions/trc20?only_confirmed=true&limit=20&contract_address=...
      // 返回的 amount 是字符串（按最小单位），需要除以 10^decimals
      const { apiKey, contract, address, amountUsd, since, until } = cfg;

      // 金额匹配策略（简单稳健版）：
      // - 在有效时间窗内找到转入 address 的 USDT TRC20
      // - 金额等于订单金额（允许极小误差）
      const target = Number(amountUsd);
      const eps = 0.000001;

      const qs = new URLSearchParams({
        only_confirmed: "true",
        limit: "50",
        contract_address: contract,
      });

      const endpoint = `https://api.trongrid.io/v1/accounts/${encodeURIComponent(
        address
      )}/transactions/trc20?${qs.toString()}`;

      const resp = await fetch(endpoint, {
        headers: {
          "TRON-PRO-API-KEY": apiKey,
        },
      });

      if (!resp.ok) return null;
      const data = await resp.json().catch(() => null);
      if (!data || !Array.isArray(data.data)) return null;

      for (const tx of data.data) {
        // tx.block_timestamp 毫秒
        const ts = Math.floor((tx.block_timestamp || 0) / 1000);
        if (ts < since || ts > until) continue;

        // tx.to / tx.from / tx.value / tx.transaction_id
        const to = (tx.to || "").trim();
        if (to !== address) continue;

        const raw = tx.value; // string
        if (!raw) continue;

        const amt = Number(raw) / Math.pow(10, USDT_DECIMALS);
        if (Math.abs(amt - target) <= eps) {
          return { txid: tx.transaction_id || "" };
        }
      }
      return null;
    }
  },
};
