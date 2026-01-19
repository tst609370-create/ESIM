export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // ========== 工具函数 ==========
    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      });

    const html = (body) =>
      new Response(body, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });

    const hash = async (str) => {
      const buf = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(str)
      );
      return [...new Uint8Array(buf)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    };

    const parseJSON = async (req) => {
      try {
        return await req.json();
      } catch {
        return null;
      }
    };

    const getCookie = (req, name) => {
      const c = req.headers.get("Cookie") || "";
      const m = c.match(new RegExp(`${name}=([^;]+)`));
      return m ? m[1] : null;
    };

    const now = () => new Date().toISOString();

    // ========== 页面 ==========
    if (method === "GET" && path === "/register") {
      return html(`
<!doctype html>
<html>
<head><meta charset="utf-8"><title>注册</title></head>
<body>
<h2>邮箱注册</h2>
<input id="email" placeholder="邮箱"><br><br>
<input id="password" type="password" placeholder="密码"><br><br>
<button onclick="reg()">注册</button>
<p id="msg"></p>
<script>
async function reg(){
  const r = await fetch('/api/register',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({
      email:email.value,
      password:password.value
    })
  });
  const j = await r.json();
  msg.innerText = j.error || '注册成功';
}
</script>
</body>
</html>
      `);
    }

    if (method === "GET" && path === "/login") {
      return html(`
<!doctype html>
<html>
<head><meta charset="utf-8"><title>登录</title></head>
<body>
<h2>登录</h2>
<input id="email" placeholder="邮箱"><br><br>
<input id="password" type="password" placeholder="密码"><br><br>
<button onclick="login()">登录</button>
<p id="msg"></p>
<script>
async function login(){
  const r = await fetch('/api/login',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({
      email:email.value,
      password:password.value
    })
  });
  const j = await r.json();
  msg.innerText = j.error || '登录成功';
}
</script>
</body>
</html>
      `);
    }

    if (method === "GET" && path === "/me") {
      const sid = getCookie(request, "sid");
      if (!sid) return html("未登录");

      const sess = await env.DB.prepare(
        `SELECT users.email FROM sessions 
         JOIN users ON users.id=sessions.user_id
         WHERE sessions.id=? AND expires_at>?`
      ).bind(sid, now()).first();

      if (!sess) return html("登录已过期");

      return html(`<h3>已登录用户：${sess.email}</h3>`);
    }

    // ========== API ==========
    if (method === "POST" && path === "/api/register") {
      const body = await parseJSON(request);
      if (!body) return json({ error: "bad json" }, 400);

      const { email, password } = body;
      if (!email || !password) {
        return json({ error: "参数不完整" }, 400);
      }

      const exists = await env.DB.prepare(
        "SELECT id FROM users WHERE email=?"
      ).bind(email).first();

      if (exists) return json({ error: "邮箱已注册" }, 400);

      const passhash = await hash(password);

      await env.DB.prepare(
        "INSERT INTO users (email,password_hash,created_at) VALUES (?,?,?)"
      ).bind(email, passhash, now()).run();

      return json({ ok: true });
    }

    if (method === "POST" && path === "/api/login") {
      const body = await parseJSON(request);
      if (!body) return json({ error: "bad json" }, 400);

      const { email, password } = body;
      if (!email || !password) {
        return json({ error: "参数不完整" }, 400);
      }

      const user = await env.DB.prepare(
        "SELECT id,password_hash FROM users WHERE email=?"
      ).bind(email).first();

      if (!user) return json({ error: "账号不存在" }, 400);

      if ((await hash(password)) !== user.password_hash) {
        return json({ error: "密码错误" }, 400);
      }

      const sid = crypto.randomUUID();
      const exp = new Date(Date.now() + 7 * 86400 * 1000).toISOString();

      await env.DB.prepare(
        "INSERT INTO sessions (id,user_id,created_at,expires_at) VALUES (?,?,?,?)"
      ).bind(sid, user.id, now(), exp).run();

      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; SameSite=Lax`,
          "Content-Type": "application/json",
        },
      });
    }

    if (method === "POST" && path === "/api/logout") {
      const sid = getCookie(request, "sid");
      if (sid) {
        await env.DB.prepare("DELETE FROM sessions WHERE id=?")
          .bind(sid).run();
      }
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "Set-Cookie": "sid=; Max-Age=0; Path=/",
          "Content-Type": "application/json",
        },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
