const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const url = require("url");

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DB = path.join(ROOT, "users.json");
const sessions = new Map();

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(DB, "utf8")); }
  catch { return []; }
}
function saveUsers(users) {
  fs.writeFileSync(DB, JSON.stringify(users, null, 2));
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const test = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(test, "hex"));
}
function token() { return crypto.randomBytes(32).toString("hex"); }
function body(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { reject(new Error("JSON")); } });
    req.on("error", reject);
  });
}
function auth(req) {
  const t = (req.headers.cookie || "").match(/session=([^;]+)/)?.[1];
  return t ? sessions.get(t) : null;
}
function send(res, status, data) {
  res.writeHead(status, {"Content-Type":"application/json; charset=utf-8"});
  res.end(JSON.stringify(data));
}
function serve(res, pathname) {
  const file = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const full = path.join(__dirname, "public", file);
  if (!full.startsWith(path.join(__dirname, "public")) || !fs.existsSync(full)) return send(res, 404, {error:"Not found"});
  const ext = path.extname(full);
  const types = {".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8"};
  res.writeHead(200, {"Content-Type": types[ext] || "text/plain; charset=utf-8"});
  fs.createReadStream(full).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  try {
    if (req.method === "POST" && parsed.pathname === "/api/register") {
      const {username, email, password} = await body(req);
      const u = String(username || "").trim();
      const e = String(email || "").trim().toLowerCase();
      if (u.length < 3 || u.length > 24) return send(res, 400, {error:"Benutzername muss 3–24 Zeichen lang sein."});
      if (!/^[a-zA-Z0-9_.-]+$/.test(u)) return send(res, 400, {error:"Benutzername enthält ungültige Zeichen."});
      if (!e.includes("@")) return send(res, 400, {error:"Bitte eine gültige E-Mail eingeben."});
      if (String(password || "").length < 8) return send(res, 400, {error:"Passwort muss mindestens 8 Zeichen haben."});
      const users = loadUsers();
      if (users.some(x => x.username.toLowerCase() === u.toLowerCase())) return send(res, 409, {error:"Benutzername ist bereits vergeben."});
      if (users.some(x => x.email === e)) return send(res, 409, {error:"E-Mail ist bereits registriert."});
      const user = {id: crypto.randomUUID(), username:u, email:e, password:hashPassword(password), bio:"", createdAt:new Date().toISOString()};
      users.push(user); saveUsers(users);
      const t = token(); sessions.set(t, user.id);
      res.writeHead(201, {"Content-Type":"application/json", "Set-Cookie":`session=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`});
      return res.end(JSON.stringify({user:{id:user.id,username:user.username,email:user.email,bio:user.bio,createdAt:user.createdAt}}));
    }

    if (req.method === "POST" && parsed.pathname === "/api/login") {
      const {login, password} = await body(req);
      const users = loadUsers();
      const user = users.find(x => x.email === String(login||"").toLowerCase() || x.username.toLowerCase() === String(login||"").toLowerCase());
      if (!user || !verifyPassword(String(password||""), user.password)) return send(res, 401, {error:"Login-Daten sind falsch."});
      const t = token(); sessions.set(t, user.id);
      res.writeHead(200, {"Content-Type":"application/json", "Set-Cookie":`session=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`});
      return res.end(JSON.stringify({user:{id:user.id,username:user.username,email:user.email,bio:user.bio,createdAt:user.createdAt}}));
    }

    if (req.method === "POST" && parsed.pathname === "/api/logout") {
      const t = (req.headers.cookie || "").match(/session=([^;]+)/)?.[1];
      if (t) sessions.delete(t);
      res.writeHead(200, {"Content-Type":"application/json","Set-Cookie":"session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"});
      return res.end(JSON.stringify({ok:true}));
    }

    if (req.method === "GET" && parsed.pathname === "/api/me") {
      const id = auth(req);
      const user = id && loadUsers().find(x => x.id === id);
      if (!user) return send(res, 401, {error:"Nicht eingeloggt."});
      return send(res, 200, {user:{id:user.id,username:user.username,email:user.email,bio:user.bio,createdAt:user.createdAt}});
    }

    if (req.method === "POST" && parsed.pathname === "/api/profile") {
      const id = auth(req);
      if (!id) return send(res, 401, {error:"Nicht eingeloggt."});
      const {bio} = await body(req);
      const users = loadUsers();
      const user = users.find(x => x.id === id);
      if (!user) return send(res, 401, {error:"Nicht eingeloggt."});
      user.bio = String(bio || "").slice(0, 160);
      saveUsers(users);
      return send(res, 200, {user:{id:user.id,username:user.username,email:user.email,bio:user.bio,createdAt:user.createdAt}});
    }

    if (req.method === "GET") return serve(res, parsed.pathname);
    send(res, 404, {error:"Not found"});
  } catch (e) {
    console.error(e);
    send(res, 500, {error:"Serverfehler."});
  }
});

server.listen(PORT, () => console.log(`Cyber Account Web läuft auf http://localhost:${PORT}`));
