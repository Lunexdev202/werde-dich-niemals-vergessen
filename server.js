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
      if (u.length < 3 || u.length > 24) return send(res, 400, {error:"Benutzername muss 3â€“24 Zeichen lang sein."});
      if (!/^[a-zA-Z0-9_.-]+$/.test(u)) return send(res, 400, {error:"Benutzername enthÃ¤lt ungÃ¼ltige Zeichen."});
      if (!e.includes("@")) return send(res, 400, {error:"Bitte eine gÃ¼ltige E-Mail eingeben."});
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

    if (req.method === "GET" && parsed.pathname === "/legal") {
      res.writeHead(200, {"Content-Type":"text/html; charset=utf-8"});
      return res.end(`<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rechtliches // THE CASE</title><style>body{margin:0;background:#09060f;color:#eee;font-family:Arial,sans-serif;padding:40px;line-height:1.7}main{max-width:900px;margin:auto;background:#120b1d;border:1px solid #6d28d9;border-radius:16px;padding:36px;box-shadow:0 0 40px #4c1d9555}h1{color:#c084fc}h2{color:#d8b4fe;border-bottom:1px solid #3b1d5c;padding-bottom:8px}a{color:#c084fc}.box{background:#0d0815;border:1px solid #2d1745;border-radius:10px;padding:16px;margin:18px 0}</style></head><body><main><h1>THE CASE // RECHTLICHES</h1><div class="box"><h2>1. Impressum</h2><p><strong>Betreiber:</strong><br>THE CASE</p><p><strong>Anschrift:</strong><br>Online-Projekt / keine öffentliche Anschrift<br>Deutschland<br>Deutschland</p><p><strong>E-Mail:</strong><br>kontakt@the-case.example</p></div><div class="box"><h2>2. Datenschutzerklärung / DSGVO</h2><p>THE CASE verarbeitet personenbezogene Daten, soweit dies für die Bereitstellung der Benutzerkonten und Funktionen erforderlich ist.</p><p>Bei einer Registrierung können insbesondere Benutzername, E-Mail-Adresse, Passwort-Hash, Profilinformationen und technische Sitzungsdaten verarbeitet werden.</p><p>Passwörter werden nicht im Klartext gespeichert, sondern als Hash verarbeitet.</p><p>Zur Anmeldung wird ein technisch notwendiges Session-Cookie verwendet. Dieses dient ausschließlich der Sitzungsverwaltung.</p><p>Betroffene Personen haben im Rahmen der gesetzlichen Voraussetzungen insbesondere Rechte auf Auskunft, Berichtigung, Löschung, Einschränkung der Verarbeitung und Widerspruch.</p><p><strong>Kontakt Datenschutz:</strong><br>kontakt@the-case.example</p></div><div class="box"><h2>3. Allgemeine Geschäftsbedingungen (AGB)</h2><p>Die Nutzung von THE CASE erfolgt ausschließlich im Rahmen der geltenden gesetzlichen Vorschriften.</p><p>Die Nutzer sind dafür verantwortlich, ihre Zugangsdaten vertraulich zu behandeln und keine rechtswidrigen Inhalte oder Aktivitäten über die Plattform durchzuführen.</p><p>Der Betreiber kann Funktionen ändern, erweitern, einschränken oder einstellen, soweit dies im Rahmen der gesetzlichen Vorgaben zulässig ist.</p><p>Eine missbräuchliche Nutzung kann zum Ausschluss von der Nutzung führen, soweit dies rechtlich zulässig ist.</p><p>Die Nutzung von THE CASE setzt die Anerkennung der jeweils geltenden Nutzungsbedingungen voraus.</p></div><p><a href="/">← Zurück zu THE CASE</a></p></main></body></html>`);
    }
    if (req.method === "GET" && parsed.pathname === "/api/candles") {
      const file = path.join(__dirname, "candles.json");
      let data = {count:0, visitors:{}};
      if (fs.existsSync(file)) {
        try { data = JSON.parse(fs.readFileSync(file, "utf8")); } catch {}
      }
      const visitor = (req.headers.cookie || "").match(/memorialVisitor=([^;]+)/)?.[1];
      return send(res, 200, {count:data.count || 0, hasCandle:!!(visitor && data.visitors && data.visitors[visitor])});
    }

    if (req.method === "POST" && parsed.pathname === "/api/candle") {
      const file = path.join(__dirname, "candles.json");
      let data = {count:0, visitors:{}};
      if (fs.existsSync(file)) {
        try { data = JSON.parse(fs.readFileSync(file, "utf8")); } catch {}
      }
      const cookies = req.headers.cookie || "";
      let visitor = cookies.match(/memorialVisitor=([^;]+)/)?.[1];
      if (!visitor) visitor = crypto.randomUUID();
      if (data.visitors[visitor]) {
        res.writeHead(200, {"Content-Type":"application/json","Set-Cookie":`memorialVisitor=${visitor}; SameSite=Lax; Path=/; Max-Age=31536000`});
        return res.end(JSON.stringify({ok:false,count:data.count,hasCandle:true}));
      }
      data.visitors[visitor] = true;
      data.count = (data.count || 0) + 1;
      fs.writeFileSync(file, JSON.stringify(data, null, 2));
      res.writeHead(201, {"Content-Type":"application/json","Set-Cookie":`memorialVisitor=${visitor}; SameSite=Lax; Path=/; Max-Age=31536000`});
      return res.end(JSON.stringify({ok:true,count:data.count,hasCandle:true}));
    }

    if (req.method === "GET" && parsed.pathname === "/api/memorial") {
    const file=path.join(__dirname,"memorial.json");
    let data={name:"",birth:"",death:"",time:""};
    if(fs.existsSync(file)){try{data=JSON.parse(fs.readFileSync(file,"utf8"));}catch{}}
    return send(res,200,data);
  }

  if (req.method === "POST" && parsed.pathname === "/api/memorial") {
    const data=await body(req);
    if(!data.death||!data.time)return send(res,400,{error:"Sterbedatum und Uhrzeit erforderlich"});
    const clean={
      
      birth:String(data.birth||""),
      death:String(data.death).trim(),
      time:String(data.time).trim()
    };
    fs.writeFileSync(path.join(__dirname,"memorial.json"),JSON.stringify(clean,null,2));
    return send(res,200,{ok:true,...clean});
  }

  if (req.method === "GET" && parsed.pathname === "/gamehub") return serve(res, "/gamehub.html");
    if (req.method === "GET") return serve(res, parsed.pathname);
    send(res, 404, {error:"Not found"});
  } catch (e) {
    console.error(e);
    send(res, 500, {error:"Serverfehler."});
  }
});

server.listen(PORT, () => console.log(`Gedenkseite läuft auf http://localhost:${PORT}`));








