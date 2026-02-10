const path = require("path");
const fs = require("fs");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");
const express = require("express");
const WebSocket = require("ws");

const app = express();

const PORT = process.env.PORT || 3000;
const HISTORY_LIMIT = 120;
const USERS_FILE = path.join(__dirname, "users.json");
const BANS_FILE = path.join(__dirname, "bans.json");
const ROOMS_FILE = path.join(__dirname, "rooms.json");
const DMS_FILE = path.join(__dirname, "dms.json");
const MOD_LOG = path.join(__dirname, "moderation.log");
const SALT_ROUNDS = 10;
const AVATAR_MAX_BYTES = 5 * 1024 * 1024;
const MAX_MESSAGE_LEN = 400;
const FIREBASE_SERVICE_PATH = process.env.FIREBASE_SERVICE_PATH || "";
const FIREBASE_SERVICE_JSON = process.env.FIREBASE_SERVICE_JSON || "";

const users = new Map();
const messagesByRoom = new Map();
const roomUsers = new Map();
let accounts = loadUsers();
normalizeAccounts();
let bans = loadBans();
const muted = new Set();
const ipMessageBuckets = new Map();
const ipAuthBuckets = new Map();
let dms = loadDms();

let firebaseReady = false;
try {
  let serviceAccount = null;
  if (FIREBASE_SERVICE_JSON) {
    serviceAccount = JSON.parse(FIREBASE_SERVICE_JSON);
  } else if (FIREBASE_SERVICE_PATH && fs.existsSync(FIREBASE_SERVICE_PATH)) {
    serviceAccount = require(FIREBASE_SERVICE_PATH);
  }

  if (serviceAccount) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    firebaseReady = true;
  }
} catch {
  firebaseReady = false;
}

function nowTime() {
  const d = new Date();
  return d.toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
}

function hashSha256(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function isBcryptHash(value) {
  return typeof value === "string" && value.startsWith("$2");
}

function loadUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, "utf-8");
    const data = JSON.parse(raw);
    if (typeof data !== "object" || !data) return {};
    return data;
  } catch {
    return {};
  }
}

function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(accounts, null, 2));
}

function normalizeAccounts() {
  for (const [nick, acc] of Object.entries(accounts)) {
    if (!acc || typeof acc !== "object") continue;
    if (!acc.status) acc.status = "listo";
    if (!acc.role) acc.role = "user";
    if (!acc.bio) acc.bio = "";
    if (!acc.color) acc.color = "";
    if (!acc.avatar) acc.avatar = "";
    if (!Array.isArray(acc.tokens)) acc.tokens = [];
    if (!Array.isArray(acc.blocked)) acc.blocked = [];
    if (!acc.uid) acc.uid = "";
    if (!acc.email) acc.email = "";
  }
  saveUsers();
}

function loadBans() {
  try {
    const raw = fs.readFileSync(BANS_FILE, "utf-8");
    const data = JSON.parse(raw);
    if (Array.isArray(data)) {
      return { nicks: data, ips: [] };
    }
    if (typeof data === "object" && data) {
      return {
        nicks: Array.isArray(data.nicks) ? data.nicks : [],
        ips: Array.isArray(data.ips) ? data.ips : []
      };
    }
    return { nicks: [], ips: [] };
  } catch {
    return { nicks: [], ips: [] };
  }
}

function saveBans() {
  fs.writeFileSync(BANS_FILE, JSON.stringify(bans, null, 2));
}

function loadRooms() {
  try {
    const raw = fs.readFileSync(ROOMS_FILE, "utf-8");
    const data = JSON.parse(raw);
    if (typeof data !== "object" || !data) return {};
    return data;
  } catch {
    return {};
  }
}

function loadDms() {
  try {
    const raw = fs.readFileSync(DMS_FILE, "utf-8");
    const data = JSON.parse(raw);
    if (typeof data !== "object" || !data) return {};
    return data;
  } catch {
    return {};
  }
}

function saveDms() {
  fs.writeFileSync(DMS_FILE, JSON.stringify(dms, null, 2));
}

function saveRooms() {
  const obj = {};
  for (const [room, list] of messagesByRoom.entries()) obj[room] = list;
  fs.writeFileSync(ROOMS_FILE, JSON.stringify(obj, null, 2));
}

function normalizeRoom(room) {
  let name = String(room || "").trim().toLowerCase();
  if (!name) return "#general";
  if (!name.startsWith("#")) name = `#${name}`;
  name = name.replace(/[^#a-z0-9_-]/g, "").slice(0, 40);
  if (name.length < 2) return "#general";
  return name;
}


function normalizeRegionPart(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 20);
}

function buildRegionRooms(country, state, city) {
  const c = normalizeRegionPart(country);
  if (!c) return [];
  const rooms = [`#pais-${c}`];
  const s = normalizeRegionPart(state);
  const ci = normalizeRegionPart(city);
  if (s) rooms.push(`#pais-${c}-${s}`);
  if (s && ci) rooms.push(`#pais-${c}-${s}-${ci}`);
  return rooms;
}

function ensureRegionRooms(country, state, city) {
  const rooms = buildRegionRooms(country, state, city);
  rooms.forEach((r) => getRoom(r));
  return rooms;
}

function pickDefaultRoom(rooms) {
  return rooms.length ? rooms[rooms.length - 1] : "#general";
}

function getRoom(name) {
  const room = normalizeRoom(name);
  if (!messagesByRoom.has(room)) messagesByRoom.set(room, []);
  if (!roomUsers.has(room)) roomUsers.set(room, new Set());
  return room;
}

function roomHistory(room) {
  return messagesByRoom.get(room) || [];
}

function pushMessage(room, msg) {
  const list = messagesByRoom.get(room) || [];
  list.push(msg);
  if (list.length > HISTORY_LIMIT) list.shift();
  messagesByRoom.set(room, list);
  saveRooms();
}

function broadcast(payload) {
  const data = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) client.send(data);
  }
}

function broadcastToRoom(room, payload) {
  const data = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client.readyState !== WebSocket.OPEN) continue;
    const u = users.get(client.__id);
    if (u && u.room === room && u.authenticated) client.send(data);
  }
}

function systemMessage(room, text) {
  const msg = {
    type: "system",
    id: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    text,
    time: nowTime()
  };
  pushMessage(room, msg);
  broadcastToRoom(room, { type: "message", message: msg });
}

function userList(room) {
  return Array.from(users.values())
    .filter((u) => u.authenticated && u.room === room)
    .map((u) => ({
      id: u.id,
      nick: u.nick,
      status: u.status,
      lastActive: u.lastActive,
      color: u.color || "",
      avatar: u.avatar || "",
      bio: u.bio || "",
      country: u.country || "",
      state: u.state || "",
      city: u.city || ""
    }));
}

function roomList() {
  const names = new Set();
  for (const name of messagesByRoom.keys()) names.add(name);
  for (const name of roomUsers.keys()) names.add(name);
  if (!names.size) names.add("#general");

  return Array.from(names).map((name) => ({
    name,
    count: roomUsers.get(name)?.size || 0
  }));
}

function updatePresence(room) {
  broadcastToRoom(room, { type: "presence", room, users: userList(room) });
}

function updateRooms() {
  broadcast({ type: "rooms", rooms: roomList() });
}

function makeGuest() {
  return `guest${Math.floor(100 + Math.random() * 900)}`;
}

function isNickOnline(nick) {
  return Array.from(users.values()).some((u) => u.authenticated && u.nick === nick);
}

function isBanned(nick, ip) {
  return bans.nicks.includes(nick) || (ip && bans.ips.includes(ip));
}

async function verifyPassword(nick, password) {
  const acc = accounts[nick];
  if (!acc) return false;
  if (isBcryptHash(acc.password)) {
    return bcrypt.compare(password, acc.password);
  }
  const ok = acc.password === hashSha256(password);
  if (ok) {
    acc.password = await bcrypt.hash(password, SALT_ROUNDS);
    saveUsers();
  }
  return ok;
}

async function setPassword(nick, password) {
  accounts[nick].password = await bcrypt.hash(password, SALT_ROUNDS);
  saveUsers();
}

function rateLimit(bucketMap, key, limit, windowMs) {
  const now = Date.now();
  const list = bucketMap.get(key) || [];
  const filtered = list.filter((t) => now - t < windowMs);
  if (filtered.length >= limit) {
    bucketMap.set(key, filtered);
    return false;
  }
  filtered.push(now);
  bucketMap.set(key, filtered);
  return true;
}

function validateAvatar(dataUrl) {
  if (!dataUrl) return "";
  if (dataUrl.startsWith("http://") || dataUrl.startsWith("https://")) return dataUrl;
  if (!dataUrl.startsWith("data:image/")) return "";
  const size = Buffer.byteLength(dataUrl, "utf-8");
  if (size > AVATAR_MAX_BYTES) return "";
  return dataUrl;
}

function uniqueNick(base) {
  let nick = base || "user";
  if (!accounts[nick]) return nick;
  let i = 1;
  while (accounts[`${nick}${i}`]) i += 1;
  return `${nick}${i}`;
}

function findNickByUid(uid) {
  if (!uid) return "";
  for (const [nick, acc] of Object.entries(accounts)) {
    if (acc && acc.uid === uid) return nick;
  }
  return "";
}

function updateProfile(u, patch) {
  if (typeof patch.status === "string") {
    u.status = patch.status.trim().slice(0, 40) || u.status;
  }
  if (typeof patch.bio === "string") {
    u.bio = patch.bio.trim().slice(0, 120);
  }
  if (typeof patch.color === "string") {
    const color = patch.color.trim();
    if (/^#[0-9a-fA-F]{6}$/.test(color)) u.color = color;
  }
  if (typeof patch.avatar === "string") {
    u.avatar = validateAvatar(patch.avatar);
  }
  if (typeof patch.country === "string") {
    u.country = patch.country.trim().slice(0, 40);
  }
  if (typeof patch.state === "string") {
    u.state = patch.state.trim().slice(0, 40);
  }
  if (typeof patch.city === "string") {
    u.city = patch.city.trim().slice(0, 40);
  }

  if (u.country || u.state || u.city) {
    ensureRegionRooms(u.country, u.state, u.city);
  }

  if (accounts[u.nick]) {
    accounts[u.nick].status = u.status;
    accounts[u.nick].bio = u.bio || "";
    accounts[u.nick].color = u.color || "";
    accounts[u.nick].avatar = u.avatar || "";
    accounts[u.nick].country = u.country || "";
    accounts[u.nick].state = u.state || "";
    accounts[u.nick].city = u.city || "";
    saveUsers();
  }
}

function hydrateRooms() {
  const data = loadRooms();
  for (const [room, list] of Object.entries(data)) {
    messagesByRoom.set(room, Array.isArray(list) ? list : []);
    if (!roomUsers.has(room)) roomUsers.set(room, new Set());
  }
}

function getIp(ws) {
  const raw = ws._socket?.remoteAddress || "";
  return raw.replace("::ffff:", "");
}

function logModeration(action, actor, target, ip) {
  const line = `[${new Date().toISOString()}] ${action} by ${actor} on ${target} ip=${ip}\n`;
  fs.appendFileSync(MOD_LOG, line);
}

function issueToken(nick) {
  const token = crypto.randomBytes(24).toString("hex");
  accounts[nick].tokens = Array.isArray(accounts[nick].tokens) ? accounts[nick].tokens : [];
  accounts[nick].tokens.unshift(token);
  accounts[nick].tokens = accounts[nick].tokens.slice(0, 5);
  saveUsers();
  return token;
}

function consumeToken(token) {
  if (!token) return null;
  const entries = Object.entries(accounts);
  for (const [nick, acc] of entries) {
    if (Array.isArray(acc.tokens) && acc.tokens.includes(token)) {
      return nick;
    }
  }
  return null;
}

function revokeToken(nick, token) {
  if (!nick || !token || !accounts[nick]) return;
  accounts[nick].tokens = (accounts[nick].tokens || []).filter((t) => t !== token);
  saveUsers();
}

function dmId(a, b) {
  const [x, y] = [a, b].map((s) => String(s || "").trim().toLowerCase()).sort();
  return `dm:${x}:${y}`;
}

function getDmThread(a, b) {
  const id = dmId(a, b);
  if (!dms[id]) dms[id] = [];
  return { id, list: dms[id] };
}

function pushDm(a, b, msg) {
  const thread = getDmThread(a, b);
  thread.list.push(msg);
  if (thread.list.length > HISTORY_LIMIT) thread.list.shift();
  dms[thread.id] = thread.list;
  saveDms();
}

function findOnlineByNick(nick) {
  for (const u of users.values()) {
    if (u.authenticated && u.nick === nick) return u;
  }
  return null;
}

function isBlocked(byNick, targetNick) {
  const acc = accounts[byNick];
  if (!acc || !Array.isArray(acc.blocked)) return false;
  return acc.blocked.includes(targetNick);
}

function handleDmSend(u, ws, toInput, text) {
  const to = resolveNick(toInput);
  if (!to) {
    ws.send(JSON.stringify({ type: "dm_error", text: "Usuario no existe." }));
    return;
  }
  if (isBlocked(u.nick, to)) {
    ws.send(JSON.stringify({ type: "dm_error", text: "Has bloqueado a ese usuario." }));
    return;
  }
  if (isBlocked(to, u.nick)) {
    ws.send(JSON.stringify({ type: "dm_error", text: "Este usuario te ha bloqueado." }));
    return;
  }

  const msg = {
    type: "dm",
    id: `dm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    from: u.nick,
    to,
    text,
    time: nowTime()
  };
  pushDm(u.nick, to, msg);
  ws.send(JSON.stringify({ type: "dm_message", message: msg }));
  const target = findOnlineByNick(to);
  if (target) {
    for (const client of wss.clients) {
      if (client.readyState !== WebSocket.OPEN) continue;
      const tu = users.get(client.__id);
      if (tu && tu.nick === to) {
        client.send(JSON.stringify({ type: "dm_message", message: msg }));
      }
    }
  }
}

function resolveNick(input) {
  const raw = String(input || "").trim();
  if (!raw) return "";
  if (accounts[raw]) return raw;
  const lower = raw.toLowerCase();
  const match = Object.keys(accounts).find((n) => n.toLowerCase() === lower);
  return match || "";
}

hydrateRooms();

const sslKey = process.env.SSL_KEY;
const sslCert = process.env.SSL_CERT;
let server;
if (sslKey && sslCert && fs.existsSync(sslKey) && fs.existsSync(sslCert)) {
  server = https.createServer({
    key: fs.readFileSync(sslKey),
    cert: fs.readFileSync(sslCert)
  }, app);
} else {
  server = http.createServer(app);
}

const wss = new WebSocket.Server({ server });

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

wss.on("connection", (ws) => {
  const id = `u_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  ws.__id = id;
  const ip = getIp(ws);

  if (isBanned("", ip)) {
    ws.close();
    return;
  }

  const user = {
    id,
    nick: makeGuest(),
    status: "sin registrar",
    lastActive: nowTime(),
    authenticated: false,
    room: "#general",
    role: "user",
    msgTimes: [],
    lastNudge: 0,
    bio: "",
    color: "",
    avatar: "",
    country: "",
    state: "",
    city: "",
    ip,
    blocked: []
  };
  users.set(id, user);

  ws.send(
    JSON.stringify({
      type: "init",
      self: user,
      rooms: roomList(),
      authRequired: true
    })
  );

  ws.on("message", async (raw) => {
    let payload;
    try {
      payload = JSON.parse(raw);
    } catch {
      return;
    }

    const u = users.get(id);
    if (!u) return;
    u.lastActive = nowTime();

    if (payload.type === "ping") {
      ws.send(JSON.stringify({ type: "pong" }));
      return;
    }

    if (payload.type === "auth_token") {
      const token = String(payload.token || "").trim();
      const nick = consumeToken(token);
      if (!nick || !accounts[nick]) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Sesión inválida." }));
        return;
      }
      if (isNickOnline(nick)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Ese nick ya está en línea." }));
        return;
      }
      if (isBanned(nick, ip)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Acceso bloqueado." }));
        return;
      }

      u.nick = nick;
      u.status = accounts[nick].status || "listo";
      u.role = accounts[nick].role || "user";
      u.bio = accounts[nick].bio || "";
      u.color = accounts[nick].color || "";
      u.avatar = accounts[nick].avatar || "";
      u.country = accounts[nick].country || "";
      u.state = accounts[nick].state || "";
      u.city = accounts[nick].city || "";
      const regionRooms = ensureRegionRooms(u.country, u.state, u.city);
      const preferred = accounts[nick].lastRoom || pickDefaultRoom(regionRooms);
      u.authenticated = true;
      u.room = getRoom(preferred || "#general");

      roomUsers.get(u.room).add(u.id);

      ws.send(JSON.stringify({ type: "auth_ok", self: u, token }));
      ws.send(JSON.stringify({ type: "system", text: `Bienvenido ${u.nick}.` }));
      systemMessage(u.room, `${u.nick} se conectó.`);
      updatePresence(u.room);
      updateRooms();
      ws.send(JSON.stringify({ type: "room_sync", room: u.room, messages: roomHistory(u.room), users: userList(u.room) }));
      return;
    }

    if (payload.type === "firebase_auth") {
      const idToken = String(payload.token || "").trim();
      if (!firebaseReady) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Firebase Admin no configurado." }));
        return;
      }
      if (!idToken) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Token inválido." }));
        return;
      }
      if (isBanned("", ip)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Acceso bloqueado." }));
        return;
      }

      let decoded;
      try {
        decoded = await admin.auth().verifyIdToken(idToken);
      } catch {
        ws.send(JSON.stringify({ type: "auth_error", text: "Token no válido." }));
        return;
      }

      const uid = String(decoded.uid || "").trim();
      const email = String(decoded.email || "").trim();
      const displayName = String(decoded.name || "").trim();
      const photoURL = String(decoded.picture || "").trim();
      if (!uid) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Auth inválida." }));
        return;
      }

      let nick = findNickByUid(uid);
      if (!nick) {
        const base = displayName || (email ? email.split("@")[0] : "") || `user${Math.floor(1000 + Math.random() * 9000)}`;
        nick = uniqueNick(base);
        accounts[nick] = {
          password: "",
          status: "listo",
          role: "user",
          bio: "",
          color: "",
          avatar: photoURL || "",
          tokens: [],
          blocked: [],
          uid,
          email
        };
        saveUsers();
      }

      u.nick = nick;
      u.status = accounts[nick].status || "listo";
      u.role = accounts[nick].role || "user";
      u.bio = accounts[nick].bio || "";
      u.color = accounts[nick].color || "";
      u.avatar = accounts[nick].avatar || photoURL || "";
      u.country = accounts[nick].country || "";
      u.state = accounts[nick].state || "";
      u.city = accounts[nick].city || "";
      const regionRooms = ensureRegionRooms(u.country, u.state, u.city);
      const preferred = accounts[nick].lastRoom || pickDefaultRoom(regionRooms);
      u.authenticated = true;
      u.room = getRoom(preferred || "#general");

      roomUsers.get(u.room).add(u.id);

      const token = issueToken(nick);
      ws.send(JSON.stringify({ type: "auth_ok", self: u, token }));
      ws.send(JSON.stringify({ type: "system", text: `Bienvenido ${u.nick}.` }));
      systemMessage(u.room, `${u.nick} se conectó.`);
      updatePresence(u.room);
      updateRooms();
      ws.send(JSON.stringify({ type: "room_sync", room: u.room, messages: roomHistory(u.room), users: userList(u.room) }));
      return;
    }

    if (payload.type === "logout") {
      const token = String(payload.token || "").trim();
      if (u && u.nick && token) {
        revokeToken(u.nick, token);
      }
      ws.send(JSON.stringify({ type: "logout_ok" }));
      ws.close();
      return;
    }

    if (payload.type === "register") {
      if (!rateLimit(ipAuthBuckets, ip, 5, 60000)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Demasiados intentos. Intenta más tarde." }));
        return;
      }
      const nick = String(payload.nick || "").trim();
      const password = String(payload.password || "").trim();
      const status = String(payload.status || "").trim();
      const country = String(payload.country || "").trim();
      const state = String(payload.state || "").trim();
      const city = String(payload.city || "").trim();

      if (!nick || !password) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Nick y contraseña requeridos." }));
        return;
      }
      if (accounts[nick]) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Ese nick ya existe." }));
        return;
      }
      if (isBanned(nick, ip)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Acceso bloqueado." }));
        return;
      }

      accounts[nick] = {
        password: "",
        status: status ? status.slice(0, 40) : "listo",
        role: "user",
        bio: "",
        color: "",
        avatar: "",
        tokens: [],
        blocked: [],
        country: country.slice(0, 40),
        state: state.slice(0, 40),
        city: city.slice(0, 40),
        lastRoom: ""
      };
      await setPassword(nick, password);

      u.nick = nick;
      u.status = accounts[nick].status;
      u.role = accounts[nick].role || "user";
      u.bio = accounts[nick].bio || "";
      u.color = accounts[nick].color || "";
      u.avatar = accounts[nick].avatar || "";
      u.blocked = accounts[nick].blocked || [];
      u.country = accounts[nick].country || "";
      u.state = accounts[nick].state || "";
      u.city = accounts[nick].city || "";
      const regionRooms = ensureRegionRooms(u.country, u.state, u.city);
      accounts[nick].lastRoom = pickDefaultRoom(regionRooms);
      u.authenticated = true;
      u.room = getRoom(accounts[nick].lastRoom || "#general");

      roomUsers.get(u.room).add(u.id);

      const token = issueToken(nick);
      ws.send(JSON.stringify({ type: "auth_ok", self: u, token }));
      ws.send(JSON.stringify({ type: "system", text: `Bienvenido ${u.nick}.` }));
      systemMessage(u.room, `${u.nick} se conectó.`);
      updatePresence(u.room);
      updateRooms();
      ws.send(JSON.stringify({ type: "room_sync", room: u.room, messages: roomHistory(u.room), users: userList(u.room) }));
      return;
    }

    if (payload.type === "login") {
      if (!rateLimit(ipAuthBuckets, ip, 8, 60000)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Demasiados intentos. Intenta más tarde." }));
        return;
      }
      const nick = String(payload.nick || "").trim();
      const password = String(payload.password || "").trim();

      if (!accounts[nick]) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Nick no registrado." }));
        return;
      }
      if (isBanned(nick, ip)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Acceso bloqueado." }));
        return;
      }
      if (isNickOnline(nick)) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Ese nick ya está en línea." }));
        return;
      }
      const ok = await verifyPassword(nick, password);
      if (!ok) {
        ws.send(JSON.stringify({ type: "auth_error", text: "Contraseña incorrecta." }));
        return;
      }

      u.nick = nick;
      u.status = accounts[nick].status || "listo";
      u.role = accounts[nick].role || "user";
      u.bio = accounts[nick].bio || "";
      u.color = accounts[nick].color || "";
      u.avatar = accounts[nick].avatar || "";
      u.blocked = accounts[nick].blocked || [];
      u.country = accounts[nick].country || "";
      u.state = accounts[nick].state || "";
      u.city = accounts[nick].city || "";
      const regionRooms = ensureRegionRooms(u.country, u.state, u.city);
      accounts[nick].lastRoom = pickDefaultRoom(regionRooms);
      u.authenticated = true;
      u.room = getRoom(accounts[nick].lastRoom || "#general");

      roomUsers.get(u.room).add(u.id);

      const token = issueToken(nick);
      ws.send(JSON.stringify({ type: "auth_ok", self: u, token }));
      ws.send(JSON.stringify({ type: "system", text: `Bienvenido ${u.nick}.` }));
      systemMessage(u.room, `${u.nick} se conectó.`);
      updatePresence(u.room);
      updateRooms();
      ws.send(JSON.stringify({ type: "room_sync", room: u.room, messages: roomHistory(u.room), users: userList(u.room) }));
      return;
    }

    if (!u.authenticated) {
      ws.send(JSON.stringify({ type: "auth_error", text: "Debes iniciar sesión." }));
      return;
    }

    if (payload.type === "history") {
      ws.send(JSON.stringify({ type: "room_sync", room: u.room, messages: roomHistory(u.room), users: userList(u.room) }));
      return;
    }

    if (payload.type === "profile_update") {
      const patch = payload.patch || {};
      if (patch.nick) {
        const nextNick = String(patch.nick || "").trim();
        if (!nextNick) {
          ws.send(JSON.stringify({ type: "system", text: "Nick inválido." }));
          return;
        }
        if (accounts[nextNick] && nextNick !== u.nick) {
          ws.send(JSON.stringify({ type: "system", text: "Ese nick ya está registrado." }));
          return;
        }
        const old = u.nick;
        const oldAccount = accounts[old] || { password: hashSha256(""), status: u.status, role: u.role, bio: "", color: "", avatar: "", tokens: [], blocked: [] };
        delete accounts[old];
        accounts[nextNick] = {
          password: oldAccount.password,
          status: u.status,
          role: oldAccount.role || "user",
          bio: oldAccount.bio || "",
          color: oldAccount.color || "",
          avatar: oldAccount.avatar || "",
          tokens: oldAccount.tokens || [],
          blocked: oldAccount.blocked || [],
          country: oldAccount.country || "",
          state: oldAccount.state || "",
          city: oldAccount.city || "",
          lastRoom: oldAccount.lastRoom || ""
        };
        saveUsers();
        u.nick = nextNick.slice(0, 18);
        systemMessage(u.room, `${old} ahora es ${u.nick}.`);
      }

      updateProfile(u, patch);
      ws.send(JSON.stringify({ type: "profile_ok", self: u }));
      updatePresence(u.room);
      return;
    }

    if (payload.type === "password_update") {
      const current = String(payload.current || "").trim();
      const next = String(payload.next || "").trim();
      if (!current || !next) {
        ws.send(JSON.stringify({ type: "system", text: "Debes completar la contraseña actual y la nueva." }));
        return;
      }
      const ok = await verifyPassword(u.nick, current);
      if (!ok) {
        ws.send(JSON.stringify({ type: "system", text: "Contraseña actual incorrecta." }));
        return;
      }
      await setPassword(u.nick, next);
      ws.send(JSON.stringify({ type: "system", text: "Contraseña actualizada." }));
      return;
    }

    if (payload.type === "block_user") {
      const target = String(payload.nick || "").trim();
      if (!target || target === u.nick) return;
      const acc = accounts[u.nick];
      acc.blocked = Array.isArray(acc.blocked) ? acc.blocked : [];
      if (!acc.blocked.includes(target)) acc.blocked.push(target);
      saveUsers();
      u.blocked = acc.blocked;
      ws.send(JSON.stringify({ type: "block_ok", blocked: u.blocked }));
      return;
    }

    if (payload.type === "unblock_user") {
      const target = String(payload.nick || "").trim();
      const acc = accounts[u.nick];
      acc.blocked = Array.isArray(acc.blocked) ? acc.blocked : [];
      acc.blocked = acc.blocked.filter((n) => n !== target);
      saveUsers();
      u.blocked = acc.blocked;
      ws.send(JSON.stringify({ type: "block_ok", blocked: u.blocked }));
      return;
    }

    if (payload.type === "dm_history") {
      const other = String(payload.nick || "").trim();
      if (!other) return;
      const thread = getDmThread(u.nick, other);
      ws.send(JSON.stringify({ type: "dm_history", nick: other, messages: thread.list }));
      return;
    }

    if (payload.type === "dm_send") {
      const toInput = String(payload.to || "").trim();
      const text = String(payload.text || "").trim();
      if (!toInput || !text) return;
      if (text.length > MAX_MESSAGE_LEN) {
        ws.send(JSON.stringify({ type: "system", text: "Mensaje demasiado largo." }));
        return;
      }
      handleDmSend(u, ws, toInput, text);
      return;
    }

    if (payload.type === "chat") {
      const text = String(payload.text || "").trim();
      if (!text) return;
      if (text.length > MAX_MESSAGE_LEN) {
        ws.send(JSON.stringify({ type: "system", text: "Mensaje demasiado largo." }));
        return;
      }
      if (muted.has(u.nick)) {
        ws.send(JSON.stringify({ type: "system", text: "Estás silenciado." }));
        return;
      }
      if (!rateLimit(ipMessageBuckets, ip, 10, 5000)) {
        ws.send(JSON.stringify({ type: "system", text: "Estás enviando mensajes muy rápido." }));
        return;
      }
      const msg = {
        type: "chat",
        id: `m_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        nick: u.nick,
        text,
        time: nowTime(),
        reactions: {},
        color: u.color || "",
        avatar: u.avatar || ""
      };
      pushMessage(u.room, msg);
      broadcastToRoom(u.room, { type: "message", message: msg });
      updatePresence(u.room);
      return;
    }

    if (payload.type === "command") {
      const cmd = String(payload.command || "").toLowerCase();
      const args = String(payload.args || "").trim();

      if (cmd === "join") {
        const next = getRoom(args || "#general");
        if (u.room !== next) {
          const oldRoom = u.room;
          roomUsers.get(oldRoom)?.delete(u.id);
          updatePresence(oldRoom);
          systemMessage(oldRoom, `${u.nick} salió.`);

          u.room = next;
          roomUsers.get(next).add(u.id);
          systemMessage(next, `${u.nick} entró.`);
          updatePresence(next);
          updateRooms();
          if (accounts[u.nick]) {
            accounts[u.nick].lastRoom = u.room;
            saveUsers();
          }
        }
        ws.send(JSON.stringify({ type: "room_sync", room: u.room, messages: roomHistory(u.room), users: userList(u.room) }));
        return;
      }

      if (cmd === "rooms") {
        ws.send(JSON.stringify({ type: "rooms", rooms: roomList() }));
        return;
      }

      if (cmd === "me") {
        if (!args) return;
        const msg = {
          type: "action",
          id: `m_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          nick: u.nick,
          text: args,
          time: nowTime(),
          reactions: {},
          color: u.color || "",
          avatar: u.avatar || ""
        };
        pushMessage(u.room, msg);
        broadcastToRoom(u.room, { type: "message", message: msg });
        updatePresence(u.room);
        return;
      }

      if (cmd === "status") {
        if (!args) {
          ws.send(JSON.stringify({ type: "system", text: "Uso: /status tuEstado" }));
          return;
        }
        u.status = args.slice(0, 40);
        if (accounts[u.nick]) {
          accounts[u.nick].status = u.status;
          saveUsers();
        }
        systemMessage(u.room, `${u.nick} cambió estado a: ${u.status}`);
        updatePresence(u.room);
        return;
      }

      if (cmd === "help") {
        ws.send(
          JSON.stringify({
            type: "system",
            text: "Comandos: /join, /rooms, /me, /status, /nudge, /dm, /help, /clear"
          })
        );
        return;
      }

      if (cmd === "clear") {
        ws.send(JSON.stringify({ type: "clear" }));
        return;
      }

      if (cmd === "nudge") {
        const now = Date.now();
        if (now - (u.lastNudge || 0) < 15000) {
          ws.send(JSON.stringify({ type: "system", text: "Espera unos segundos para enviar otro zumbido." }));
          return;
        }
        u.lastNudge = now;
        broadcastToRoom(u.room, { type: "nudge", from: u.nick, time: nowTime() });
        return;
      }

      if (cmd === "dm") {
        const [toInput, ...rest] = args.split(" ");
        const text = rest.join(" ").trim();
        if (!toInput || !text) {
          ws.send(JSON.stringify({ type: "dm_error", text: "Uso: /dm nick mensaje" }));
          return;
        }
        if (text.length > MAX_MESSAGE_LEN) {
          ws.send(JSON.stringify({ type: "dm_error", text: "Mensaje demasiado largo." }));
          return;
        }
        handleDmSend(u, ws, toInput, text);
        return;
      }

      if (cmd === "kick" || cmd === "ban" || cmd === "mute" || cmd === "unmute" || cmd === "unban" || cmd === "banip" || cmd === "unbanip") {
        if (u.role !== "admin") {
          ws.send(JSON.stringify({ type: "system", text: "No autorizado." }));
          return;
        }
        const target = args;
        if (!target) {
          ws.send(JSON.stringify({ type: "system", text: `Uso: /${cmd} nick|ip` }));
          return;
        }

        if (cmd === "ban") {
          if (!bans.nicks.includes(target)) {
            bans.nicks.push(target);
            saveBans();
            logModeration("ban", u.nick, target, ip);
          }
        }
        if (cmd === "unban") {
          bans.nicks = bans.nicks.filter((b) => b !== target);
          saveBans();
          logModeration("unban", u.nick, target, ip);
        }
        if (cmd === "banip") {
          if (!bans.ips.includes(target)) {
            bans.ips.push(target);
            saveBans();
            logModeration("banip", u.nick, target, ip);
          }
        }
        if (cmd === "unbanip") {
          bans.ips = bans.ips.filter((b) => b !== target);
          saveBans();
          logModeration("unbanip", u.nick, target, ip);
        }
        if (cmd === "mute") muted.add(target);
        if (cmd === "unmute") muted.delete(target);

        for (const client of wss.clients) {
          if (client.readyState !== WebSocket.OPEN) continue;
          const tu = users.get(client.__id);
          if (tu && (tu.nick === target || tu.ip === target)) {
            if (cmd === "kick" || cmd === "ban" || cmd === "banip") {
              client.send(JSON.stringify({ type: "system", text: "Has sido expulsado." }));
              client.close();
            } else {
              client.send(JSON.stringify({ type: "system", text: "Actualización de moderación aplicada." }));
            }
          }
        }

        systemMessage(u.room, `Moderación: ${cmd} a ${target}.`);
        updatePresence(u.room);
        updateRooms();
        return;
      }

      ws.send(JSON.stringify({ type: "system", text: "Comando no reconocido." }));
      return;
    }

    if (payload.type === "reaction") {
      const messageId = String(payload.messageId || "");
      const emoji = String(payload.emoji || "");
      const list = roomHistory(u.room);
      const msg = list.find((m) => m.id === messageId);
      if (!msg || !emoji) return;
      msg.reactions[emoji] = msg.reactions[emoji] || [];
      if (!msg.reactions[emoji].includes(u.nick)) {
        msg.reactions[emoji].push(u.nick);
      }
      saveRooms();
      broadcastToRoom(u.room, { type: "reaction", messageId, emoji, users: msg.reactions[emoji] });
      return;
    }

    if (payload.type === "setStatus") {
      const status = String(payload.status || "").trim();
      const country = String(payload.country || "").trim();
      const state = String(payload.state || "").trim();
      const city = String(payload.city || "").trim();
      if (!status) return;
      u.status = status.slice(0, 40);
      if (accounts[u.nick]) {
        accounts[u.nick].status = u.status;
        saveUsers();
      }
      systemMessage(u.room, `${u.nick} cambió estado a: ${u.status}`);
      updatePresence(u.room);
      return;
    }
  });

  ws.on("close", () => {
    const u = users.get(id);
    if (!u) return;
    users.delete(id);
    if (u.authenticated) {
      roomUsers.get(u.room)?.delete(u.id);
      systemMessage(u.room, `${u.nick} salió del canal.`);
      updatePresence(u.room);
      updateRooms();
    }
  });
});

server.listen(PORT, () => {
  const proto = sslKey && sslCert ? "https" : "http";
  console.log(`Chat listo en ${proto}://localhost:${PORT}`);
});
