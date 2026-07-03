const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const archiver = require("archiver");
const sqlite3 = require("sqlite3").verbose();
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";

const BASE_DIR = __dirname;
const UPLOAD_DIR = path.join(BASE_DIR, "uploads");
const FILE_DIR = path.join(UPLOAD_DIR, "files");
const FOLDER_DIR = path.join(UPLOAD_DIR, "folders");
const TMP_DIR = path.join(UPLOAD_DIR, "tmp");
const BACKUP_DIR = path.join(BASE_DIR, "backups");
for (const dir of [UPLOAD_DIR, FILE_DIR, FOLDER_DIR, TMP_DIR, BACKUP_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

const db = new sqlite3.Database(path.join(BASE_DIR, "chat.db"));
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows || []));
  });
}
function q(x){ return sanitizeRoom(x); }

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    name TEXT PRIMARY KEY,
    password_hash TEXT,
    visibility TEXT DEFAULT 'public',
    approval_mode INTEGER DEFAULT 0,
    created_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS room_members (
    room_name TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'member',
    approved INTEGER DEFAULT 1,
    invited_by INTEGER,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (room_name, user_id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS room_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_name TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room TEXT NOT NULL,
    sender_id INTEGER NOT NULL,
    sender_name TEXT NOT NULL,
    recipient_id INTEGER,
    recipient_name TEXT,
    message TEXT,
    attachments_json TEXT,
    reply_to_id INTEGER,
    reply_preview_json TEXT,
    is_pinned INTEGER DEFAULT 0,
    edited_at DATETIME,
    deleted_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`INSERT OR IGNORE INTO rooms(name, password_hash, visibility, approval_mode, created_by) VALUES ('lobby', NULL, 'public', 0, 1)`);
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(path.join(BASE_DIR, "public")));

const tempStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, TMP_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").slice(0, 20);
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`);
  }
});
const upload = multer({ storage: tempStorage, limits: { fileSize: 500 * 1024 * 1024 } });

function sanitizeName(input, fallback = "Ẩn danh") {
  const name = String(input || "").trim().replace(/\s+/g, " ");
  return (name || fallback).slice(0, 24);
}
function sanitizeRoom(input) {
  const raw = String(input || "").trim().toLowerCase().replace(/\s+/g, "-");
  const cleaned = raw.replace(/[^a-z0-9_\-\u00C0-\u024F\u1E00-\u1EFF]/gi, "");
  return cleaned.slice(0, 24) || "lobby";
}
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
}
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Missing token" });
    req.user = verifyToken(token);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}
function safeRel(p) {
  const norm = path.posix.normalize(String(p || "").replace(/\\/g, "/")).replace(/^(\.\.(\/|\\|$))+/, "");
  return norm.startsWith("/") ? norm.slice(1) : norm;
}
function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}
function snippet(text, len = 90) {
  const s = String(text || "").replace(/\s+/g, " ").trim();
  return s.length > len ? s.slice(0, len - 1) + "…" : s;
}
function canMod(role) { return role === "leader" || role === "deputy"; }
function isOwner(role) { return role === "leader"; }
function privateRoomKey(a, b) { return [Number(a), Number(b)].sort((x, y) => x - y).join(":"); }

async function getUserById(id) {
  return dbGet("SELECT id, username FROM users WHERE id = ?", [Number(id)]);
}
async function getUserByName(username) {
  return dbGet("SELECT id, username FROM users WHERE username = ?", [sanitizeName(username, "")]);
}
async function getRoom(roomName) {
  return dbGet("SELECT name, password_hash, visibility, approval_mode, created_by FROM rooms WHERE name = ?", [sanitizeRoom(roomName)]);
}
async function getRoomsForUser(userId) {
  const rows = await dbAll(
    `SELECT r.name, r.password_hash, r.visibility, r.approval_mode, r.created_by,
            rm.role AS my_role, rm.approved AS my_approved,
            EXISTS(SELECT 1 FROM room_requests rr WHERE rr.room_name = r.name AND rr.user_id = ?) AS pending
     FROM rooms r
     LEFT JOIN room_members rm ON rm.room_name = r.name AND rm.user_id = ?
     ORDER BY r.created_at DESC`,
    [userId, userId]
  );
  return rows.filter(r => r.name === "lobby" || r.visibility !== "hidden" || r.my_role || r.pending)
             .map(r => ({
               name: r.name,
               hasPassword: !!r.password_hash,
               hidden: r.visibility === "hidden",
               approvalMode: !!r.approval_mode,
               created_by: r.created_by,
               myRole: r.my_role || null,
               pending: !!r.pending
             }));
}
function normalizeMessageRow(row) {
  let attachments = [];
  let replyPreview = null;
  try { attachments = row.attachments_json ? JSON.parse(row.attachments_json) : []; } catch {}
  try { replyPreview = row.reply_preview_json ? JSON.parse(row.reply_preview_json) : null; } catch {}
  return {
    id: row.id,
    room: row.room,
    sender_id: row.sender_id,
    sender_name: row.sender_name,
    recipient_id: row.recipient_id,
    recipient_name: row.recipient_name,
    message: row.deleted_at ? "" : (row.message || ""),
    attachments,
    reply_to_id: row.reply_to_id,
    reply_preview: replyPreview,
    is_pinned: !!row.is_pinned,
    edited_at: row.edited_at,
    deleted_at: row.deleted_at,
    created_at: row.created_at
  };
}
async function getRoomHistory(roomName) {
  const rows = await dbAll(
    `SELECT id, room, sender_id, sender_name, recipient_id, recipient_name, message, attachments_json, reply_to_id, reply_preview_json, is_pinned, edited_at, deleted_at, created_at
     FROM messages WHERE room = ? ORDER BY id DESC LIMIT 150`,
    [sanitizeRoom(roomName)]
  );
  return rows.reverse().map(normalizeMessageRow);
}
async function getPrivateHistory(userA, userB) {
  const room = `private:${privateRoomKey(userA, userB)}`;
  const rows = await dbAll(
    `SELECT id, room, sender_id, sender_name, recipient_id, recipient_name, message, attachments_json, reply_to_id, reply_preview_json, is_pinned, edited_at, deleted_at, created_at
     FROM messages WHERE room = ? ORDER BY id DESC LIMIT 150`,
    [room]
  );
  return rows.reverse().map(normalizeMessageRow);
}
async function getMessageById(id) {
  return dbGet(`SELECT id, room, sender_id, sender_name, recipient_id, recipient_name, message, attachments_json, reply_to_id, reply_preview_json, is_pinned, edited_at, deleted_at, created_at FROM messages WHERE id = ?`, [Number(id)]);
}
async function decorateMessage(row) {
  return row ? normalizeMessageRow(row) : null;
}
async function roomRoleFor(userId, roomName) {
  return dbGet(`SELECT role, approved FROM room_members WHERE room_name = ? AND user_id = ?`, [sanitizeRoom(roomName), Number(userId)]);
}
async function roomState(roomName, userId) {
  const room = sanitizeRoom(roomName);
  if (room === "lobby") {
    return {
      room: { name: "lobby", visibility: "public", hasPassword: false, approvalMode: false, created_by: 1 },
      myRole: null,
      members: [],
      pending: [],
      pinned: [],
      controls: { canInvite: false, canKick: false, canApprove: false, canPromote: false, canDelete: false, canTransfer: false, canRename: false, canToggleApproval: false, canChangePassword: false, canHide: false, canPin: false, canManageFiles: false }
    };
  }
  const r = await getRoom(room);
  if (!r) return null;
  const my = await roomRoleFor(userId, room);
  const members = await dbAll(
    `SELECT rm.user_id, rm.role, rm.approved, u.username
     FROM room_members rm JOIN users u ON u.id = rm.user_id
     WHERE rm.room_name = ? AND rm.approved = 1
     ORDER BY CASE rm.role WHEN 'leader' THEN 0 WHEN 'deputy' THEN 1 ELSE 2 END, u.username ASC`,
    [room]
  );
  const pending = await dbAll(
    `SELECT rr.user_id, rr.username, rr.created_at FROM room_requests rr WHERE rr.room_name = ? ORDER BY rr.created_at ASC`,
    [room]
  );
  const pinned = await dbAll(
    `SELECT id, sender_name, message, created_at FROM messages WHERE room = ? AND is_pinned = 1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 10`,
    [room]
  );
  const role = my ? my.role : null;
  return {
    room: { name: r.name, visibility: r.visibility, hasPassword: !!r.password_hash, approvalMode: !!r.approval_mode, created_by: r.created_by },
    myRole: role,
    members: members.map(m => ({ id: m.user_id, username: m.username, role: m.role, online: false })),
    pending: pending.map(p => ({ userId: p.user_id, username: p.username, created_at: p.created_at })),
    pinned: pinned.map(p => ({ id: p.id, sender_name: p.sender_name, message: snippet(p.message, 120), created_at: p.created_at })),
    controls: {
      canInvite: canMod(role),
      canKick: canMod(role),
      canApprove: canMod(role) && !!r.approval_mode,
      canPromote: role === "leader",
      canDelete: role === "leader",
      canTransfer: role === "leader",
      canRename: role === "leader",
      canToggleApproval: role === "leader",
      canChangePassword: role === "leader",
      canHide: role === "leader",
      canPin: canMod(role)
    }
  };
}
async function broadcastRoomState(roomName) {
  const room = sanitizeRoom(roomName);
  const ids = io.sockets.adapter.rooms.get(room);
  if (!ids) return;
  for (const sid of ids) {
    const s = io.sockets.sockets.get(sid);
    if (s && s.user) {
      const st = await roomState(room, s.user.id);
      if (st) s.emit("room-state", st);
    }
  }
}
async function emitRoomsListToUser(socket, userId) {
  socket.emit("rooms-list", await getRoomsForUser(userId));
}
async function emitRoomsListToAll() {
  for (const [sid, user] of onlineBySocket.entries()) {
    const s = io.sockets.sockets.get(sid);
    if (s) await emitRoomsListToUser(s, user.id);
  }
}
function logAction(action, payload = {}) {
  fs.appendFile(path.join(BASE_DIR, "admin.log"), `[${new Date().toISOString()}] ${action} ${JSON.stringify(payload)}\n`, () => {});
}
async function backupDbNow() {
  try {
    const name = `chat-${new Date().toISOString().replace(/[:.]/g, "-")}.db`;
    fs.copyFileSync(path.join(BASE_DIR, "chat.db"), path.join(BACKUP_DIR, name));
  } catch {}
}
function moveFileToFinal(file, targetDir) {
  ensureDir(targetDir);
  const safe = path.basename(file.originalname || "file").replace(/[^\w.\-() \u00C0-\u024F\u1E00-\u1EFF]/g, "_");
  const finalName = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}-${safe || "file"}`;
  const finalPath = path.join(targetDir, finalName);
  fs.copyFileSync(file.path, finalPath);
  try { fs.unlinkSync(file.path); } catch {}
  return { name: file.originalname, storedName: finalName, path: finalPath };
}
function attachmentFromFile(f, stored) {
  const stat = fs.statSync(stored.path);
  return { name: stored.name, url: `/uploads/files/${encodeURIComponent(stored.storedName)}`, mime: f.mimetype, size: stat.size, isImage: /^image\//.test(f.mimetype), kind: "file" };
}
function safeAttachments(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  try { return JSON.parse(val); } catch { return []; }
}
async function createZipFromFiles(files, baseName) {
  const zipName = `${sanitizeName(baseName, "folder")}-${Date.now()}.zip`;
  const finalPath = path.join(FOLDER_DIR, zipName);
  const output = fs.createWriteStream(finalPath);
  const archive = archiver("zip", { zlib: { level: 9 } });
  const done = new Promise((resolve, reject) => {
    output.on("close", resolve);
    output.on("error", reject);
    archive.on("error", reject);
  });
  archive.pipe(output);
  for (const file of files) {
    archive.file(file.tempPath, { name: safeRel(file.relativePath || file.originalname || "file") });
  }
  await archive.finalize();
  await done;
  const stat = fs.statSync(finalPath);
  for (const file of files) { try { fs.unlinkSync(file.tempPath); } catch {} }
  return { name: zipName, url: `/uploads/folders/${encodeURIComponent(zipName)}`, mime: "application/zip", size: stat.size, isImage: false, kind: "folder" };
}
function privateRoom(room, userId) {
  if (String(room).startsWith("private:")) {
    const part = String(room).split(":")[1] || "";
    if (part.includes(":")) return String(room);
    return `private:${privateRoomKey(userId, Number(part))}`;
  }
  return sanitizeRoom(room);
}

app.post("/api/register", async (req, res) => {
  try {
    const username = sanitizeName(req.body.username, "");
    const password = String(req.body.password || "");
    if (username.length < 3) return res.status(400).json({ error: "Tên phải có ít nhất 3 ký tự" });
    if (password.length < 6) return res.status(400).json({ error: "Mật khẩu phải có ít nhất 6 ký tự" });
    const exists = await getUserByName(username);
    if (exists) return res.status(409).json({ error: "Tên đăng nhập đã tồn tại" });
    const hash = await bcrypt.hash(password, 10);
    const ins = await dbRun("INSERT INTO users(username, password_hash) VALUES (?, ?)", [username, hash]);
    const user = { id: ins.lastID, username };
    res.json({ token: signToken(user), user });
  } catch {
    res.status(500).json({ error: "Không thể tạo tài khoản" });
  }
});
app.post("/api/login", async (req, res) => {
  try {
    const username = sanitizeName(req.body.username, "");
    const password = String(req.body.password || "");
    const user = await dbGet("SELECT id, username, password_hash FROM users WHERE username = ?", [username]);
    if (!user) return res.status(401).json({ error: "Sai tên đăng nhập hoặc mật khẩu" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Sai tên đăng nhập hoặc mật khẩu" });
    res.json({ token: signToken(user), user: { id: user.id, username: user.username } });
  } catch {
    res.status(500).json({ error: "Không thể đăng nhập" });
  }
});
app.post("/api/change-password", authMiddleware, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || "");
    const newPassword = String(req.body.newPassword || "");
    if (newPassword.length < 6) return res.status(400).json({ error: "Mật khẩu mới phải có ít nhất 6 ký tự" });
    const user = await dbGet("SELECT id, password_hash FROM users WHERE id = ?", [req.user.id]);
    if (!user) return res.status(404).json({ error: "Không tìm thấy tài khoản" });
    const ok = await bcrypt.compare(currentPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Sai mật khẩu hiện tại" });
    const hash = await bcrypt.hash(newPassword, 10);
    await dbRun("UPDATE users SET password_hash = ? WHERE id = ?", [hash, req.user.id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Không thể đổi mật khẩu" });
  }
});
app.get("/api/rooms", authMiddleware, async (req, res) => {
  try { res.json({ rooms: await getRoomsForUser(req.user.id) }); }
  catch { res.status(500).json({ error: "Không tải được danh sách phòng" }); }
});
app.get("/api/search", authMiddleware, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (!q) return res.json({ results: [] });
    const roomParam = String(req.query.room || "lobby");
    const room = roomParam.startsWith("private:") ? privateRoom(roomParam, req.user.id) : sanitizeRoom(roomParam);
    const like = `%${q}%`;
    const rows = await dbAll(
      `SELECT id, room, sender_id, sender_name, recipient_id, recipient_name, message, attachments_json, reply_to_id, reply_preview_json, is_pinned, edited_at, deleted_at, created_at
       FROM messages
       WHERE room = ? AND deleted_at IS NULL AND (message LIKE ? OR sender_name LIKE ?)
       ORDER BY created_at DESC LIMIT 50`,
      [room, like, like]
    );
    res.json({ results: rows.map(normalizeMessageRow) });
  } catch {
    res.status(500).json({ error: "Không tìm kiếm được" });
  }
});
app.post("/api/upload/file", authMiddleware, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Không có tệp nào" });
    const stored = moveFileToFinal(req.file, FILE_DIR);
    res.json({ attachment: attachmentFromFile(req.file, stored) });
  } catch {
    res.status(500).json({ error: "Không thể tải tệp lên" });
  }
});
app.post("/api/upload/files", authMiddleware, upload.array("files", 50), async (req, res) => {
  try {
    const files = req.files || [];
    if (!files.length) return res.status(400).json({ error: "Không có tệp nào" });
    const attachments = files.map(f => attachmentFromFile(f, moveFileToFinal(f, FILE_DIR)));
    res.json({ attachments });
  } catch {
    res.status(500).json({ error: "Không thể tải các tệp lên" });
  }
});
app.post("/api/upload/folder", authMiddleware, upload.array("files", 500), async (req, res) => {
  const tempPaths = [];
  try {
    const folderName = sanitizeName(req.body.folderName || "folder", "folder");
    const manifest = JSON.parse(req.body.manifest || "[]");
    const files = req.files || [];
    if (!files.length) return res.status(400).json({ error: "Không có file trong thư mục" });
    const batch = `${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;
    const staging = path.join(TMP_DIR, batch);
    ensureDir(staging);
    const zippedItems = files.map((f, idx) => {
      const meta = manifest[idx] || {};
      const rel = safeRel(meta.relativePath || f.originalname || `file-${idx + 1}`);
      const dest = path.join(staging, rel);
      ensureDir(path.dirname(dest));
      fs.copyFileSync(f.path, dest);
      tempPaths.push(f.path);
      return { tempPath: dest, relativePath: rel, originalname: f.originalname };
    });
    const attachment = await createZipFromFiles(zippedItems, folderName);
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch {}
    res.json({ attachment });
  } catch {
    for (const p of tempPaths) { try { fs.unlinkSync(p); } catch {} }
    res.status(500).json({ error: "Không thể tải thư mục lên" });
  }
});
app.get("/health", (_req, res) => res.json({ ok: true }));

const onlineBySocket = new Map();
const socketByUserId = new Map();

function emitOnlineUsers() {
  const users = Array.from(onlineBySocket.values());
  for (const [sid] of onlineBySocket.entries()) {
    const sock = io.sockets.sockets.get(sid);
    if (sock) sock.emit("online-users", users);
  }
}

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next(new Error("unauthorized"));
    socket.user = verifyToken(token);
    next();
  } catch {
    next(new Error("unauthorized"));
  }
});

async function approvePending(roomName, userId, byId) {
  await dbRun(`DELETE FROM room_requests WHERE room_name = ? AND user_id = ?`, [sanitizeRoom(roomName), Number(userId)]);
  await dbRun(`INSERT OR REPLACE INTO room_members(room_name, user_id, role, approved, invited_by) VALUES (?, ?, 'member', 1, ?)`, [sanitizeRoom(roomName), Number(userId), Number(byId)]);
}
async function rejectPending(roomName, userId) {
  await dbRun(`DELETE FROM room_requests WHERE room_name = ? AND user_id = ?`, [sanitizeRoom(roomName), Number(userId)]);
}
async function transferOwner(roomName, fromId, toId) {
  const room = sanitizeRoom(roomName);
  await dbRun(`UPDATE room_members SET role = 'deputy' WHERE room_name = ? AND user_id = ?`, [room, Number(fromId)]);
  await dbRun(`UPDATE room_members SET role = 'leader' WHERE room_name = ? AND user_id = ?`, [room, Number(toId)]);
}
async function setDeputy(roomName, userId, enabled) {
  await dbRun(`UPDATE room_members SET role = ? WHERE room_name = ? AND user_id = ?`, [enabled ? "deputy" : "member", sanitizeRoom(roomName), Number(userId)]);
}
async function setRoomPassword(room, password = "") {
  const hash = String(password || "").trim() ? await bcrypt.hash(String(password).trim(), 10) : null;
  await dbRun(`UPDATE rooms SET password_hash = ? WHERE name = ?`, [hash, sanitizeRoom(room)]);
}
async function setRoomVisibility(room, hidden) {
  await dbRun(`UPDATE rooms SET visibility = ? WHERE name = ?`, [hidden ? "hidden" : "public", sanitizeRoom(room)]);
}
async function setRoomApproval(room, enabled) {
  await dbRun(`UPDATE rooms SET approval_mode = ? WHERE name = ?`, [enabled ? 1 : 0, sanitizeRoom(room)]);
}
async function createRoom(roomName, creatorId, password, hidden, approvalMode) {
  const room = sanitizeRoom(roomName);
  const hash = String(password || "").trim() ? await bcrypt.hash(String(password).trim(), 10) : null;
  await dbRun(`INSERT INTO rooms(name, password_hash, visibility, approval_mode, created_by) VALUES (?, ?, ?, ?, ?)`, [room, hash, hidden ? "hidden" : "public", approvalMode ? 1 : 0, creatorId]);
  await dbRun(`INSERT OR REPLACE INTO room_members(room_name, user_id, role, approved, invited_by) VALUES (?, ?, 'leader', 1, NULL)`, [room, creatorId]);
}

io.on("connection", async (socket) => {
  onlineBySocket.set(socket.id, socket.user);
  socketByUserId.set(String(socket.user.id), socket.id);

  socket.emit("auth-success", { user: socket.user });
  emitOnlineUsers();
  socket.join("lobby");
  socket.data.currentRoom = "lobby";
  socket.data.replyTarget = null;
  socket.data.editTarget = null;
  await emitRoomsListToUser(socket, socket.user.id);
  socket.emit("room-switched", { room: "lobby" });
  socket.emit("room-history", { room: "lobby", messages: await getRoomHistory("lobby") });
  socket.emit("room-state", await roomState("lobby", socket.user.id));

  socket.on("create-room", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || "");
      if (!room) return socket.emit("room-error", "Tên phòng không hợp lệ");
      if (await getRoom(room)) return socket.emit("room-error", "Phòng đã tồn tại");
      await createRoom(room, socket.user.id, data.password || "", !!data.hidden, !!data.approvalMode);
      logAction("create_room", { room, by: socket.user.id });
      socket.join(room);
      socket.data.currentRoom = room;
      socket.emit("room-created", { room });
      socket.emit("room-switched", { room });
      socket.emit("room-history", { room, messages: await getRoomHistory(room) });
      socket.emit("room-state", await roomState(room, socket.user.id));
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không tạo được phòng");
    }
  });

  socket.on("join-room", async (data = {}) => {
    try {
      const roomName = sanitizeRoom(data.room || "lobby");
      const password = String(data.password || "");
      const room = await getRoom(roomName);
      if (!room) return socket.emit("room-error", "Phòng không tồn tại");
      if (room.password_hash) {
        if (!password) return socket.emit("room-error", "Phòng này cần mật khẩu");
        if (!await bcrypt.compare(password, room.password_hash)) return socket.emit("room-error", "Sai mật khẩu phòng");
      }
      const member = await roomRoleFor(socket.user.id, roomName);
      if (room.approval_mode && !(member && member.approved)) {
        await dbRun(`INSERT OR IGNORE INTO room_requests(room_name, user_id, username) VALUES (?, ?, ?)`, [roomName, socket.user.id, socket.user.username]);
        socket.emit("room-pending", { room: roomName, message: "Đã gửi yêu cầu tham gia. Chờ duyệt." });
        socket.emit("room-state", await roomState(roomName, socket.user.id));
        await broadcastRoomState(roomName);
        return;
      }
      await dbRun(`INSERT OR REPLACE INTO room_members(room_name, user_id, role, approved, invited_by) VALUES (?, ?, ?, 1, NULL)`, [roomName, socket.user.id, member ? member.role : "member"]);
      const prev = socket.data.currentRoom;
      if (prev && prev !== roomName) {
        socket.leave(prev);
        await broadcastRoomState(prev);
      }
      socket.join(roomName);
      socket.data.currentRoom = roomName;
      socket.emit("room-switched", { room: roomName });
      socket.emit("room-history", { room: roomName, messages: await getRoomHistory(roomName) });
      socket.emit("room-state", await roomState(roomName, socket.user.id));
      await emitRoomsListToAll();
      await broadcastRoomState(roomName);
    } catch {
      socket.emit("room-error", "Không thể vào phòng");
    }
  });

  socket.on("leave-room", async (data = {}) => {
    const room = sanitizeRoom(data.room || socket.data.currentRoom || "lobby");
    if (room === "lobby") return;
    socket.leave(room);
    if (socket.data.currentRoom === room) {
      socket.data.currentRoom = "lobby";
      socket.join("lobby");
      socket.emit("room-switched", { room: "lobby" });
      socket.emit("room-history", { room: "lobby", messages: await getRoomHistory("lobby") });
      socket.emit("room-state", await roomState("lobby", socket.user.id));
    }
    await broadcastRoomState(room);
  });

  socket.on("rename-room", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const newName = sanitizeRoom(data.newName || "");
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canRename) return socket.emit("room-error", "Không có quyền đổi tên");
      if (!newName || newName === "lobby") return socket.emit("room-error", "Tên mới không hợp lệ");
      if (await getRoom(newName)) return socket.emit("room-error", "Tên phòng đã tồn tại");
      await dbRun(`UPDATE rooms SET name = ? WHERE name = ?`, [newName, room]);
      await dbRun(`UPDATE room_members SET room_name = ? WHERE room_name = ?`, [newName, room]);
      await dbRun(`UPDATE room_requests SET room_name = ? WHERE room_name = ?`, [newName, room]);
      await dbRun(`UPDATE messages SET room = ? WHERE room = ?`, [newName, room]);
      if (socket.data.currentRoom === room) {
        socket.leave(room);
        socket.join(newName);
        socket.data.currentRoom = newName;
      }
      logAction("rename_room", { room, newName, by: socket.user.id });
      await emitRoomsListToAll();
      socket.emit("room-switched", { room: newName });
      socket.emit("room-history", { room: newName, messages: await getRoomHistory(newName) });
      socket.emit("room-state", await roomState(newName, socket.user.id));
      await broadcastRoomState(newName);
    } catch {
      socket.emit("room-error", "Không thể đổi tên phòng");
    }
  });

  socket.on("set-room-password", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canChangePassword) return socket.emit("room-error", "Không có quyền đổi mật khẩu");
      await setRoomPassword(room, data.password || "");
      logAction("set_room_password", { room, by: socket.user.id });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể đổi mật khẩu");
    }
  });

  socket.on("toggle-room-hidden", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canHide) return socket.emit("room-error", "Không có quyền ẩn/hiện phòng");
      await setRoomVisibility(room, !!data.hidden);
      logAction("toggle_room_hidden", { room, hidden: !!data.hidden, by: socket.user.id });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể đổi trạng thái phòng");
    }
  });

  socket.on("toggle-approval", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canToggleApproval) return socket.emit("room-error", "Không có quyền đổi duyệt");
      const r = await getRoom(room);
      await setRoomApproval(room, !r.approval_mode);
      logAction("toggle_approval", { room, by: socket.user.id });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể đổi chế độ duyệt");
    }
  });

  socket.on("invite-member", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canInvite) return socket.emit("room-error", "Bạn không có quyền mời");
      const user = await getUserByName(data.username || "");
      if (!user) return socket.emit("room-error", "Không tìm thấy người dùng");
      await dbRun(`INSERT OR REPLACE INTO room_members(room_name, user_id, role, approved, invited_by) VALUES (?, ?, 'member', 1, ?)`, [room, user.id, socket.user.id]);
      await dbRun(`DELETE FROM room_requests WHERE room_name = ? AND user_id = ?`, [room, user.id]);
      const sid = socketByUserId.get(String(user.id));
      if (sid) {
        const s = io.sockets.sockets.get(sid);
        if (s) s.emit("room-invited", { room, by: socket.user.username });
      }
      logAction("invite_member", { room, by: socket.user.id, target: user.id });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể mời thành viên");
    }
  });

  socket.on("kick-member", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const targetId = Number(data.userId);
      if (!targetId || targetId === socket.user.id) return;
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canKick) return socket.emit("room-error", "Không có quyền kick");
      const target = await dbGet(`SELECT role FROM room_members WHERE room_name = ? AND user_id = ?`, [room, targetId]);
      if (!target) return socket.emit("room-error", "Người này không ở trong phòng");
      if (isOwner(target.role)) return socket.emit("room-error", "Không thể kick trưởng nhóm");
      if (st.myRole === "deputy" && target.role !== "member") return socket.emit("room-error", "Phó nhóm chỉ kick được thành viên thường");
      await dbRun(`DELETE FROM room_members WHERE room_name = ? AND user_id = ?`, [room, targetId]);
      await dbRun(`DELETE FROM room_requests WHERE room_name = ? AND user_id = ?`, [room, targetId]);
      const sid = socketByUserId.get(String(targetId));
      if (sid) {
        const s = io.sockets.sockets.get(sid);
        if (s) {
          s.leave(room);
          s.emit("room-kicked", { room, by: socket.user.username });
          if (s.data.currentRoom === room) {
            s.data.currentRoom = "lobby";
            s.join("lobby");
            s.emit("room-switched", { room: "lobby" });
            s.emit("room-history", { room: "lobby", messages: await getRoomHistory("lobby") });
            s.emit("room-state", await roomState("lobby", s.user.id));
          }
        }
      }
      logAction("kick_member", { room, by: socket.user.id, target: targetId });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể kick");
    }
  });

  socket.on("set-deputy", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const targetId = Number(data.userId);
      const enabled = !!data.enabled;
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canPromote) return socket.emit("room-error", "Không có quyền chỉ định phó");
      const target = await dbGet(`SELECT role FROM room_members WHERE room_name = ? AND user_id = ?`, [room, targetId]);
      if (!target) return socket.emit("room-error", "Không tìm thấy thành viên");
      if (isOwner(target.role)) return socket.emit("room-error", "Không thể đổi trưởng nhóm");
      await setDeputy(room, targetId, enabled);
      logAction("set_deputy", { room, by: socket.user.id, target: targetId, enabled });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể cập nhật vai trò");
    }
  });

  socket.on("remove-deputy", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const targetId = Number(data.userId);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canPromote) return socket.emit("room-error", "Không có quyền thu hồi phó nhóm");
      const target = await dbGet(`SELECT role FROM room_members WHERE room_name = ? AND user_id = ?`, [room, targetId]);
      if (!target) return socket.emit("room-error", "Không tìm thấy thành viên");
      if (isOwner(target.role)) return socket.emit("room-error", "Không thể đổi trưởng nhóm");
      await setDeputy(room, targetId, false);
      logAction("remove_deputy", { room, by: socket.user.id, target: targetId });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể thu hồi quyền phó");
    }
  });

  socket.on("transfer-owner", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const targetId = Number(data.userId);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canTransfer) return socket.emit("room-error", "Không có quyền chuyển trưởng nhóm");
      if (targetId === socket.user.id) return socket.emit("room-error", "Chọn người khác");
      const target = await dbGet(`SELECT role FROM room_members WHERE room_name = ? AND user_id = ?`, [room, targetId]);
      if (!target) return socket.emit("room-error", "Không tìm thấy thành viên");
      await transferOwner(room, socket.user.id, targetId);
      logAction("transfer_owner", { room, by: socket.user.id, target: targetId });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể chuyển quyền");
    }
  });

  socket.on("approve-member", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const targetId = Number(data.userId);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canApprove) return socket.emit("room-error", "Không có quyền duyệt");
      await approvePending(room, targetId, socket.user.id);
      const sid = socketByUserId.get(String(targetId));
      if (sid) {
        const s = io.sockets.sockets.get(sid);
        if (s) {
          s.join(room);
          s.data.currentRoom = room;
          s.emit("room-approved", { room, by: socket.user.username });
          s.emit("room-switched", { room });
          s.emit("room-history", { room, messages: await getRoomHistory(room) });
          s.emit("room-state", await roomState(room, s.user.id));
        }
      }
      logAction("approve_member", { room, by: socket.user.id, target: targetId });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể duyệt");
    }
  });

  socket.on("reject-member", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      const targetId = Number(data.userId);
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canApprove) return socket.emit("room-error", "Không có quyền xử lý yêu cầu");
      await rejectPending(room, targetId);
      logAction("reject_member", { room, by: socket.user.id, target: targetId });
      await emitRoomsListToAll();
      await broadcastRoomState(room);
    } catch {
      socket.emit("room-error", "Không thể từ chối");
    }
  });

  socket.on("delete-room", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom);
      if (room === "lobby") return socket.emit("room-error", "Không thể xóa lobby");
      const st = await roomState(room, socket.user.id);
      if (!st || !st.controls.canDelete) return socket.emit("room-error", "Không có quyền xóa nhóm");
      const members = await dbAll(`SELECT user_id FROM room_members WHERE room_name = ?`, [room]);
      await dbRun(`DELETE FROM rooms WHERE name = ?`, [room]);
      await dbRun(`DELETE FROM room_members WHERE room_name = ?`, [room]);
      await dbRun(`DELETE FROM room_requests WHERE room_name = ?`, [room]);
      await dbRun(`DELETE FROM messages WHERE room = ?`, [room]);
      for (const m of members) {
        const sid = socketByUserId.get(String(m.user_id));
        if (sid) {
          const s = io.sockets.sockets.get(sid);
          if (s) {
            s.leave(room);
            s.emit("room-deleted", { room, by: socket.user.username });
            if (s.data.currentRoom === room) {
              s.data.currentRoom = "lobby";
              s.join("lobby");
              s.emit("room-switched", { room: "lobby" });
              s.emit("room-history", { room: "lobby", messages: await getRoomHistory("lobby") });
              s.emit("room-state", await roomState("lobby", s.user.id));
            }
          }
        }
      }
      logAction("delete_room", { room, by: socket.user.id });
      await emitRoomsListToAll();
    } catch {
      socket.emit("room-error", "Không thể xóa nhóm");
    }
  });

  socket.on("send-message", async (data = {}) => {
    try {
      const room = sanitizeRoom(data.room || socket.data.currentRoom || "lobby");
      const message = String(data.message || "").trim().slice(0, 4000);
      const attachments = safeAttachments(data.attachments);
      const replyToId = data.replyToId ? Number(data.replyToId) : null;
      if (!message && !attachments.length) return;
      let replyPreview = null;
      if (replyToId) {
        const orig = await getMessageById(replyToId);
        if (orig) replyPreview = { sender_name: orig.sender_name, message: snippet(orig.message || "[đính kèm]", 80) };
      }
      const ins = await dbRun(
        `INSERT INTO messages(room, sender_id, sender_name, recipient_id, recipient_name, message, attachments_json, reply_to_id, reply_preview_json, is_pinned)
         VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, 0)`,
        [room, socket.user.id, socket.user.username, message, attachments.length ? JSON.stringify(attachments) : null, replyToId, replyPreview ? JSON.stringify(replyPreview) : null]
      );
      const payload = await decorateMessage(await getMessageById(ins.lastID));
      io.to(room).emit("new-message", payload);
      logAction("send_message", { room, by: socket.user.id });
    } catch {}
  });

  socket.on("open-private", async (data = {}) => {
    try {
      const toUserId = Number(data.toUserId);
      if (!toUserId) return;
      const user = await getUserById(toUserId);
      if (!user) return;
      socket.emit("private-opened", { user });
      socket.emit("private-history", { toUserId, messages: await getPrivateHistory(socket.user.id, toUserId) });
    } catch {}
  });

  socket.on("open-private-by-name", async (data = {}) => {
    try {
      const username = sanitizeName(data.username || "", "");
      if (!username) return;
      const user = await getUserByName(username);
      if (!user) return socket.emit("room-error", "Không tìm thấy người dùng");
      socket.emit("private-opened", { user });
      socket.emit("private-history", { toUserId: user.id, messages: await getPrivateHistory(socket.user.id, user.id) });
    } catch {}
  });

  socket.on("send-private", async (data = {}) => {
    try {
      const toUserId = Number(data.toUserId);
      if (!toUserId) return;
      const recipient = await getUserById(toUserId);
      if (!recipient) return;
      const message = String(data.message || "").trim().slice(0, 4000);
      const attachments = safeAttachments(data.attachments);
      const replyToId = data.replyToId ? Number(data.replyToId) : null;
      if (!message && !attachments.length) return;
      let replyPreview = null;
      if (replyToId) {
        const orig = await getMessageById(replyToId);
        if (orig) replyPreview = { sender_name: orig.sender_name, message: snippet(orig.message || "[đính kèm]", 80) };
      }
      const room = `private:${privateRoomKey(socket.user.id, recipient.id)}`;
      const ins = await dbRun(
        `INSERT INTO messages(room, sender_id, sender_name, recipient_id, recipient_name, message, attachments_json, reply_to_id, reply_preview_json, is_pinned)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
        [room, socket.user.id, socket.user.username, recipient.id, recipient.username, message, attachments.length ? JSON.stringify(attachments) : null, replyToId, replyPreview ? JSON.stringify(replyPreview) : null]
      );
      const payload = await decorateMessage(await getMessageById(ins.lastID));
      socket.emit("private-message", payload);
      const sid = socketByUserId.get(String(recipient.id));
      if (sid) {
        const s = io.sockets.sockets.get(sid);
        if (s) s.emit("private-message", payload);
      }
    } catch {}
  });

  socket.on("edit-message", async (data = {}) => {
    try {
      const id = Number(data.messageId);
      const text = String(data.message || "").trim().slice(0, 4000);
      if (!id) return;
      const row = await getMessageById(id);
      if (!row || row.deleted_at) return;
      const room = row.room;
      const r = await roomRoleFor(socket.user.id, room);
      const allowed = row.sender_id === socket.user.id || (r && canMod(r.role));
      if (!allowed) return socket.emit("room-error", "Không có quyền sửa");
      await dbRun(`UPDATE messages SET message = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ?`, [text, id]);
      const updated = await decorateMessage(await getMessageById(id));
      if (room.startsWith("private:")) {
        const [a, b] = room.split(":")[1].split(":").map(Number);
        for (const uid of [a, b]) {
          const sid = socketByUserId.get(String(uid));
          if (sid) {
            const s = io.sockets.sockets.get(sid);
            if (s) s.emit("message-updated", updated);
          }
        }
      } else {
        io.to(room).emit("message-updated", updated);
      }
    } catch {}
  });

  socket.on("revoke-message", async (data = {}) => {
    try {
      const id = Number(data.messageId);
      if (!id) return;
      const row = await getMessageById(id);
      if (!row || row.deleted_at) return;
      const room = row.room;
      const r = await roomRoleFor(socket.user.id, room);
      const allowed = row.sender_id === socket.user.id || (r && canMod(r.role));
      if (!allowed) return socket.emit("room-error", "Không có quyền thu hồi");
      await dbRun(`UPDATE messages SET deleted_at = CURRENT_TIMESTAMP, message = '' WHERE id = ?`, [id]);
      const updated = await decorateMessage(await getMessageById(id));
      if (room.startsWith("private:")) {
        const [a, b] = room.split(":")[1].split(":").map(Number);
        for (const uid of [a, b]) {
          const sid = socketByUserId.get(String(uid));
          if (sid) {
            const s = io.sockets.sockets.get(sid);
            if (s) s.emit("message-updated", updated);
          }
        }
      } else {
        io.to(room).emit("message-updated", updated);
      }
    } catch {}
  });

  socket.on("pin-message", async (data = {}) => {
    try {
      const id = Number(data.messageId);
      const pin = !!data.pin;
      const row = await getMessageById(id);
      if (!row || row.deleted_at) return;
      const room = row.room;
      const r = await roomRoleFor(socket.user.id, room);
      if (!r || !canMod(r.role)) return socket.emit("room-error", "Không có quyền ghim");
      await dbRun(`UPDATE messages SET is_pinned = ? WHERE id = ?`, [pin ? 1 : 0, id]);
      const updated = await decorateMessage(await getMessageById(id));
      if (room.startsWith("private:")) {
        const [a, b] = room.split(":")[1].split(":").map(Number);
        for (const uid of [a, b]) {
          const sid = socketByUserId.get(String(uid));
          if (sid) {
            const s = io.sockets.sockets.get(sid);
            if (s) s.emit("message-updated", updated);
          }
        }
      } else {
        io.to(room).emit("message-updated", updated);
      }
      await broadcastRoomState(room);
    } catch {}
  });
  socket.on("remove-attachment", async (data = {}) => {
    try {
      const id = Number(data.messageId);
      const index = Number(data.index);
      if (!Number.isInteger(index) || index < 0) return;
      const row = await getMessageById(id);
      if (!row || row.deleted_at) return;
      const room = row.room;
      const r = await roomRoleFor(socket.user.id, room);
      const allowed = row.sender_id === socket.user.id || (r && canMod(r.role));
      if (!allowed) return socket.emit("room-error", "Không có quyền quản lý file");
      const attachments = parseAttachments(row.attachments_json);
      if (!attachments[index]) return socket.emit("room-error", "Không tìm thấy file");
      attachments.splice(index, 1);
      await dbRun(
        `UPDATE messages SET attachments_json = ? WHERE id = ?`,
        [attachments.length ? JSON.stringify(attachments) : null, id]
      );
      const updated = await decorateMessage(await getMessageById(id));
      if (room.startsWith("private:")) {
        const [a, b] = room.split(":")[1].split(":").map(Number);
        for (const uid of [a, b]) {
          const sid = socketByUserId.get(String(uid));
          if (sid) {
            const s = io.sockets.sockets.get(sid);
            if (s) s.emit("message-updated", updated);
          }
        }
      } else {
        io.to(room).emit("message-updated", updated);
      }
      await broadcastRoomState(room);
      logAction("remove_attachment", { messageId: id, index, by: socket.user.id });
    } catch {}
  });

  socket.on("typing", (data = {}) => {
    const payload = { fromUserId: socket.user.id, fromUsername: socket.user.username, room: sanitizeRoom(data.room || socket.data.currentRoom || "lobby"), toUserId: data.toUserId ? Number(data.toUserId) : null, isTyping: !!data.isTyping };
    if (payload.toUserId) {
      const sid = socketByUserId.get(String(payload.toUserId));
      if (sid) {
        const s = io.sockets.sockets.get(sid);
        if (s) s.emit("typing-private", payload);
      }
      socket.emit("typing-private", payload);
    } else {
      socket.to(payload.room).emit("typing-room", payload);
    }
  });

  socket.on("disconnect", async () => {
    onlineBySocket.delete(socket.id);
    socketByUserId.delete(String(socket.user.id));
    if (socket.data.currentRoom) await broadcastRoomState(socket.data.currentRoom);
    await emitRoomsListToAll();
  });
});

setInterval(backupDbNow, 24 * 60 * 60 * 1000);
backupDbNow();

server.listen(PORT, "0.0.0.0", () => console.log(`LAN Chat Full running at http://0.0.0.0:${PORT}`));
