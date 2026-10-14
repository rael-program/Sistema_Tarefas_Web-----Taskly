// ============================================
// 1. IMPORTAÇÕES
// ============================================
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
require("dotenv").config();

// ============================================
// 2. CONFIGURAÇÕES
// ============================================
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "segredo-padrao";

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ============================================
// 3. BANCO DE DADOS (SQLite)
// ============================================
const db = new Database("taskly.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// --- Tabela de usuários ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    UNIQUE NOT NULL,
    password_hash       TEXT    NOT NULL,
    reset_token         TEXT,
    reset_token_expires TEXT,
    created_at          TEXT    DEFAULT (datetime('now'))
  );
`);

// Migração da tabela users
const cols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!cols.includes("reset_token")) db.exec("ALTER TABLE users ADD COLUMN reset_token TEXT");
if (!cols.includes("reset_token_expires")) db.exec("ALTER TABLE users ADD COLUMN reset_token_expires TEXT");

// --- Tabela de tarefas ---
db.exec(`
  CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    name        TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    priority    TEXT    NOT NULL,
    start_date  TEXT    NOT NULL,
    end_date    TEXT    NOT NULL,
    color       TEXT    NOT NULL,
    time        TEXT    DEFAULT '09:00',
    created_at  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Índice para acelerar buscas por usuário
db.exec(`CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user_id);`);

console.log("✅ Banco de dados pronto.");

// ============================================
// 4. FUNÇÕES AUXILIARES
// ============================================
function gerarToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    SECRET,
    { expiresIn: "1d" }
  );
}

function autenticar(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token não fornecido." });
  }
  try {
    const payload = jwt.verify(header.split(" ")[1], SECRET);
    req.user = { id: payload.id, username: payload.username };
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado." });
  }
}

// Converte linha do banco para o formato que o front espera
function taskToJson(row) {
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    priority: row.priority,
    start: row.start_date,
    end: row.end_date,
    color: row.color,
    time: row.time,
  };
}

// ============================================
// 5. ROTAS DE AUTENTICAÇÃO
// ============================================

app.get("/", (req, res) => {
  res.json({ ok: true, mensagem: "API Taskly funcionando!" });
});

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Usuário e senha são obrigatórios." });
  if (username.length < 3) return res.status(400).json({ error: "Usuário deve ter ao menos 3 caracteres." });
  if (password.length < 6) return res.status(400).json({ error: "Senha deve ter ao menos 6 caracteres." });

  const existe = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (existe) return res.status(409).json({ error: "Usuário já existe." });

  const passwordHash = await bcrypt.hash(password, 10);
  const info = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, passwordHash);

  const user = { id: info.lastInsertRowid, username };
  const token = gerarToken(user);
  res.status(201).json({ token, user });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Usuário e senha são obrigatórios." });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) return res.status(401).json({ error: "Usuário ou senha inválidos." });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Usuário ou senha inválidos." });

  const token = gerarToken(user);
  res.json({ token, user: { id: user.id, username: user.username } });
});

app.post("/api/forgot-password", (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: "Informe o nome de usuário." });

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    return res.json({ message: "Se o usuário existir, um token de redefinição foi gerado." });
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  db.prepare("UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?").run(token, expires, user.id);

  console.log("\n============================================");
  console.log("🔑  RESET DE SENHA SOLICITADO");
  console.log(`    Usuário: ${user.username}`);
  console.log(`    Token:   ${token}`);
  console.log(`    Expira em 15 minutos.`);
  console.log("============================================\n");

  res.json({
    message: "Token gerado. Verifique o console do servidor (ambiente de desenvolvimento).",
    token,
  });
});

app.post("/api/reset-password", async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: "Token e nova senha são obrigatórios." });
  if (newPassword.length < 6) return res.status(400).json({ error: "Nova senha deve ter ao menos 6 caracteres." });

  const user = db.prepare("SELECT * FROM users WHERE reset_token = ?").get(token);
  if (!user) return res.status(400).json({ error: "Token inválido." });
  if (!user.reset_token_expires || new Date(user.reset_token_expires) < new Date()) {
    return res.status(400).json({ error: "Token expirado. Solicite um novo." });
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);
  db.prepare(`UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?`)
    .run(passwordHash, user.id);

  res.json({ message: "Senha redefinida com sucesso. Faça login novamente." });
});

app.post("/api/change-password", autenticar, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "Senha atual e nova senha são obrigatórias." });
  if (newPassword.length < 6) return res.status(400).json({ error: "Nova senha deve ter ao menos 6 caracteres." });
  if (currentPassword === newPassword) return res.status(400).json({ error: "A nova senha deve ser diferente da atual." });

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  if (!user) return res.status(404).json({ error: "Usuário não encontrado." });

  const ok = await bcrypt.compare(currentPassword, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Senha atual incorreta." });

  const passwordHash = await bcrypt.hash(newPassword, 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(passwordHash, user.id);

  res.json({ message: "Senha alterada com sucesso." });
});

app.get("/api/me", autenticar, (req, res) => {
  res.json({ user: req.user });
});

// ============================================
// 6. CRUD DE TAREFAS (todas exigem login)
// ============================================

// --- LISTAR tarefas do usuário logado ---
app.get("/api/tasks", autenticar, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM tasks WHERE user_id = ? ORDER BY start_date ASC, id ASC")
    .all(req.user.id);
  res.json(rows.map(taskToJson));
});

// --- CRIAR tarefa ---
app.post("/api/tasks", autenticar, (req, res) => {
  const { name, type, priority, start, end, color, time } = req.body || {};

  if (!name || !type || !priority || !start || !end) {
    return res.status(400).json({ error: "Preencha todos os campos obrigatórios." });
  }
  if (end < start) {
    return res.status(400).json({ error: "A data de término deve ser posterior à data de início." });
  }

  const info = db.prepare(`
    INSERT INTO tasks (user_id, name, type, priority, start_date, end_date, color, time)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    req.user.id,
    String(name).trim(),
    type,
    priority,
    start,
    end,
    color || "#6c63dc",
    time || "09:00"
  );

  const row = db.prepare("SELECT * FROM tasks WHERE id = ?").get(info.lastInsertRowid);
  res.status(201).json(taskToJson(row));
});

// --- ATUALIZAR tarefa ---
app.put("/api/tasks/:id", autenticar, (req, res) => {
  const id = Number(req.params.id);
  const { name, type, priority, start, end, color, time } = req.body || {};

  const tarefa = db.prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ?").get(id, req.user.id);
  if (!tarefa) return res.status(404).json({ error: "Tarefa não encontrada." });

  if (!name || !type || !priority || !start || !end) {
    return res.status(400).json({ error: "Preencha todos os campos obrigatórios." });
  }
  if (end < start) {
    return res.status(400).json({ error: "A data de término deve ser posterior à data de início." });
  }

  db.prepare(`
    UPDATE tasks
       SET name = ?, type = ?, priority = ?, start_date = ?, end_date = ?, color = ?, time = ?
     WHERE id = ? AND user_id = ?
  `).run(
    String(name).trim(),
    type,
    priority,
    start,
    end,
    color || tarefa.color,
    time || tarefa.time || "09:00",
    id,
    req.user.id
  );

  const row = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  res.json(taskToJson(row));
});

// --- EXCLUIR tarefa ---
app.delete("/api/tasks/:id", autenticar, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare("DELETE FROM tasks WHERE id = ? AND user_id = ?").run(id, req.user.id);

  if (info.changes === 0) {
    return res.status(404).json({ error: "Tarefa não encontrada." });
  }
  res.json({ ok: true });
});

// ============================================
// 7. INICIA O SERVIDOR
// ============================================
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});