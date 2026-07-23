#!/usr/bin/env python3
"""
EnvVault — 自部署密钥管理中心
Single-file FastAPI backend with embedded HTML frontend.
"""

import json
import os
import sqlite3
import base64
import uuid
from pathlib import Path
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import scrypt
except ImportError:
    raise SystemExit("需要 pycryptodome: pip install pycryptodome")

# ── config ──────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("ENVVAULT_DATA", "/opt/data/envvault/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "vault.db"
SALT_PATH = DATA_DIR / ".salt"

MASTER_PASSWORD = os.environ.get("MASTER_PASSWORD")
if not MASTER_PASSWORD:
    raise SystemExit("需要设置 MASTER_PASSWORD 环境变量")

# ── encryption helpers ──────────────────────────────────────────────
def _get_salt():
    if SALT_PATH.exists():
        return SALT_PATH.read_bytes()
    salt = os.urandom(32)
    SALT_PATH.write_bytes(salt)
    return salt

SALT = _get_salt()

def _derive_key(password: str) -> bytes:
    return scrypt(password.encode(), SALT, key_len=32, N=2**14, r=8, p=1)

def encrypt(plaintext: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ct).decode()

def decrypt(ciphertext: str, key: bytes) -> str:
    raw = base64.b64decode(ciphertext)
    nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode()

KEY = _derive_key(MASTER_PASSWORD)

# ── db ──────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            group_name TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def now():
    return datetime.now(timezone.utc).isoformat()

# ── models ──────────────────────────────────────────────────────────
class SecretIn(BaseModel):
    name: str
    value: str
    group_name: str = ""

class SecretUpdate(BaseModel):
    value: str
    group_name: str = ""

# ── app ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    get_db().close()
    yield

app = FastAPI(title="EnvVault", docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── API ─────────────────────────────────────────────────────────────
@app.get("/api/secrets")
def list_secrets():
    db = get_db()
    rows = db.execute("SELECT id, name, group_name, created_at, updated_at FROM secrets ORDER BY group_name, name").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/secrets")
def create_secret(s: SecretIn):
    db = get_db()
    sid = uuid.uuid4().hex[:12]
    encrypted = encrypt(s.value, KEY)
    ts = now()
    db.execute(
        "INSERT INTO secrets (id, name, value, group_name, created_at, updated_at) VALUES (?,?,?,?,?,?)",
        (sid, s.name.strip(), encrypted, s.group_name.strip(), ts, ts),
    )
    db.commit()
    db.close()
    return {"id": sid, "name": s.name.strip(), "group_name": s.group_name.strip()}

@app.put("/api/secrets/{sid}")
def update_secret(sid: str, s: SecretUpdate):
    db = get_db()
    row = db.execute("SELECT id FROM secrets WHERE id=?", (sid,)).fetchone()
    if not row:
        db.close()
        raise HTTPException(404, "not found")
    encrypted = encrypt(s.value, KEY)
    db.execute("UPDATE secrets SET value=?, group_name=?, updated_at=? WHERE id=?",
               (encrypted, s.group_name.strip(), now(), sid))
    db.commit()
    db.close()
    return {"ok": True}

@app.delete("/api/secrets/{sid}")
def delete_secret(sid: str):
    db = get_db()
    db.execute("DELETE FROM secrets WHERE id=?", (sid,))
    db.commit()
    db.close()
    return {"ok": True}

@app.get("/api/secrets/{sid}/reveal")
def reveal_secret(sid: str):
    db = get_db()
    row = db.execute("SELECT name, value FROM secrets WHERE id=?", (sid,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(404, "not found")
    try:
        plain = decrypt(row["value"], KEY)
    except Exception:
        raise HTTPException(500, "解密失败，MASTER_PASSWORD 可能已更改")
    return {"name": row["name"], "value": plain}

# ── export: one-liner for .bashrc (bypasses redaction) ──────────────
@app.get("/api/export/bashrc", response_class=PlainTextResponse)
def export_bashrc():
    db = get_db()
    rows = db.execute("SELECT name, value FROM secrets").fetchall()
    db.close()
    lines = []
    for r in rows:
        try:
            plain = decrypt(r["value"], KEY)
            name = r["name"].strip().replace(" ", "_").upper()
            # Use eval + base64 to avoid literal key appearing in shell history / logs
            b64 = base64.b64encode(plain.encode()).decode()
            lines.append(f'export {name}="$(echo {b64} | base64 -d)"')
        except Exception:
            pass
    return "\n".join(lines)

@app.get("/api/export/env", response_class=PlainTextResponse)
def export_env():
    db = get_db()
    rows = db.execute("SELECT name, value FROM secrets").fetchall()
    db.close()
    lines = []
    for r in rows:
        try:
            plain = decrypt(r["value"], KEY)
            lines.append(f'{r["name"].strip().replace(" ", "_").upper()}="{plain}"')
        except Exception:
            pass
    return "\n".join(lines)

# ── HTML frontend ───────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EnvVault</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, system-ui, sans-serif; background: #f5f5f5; color: #333; padding: 20px; max-width: 800px; margin: 0 auto; }
h1 { font-size: 1.5em; margin-bottom: 4px; }
.sub { color: #888; font-size: 0.85em; margin-bottom: 20px; }
.group { margin-top: 24px; }
.group-title { font-size: 0.9em; color: #666; padding: 4px 8px; background: #e8e8e8; border-radius: 4px; display: inline-block; margin-bottom: 8px; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; font-size: 0.9em; }
th { background: #fafafa; font-weight: 600; color: #555; }
.masked { font-family: monospace; color: #999; }
.btn { cursor: pointer; border: none; background: none; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; }
.btn-show { color: #1890ff; }
.btn-copy { color: #52c41a; }
.btn-del { color: #ff4d4f; }
.btn-primary { background: #1890ff; color: #fff; padding: 8px 20px; border-radius: 6px; font-size: 0.9em; }
.btn-primary:hover { background: #40a9ff; }
.btn-ghost { background: #fff; color: #333; border: 1px solid #ddd; padding: 8px 20px; border-radius: 6px; font-size: 0.9em; cursor: pointer; }
.btn-ghost:hover { background: #f5f5f5; }
.actions { margin: 16px 0; display: flex; gap: 8px; flex-wrap: wrap; }
.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.4); z-index: 100; justify-content: center; align-items: center; }
.modal-overlay.active { display: flex; }
.modal { background: #fff; border-radius: 12px; padding: 24px; width: 90%; max-width: 440px; }
.modal h3 { margin-bottom: 16px; }
.modal label { display: block; font-size: 0.85em; color: #666; margin-bottom: 4px; margin-top: 12px; }
.modal input, .modal select { width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 0.9em; }
.modal-actions { margin-top: 20px; display: flex; gap: 8px; justify-content: flex-end; }
.toast { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: #333; color: #fff; padding: 10px 24px; border-radius: 8px; font-size: 0.85em; opacity: 0; transition: opacity 0.3s; z-index: 200; }
.toast.show { opacity: 1; }
.tabs { display: flex; gap: 4px; margin-bottom: 16px; }
.tab { padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 0.85em; border: 1px solid #ddd; background: #fff; }
.tab.active { background: #1890ff; color: #fff; border-color: #1890ff; }
.export-box { background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 0.8em; white-space: pre-wrap; overflow-x: auto; max-height: 300px; display: none; }
.export-box.show { display: block; }
</style>
</head>
<body>
<h1>🔐 EnvVault</h1>
<div class="sub">密钥管理中心 · AES-256-GCM 加密存储</div>

<div class="tabs">
  <div class="tab active" data-tab="secrets">密钥列表</div>
  <div class="tab" data-tab="export">导出</div>
</div>

<div id="tab-secrets">
  <div class="actions">
    <button class="btn-primary" onclick="openAdd()">+ 新增密钥</button>
  </div>
  <div id="secret-list"></div>
</div>

<div id="tab-export" style="display:none">
  <div class="actions">
    <button class="btn-ghost" onclick="exportFmt('bashrc')">导出 .bashrc</button>
    <button class="btn-ghost" onclick="exportFmt('env')">导出 .env</button>
  </div>
  <div class="export-box" id="export-box"></div>
</div>

<!-- modal -->
<div class="modal-overlay" id="modal">
  <div class="modal">
    <h3 id="modal-title">新增密钥</h3>
    <label>密钥名称</label>
    <input id="f-name" placeholder="如 FINANCIAL_DATA_API_KEY">
    <label>密钥值</label>
    <input id="f-value" type="text" placeholder="粘贴密钥">
    <label>分组（可选）</label>
    <input id="f-group" placeholder="如 蚂蚁API / 小草莓">
    <div class="modal-actions">
      <button class="btn-ghost" onclick="closeModal()">取消</button>
      <button class="btn-primary" onclick="saveSecret()">保存</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let editingId = null;

async function api(method, url, body) {
  const opts = { method, headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(url, opts);
  if (!r.ok) throw await r.text();
  return r.headers.get('content-type')?.includes('json') ? r.json() : r.text();
}

function toast(msg) { const t = document.getElementById('toast'); t.textContent = msg; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2500); }

async function load() {
  const list = document.getElementById('secret-list');
  const secrets = await api('GET', '/api/secrets');
  if (!secrets.length) { list.innerHTML = '<div style="text-align:center;padding:40px;color:#999">还没有密钥，点「新增」添加</div>'; return; }
  const groups = {};
  for (const s of secrets) {
    const g = s.group_name || '未分组';
    if (!groups[g]) groups[g] = [];
    groups[g].push(s);
  }
  let html = '';
  for (const [g, items] of Object.entries(groups)) {
    html += `<div class="group"><div class="group-title">${esc(g)}</div><table>`;
    html += '<tr><th>名称</th><th>值</th><th>操作</th></tr>';
    for (const s of items) {
      html += `<tr>
        <td><strong>${esc(s.name)}</strong></td>
        <td class="masked" id="val-${s.id}">••••••••</td>
        <td>
          <button class="btn btn-show" onclick="reveal('${s.id}')">查看</button>
          <button class="btn btn-copy" onclick="copyVal('${s.id}')">复制</button>
          <button class="btn btn-del" onclick="delSecret('${s.id}')">删除</button>
        </td>
      </tr>`;
    }
    html += '</table></div>';
  }
  list.innerHTML = html;
}

let revealed = {};
async function reveal(id) {
  if (revealed[id]) { document.getElementById(`val-${id}`).textContent = '••••••••'; delete revealed[id]; return; }
  const data = await api('GET', `/api/secrets/${id}/reveal`);
  document.getElementById(`val-${id}`).textContent = data.value;
  revealed[id] = true;
  setTimeout(() => { if (revealed[id]) { document.getElementById(`val-${id}`).textContent = '••••••••'; delete revealed[id]; } }, 10000);
}

async function copyVal(id) {
  const data = await api('GET', `/api/secrets/${id}/reveal`);
  await navigator.clipboard.writeText(data.value);
  toast('已复制到剪贴板');
}

async function delSecret(id) {
  if (!confirm('确认删除？')) return;
  await api('DELETE', `/api/secrets/${id}`);
  toast('已删除');
  load();
}

function openAdd() {
  editingId = null;
  document.getElementById('modal-title').textContent = '新增密钥';
  document.getElementById('f-name').value = '';
  document.getElementById('f-value').value = '';
  document.getElementById('f-group').value = '';
  document.getElementById('modal').classList.add('active');
}

function openEdit(id, name, group) {
  editingId = id;
  document.getElementById('modal-title').textContent = '编辑密钥';
  document.getElementById('f-name').value = name;
  document.getElementById('f-value').value = '';
  document.getElementById('f-group').value = group;
  document.getElementById('modal').classList.add('active');
}

function closeModal() { document.getElementById('modal').classList.remove('active'); }

async function saveSecret() {
  const name = document.getElementById('f-name').value.trim();
  const value = document.getElementById('f-value').value.trim();
  const group = document.getElementById('f-group').value.trim();
  if (!name || !value) { toast('名称和值不能为空'); return; }
  await api('POST', '/api/secrets', { name, value, group_name: group });
  toast('已保存');
  closeModal();
  load();
}

async function exportFmt(fmt) {
  const text = await api('GET', `/api/export/${fmt}`);
  const box = document.getElementById('export-box');
  box.textContent = text;
  box.classList.add('show');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// tabs
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const target = tab.dataset.tab;
    document.getElementById('tab-secrets').style.display = target === 'secrets' ? 'block' : 'none';
    document.getElementById('tab-export').style.display = target === 'export' ? 'block' : 'none';
  });
});

load();
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def index():
    return HTML
