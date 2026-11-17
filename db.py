# -*- coding: utf-8 -*-
"""SQLite 数据库模块 - 用户、API key、分析任务、告警"""
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime

import config

DB_PATH = config.DB_PATH


def hash_password(pw: str, salt: str = None) -> str:
    """PBKDF2 加盐哈希，返回 'salt$hash'。salt 省略时随机生成。"""
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
        return hmac.compare_digest(hash_password(pw, salt), stored)
    except (ValueError, AttributeError):
        return False


def _keystream(nonce: str, length: int) -> bytes:
    mask = hashlib.sha256((config.SECRET_KEY + nonce).encode()).digest()
    return (mask * (length // len(mask) + 1))[:length]


def seal_api_key(key: str) -> str:
    """用配置密钥派生的字节流对 API key 做 XOR 封装，避免明文落库。
    注意：这是可逆的轻量混淆，不是硬件级加密；生产环境应改用 KMS。"""
    if not key:
        return ""
    nonce = secrets.token_hex(8)
    raw = key.encode()
    sealed = bytes(a ^ b for a, b in zip(raw, _keystream(nonce, len(raw))))
    return "enc$" + nonce + "$" + sealed.hex()


def unseal_api_key(value: str) -> str:
    if not value:
        return ""
    if not value.startswith("enc$"):
        return value  # 兼容历史明文数据
    try:
        _, nonce, payload = value.split("$", 2)
        raw = bytes.fromhex(payload)
        return bytes(a ^ b for a, b in zip(raw, _keystream(nonce, len(raw)))).decode()
    except (ValueError, UnicodeDecodeError):
        return ""


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        deepseek_key TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT,
        status TEXT DEFAULT 'pending',
        total INTEGER DEFAULT 0,
        analyzed INTEGER DEFAULT 0,
        attack_count INTEGER DEFAULT 0,
        fp_count INTEGER DEFAULT 0,
        error TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now','localtime')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        host TEXT, rule_id TEXT, path_template TEXT,
        method TEXT, payload TEXT, src_ip TEXT, event_time TEXT,
        verdict TEXT DEFAULT '', risk_level TEXT DEFAULT '',
        llm_reason TEXT DEFAULT '',
        FOREIGN KEY (task_id) REFERENCES tasks(id)
    )""")
    conn.commit()
    conn.close()


def create_user(username: str, password: str) -> int:
    conn = get_db()
    try:
        c = conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                         (username, hash_password(password)))
        conn.commit()
        return c.lastrowid
    except sqlite3.IntegrityError:
        return -1
    finally:
        conn.close()


def verify_user(username: str, password: str) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if row and verify_password(password, row["password_hash"]):
        return dict(row)
    return None


def get_user(uid: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def save_api_key(uid: int, key: str):
    conn = get_db()
    conn.execute("UPDATE users SET deepseek_key=? WHERE id=?", (seal_api_key(key.strip()), uid))
    conn.commit()
    conn.close()

def load_api_key(uid: int) -> str:
    conn = get_db()
    row = conn.execute("SELECT deepseek_key FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return unseal_api_key(row["deepseek_key"]) if row else ""


def create_task(uid: int, filename: str, total: int) -> int:
    conn = get_db()
    c = conn.execute("INSERT INTO tasks (user_id, filename, total) VALUES (?, ?, ?)",
                     (uid, filename, total))
    conn.commit()
    tid = c.lastrowid
    conn.close()
    return tid


def update_task(tid: int, **kw):
    conn = get_db()
    sets = ", ".join(f"{k}=?" for k in kw)
    vals = list(kw.values()) + [tid]
    conn.execute(f"UPDATE tasks SET {sets} WHERE id=?", vals)
    conn.commit()
    conn.close()


def get_task(tid: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_tasks(uid: int) -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM tasks WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def insert_alerts(task_id: int, alerts: list):
    conn = get_db()
    for a in alerts:
        conn.execute("""INSERT INTO alerts (task_id, host, rule_id, path_template, method, payload, src_ip, event_time)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (task_id, a.get("host",""), a.get("rule_id",""), a.get("path_template",""),
                      a.get("method",""), a.get("payload",""), a.get("src_ip",""), a.get("event_time","")))
    conn.commit()
    conn.close()


def update_alert(alert_db_id: int, verdict: str, risk: str, reason: str):
    conn = get_db()
    conn.execute("UPDATE alerts SET verdict=?, risk_level=?, llm_reason=? WHERE id=?",
                 (verdict, risk, reason, alert_db_id))
    conn.commit()
    conn.close()


def list_alerts(task_id: int) -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM alerts WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def batch_update_alerts(task_id: int, verdicts: list):
    """按插入顺序批量更新告警结论。verdicts 是和 alerts 列表一一对应的 verdict/risk/reason 三元组列表"""
    conn = get_db()
    rows = conn.execute("SELECT id FROM alerts WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
    for row, v in zip(rows, verdicts):
        conn.execute("UPDATE alerts SET verdict=?, risk_level=?, llm_reason=? WHERE id=?",
                     (v["verdict"], v["risk_level"], v["reason"], row["id"]))
    conn.commit()
    conn.close()


def list_pending_review(uid: int, limit: int = 50) -> list:
    """待人工复核：属于当前用户、判定为真实告警但置信度不高(medium/low)的告警。"""
    conn = get_db()
    rows = conn.execute("""SELECT a.* FROM alerts a JOIN tasks t ON a.task_id=t.id
                           WHERE t.user_id=? AND a.verdict='真实告警'
                             AND a.risk_level IN ('medium','low') AND a.llm_reason NOT LIKE '人工确认%'
                           ORDER BY a.id DESC LIMIT ?""", (uid, limit)).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["alert_id"] = d["id"]  # 模板用 alert_id
        out.append(d)
    return out


def mark_reviewed(alert_db_id: int, verdict: str):
    conn = get_db()
    conn.execute("UPDATE alerts SET verdict=?, llm_reason=? WHERE id=?",
                 (verdict, f"人工确认: {verdict}", alert_db_id))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("DB initialized at", DB_PATH)
