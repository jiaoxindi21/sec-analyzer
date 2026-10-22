# -*- coding: utf-8 -*-
"""SQLite 数据库模块 - 用户、API key、分析任务、告警"""
import sys, os
sys.path.insert(0, r'C:\Users\HP\Doubao\chats\2026-10-21\new-chat\.pylibs')
import sqlite3
import hashlib
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "secinsight.db")


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


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


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
    row = conn.execute("SELECT * FROM users WHERE username=? AND password_hash=?",
                       (username, hash_password(password))).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user(uid: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def save_api_key(uid: int, key: str):
    conn = get_db()
    conn.execute("UPDATE users SET deepseek_key=? WHERE id=?", (key, uid))
    conn.commit()
    conn.close()


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


if __name__ == "__main__":
    init_db()
    print("DB initialized at", DB_PATH)
