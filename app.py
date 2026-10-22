# -*- coding: utf-8 -*-
"""SecInsight-Pro - API 审计告警智能分析平台（企业版）"""
import sys, os, json, threading
sys.path.insert(0, r'C:\Users\HP\Doubao\chats\2026-10-21\new-chat\.pylibs')
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from db import (init_db, create_user, verify_user, get_user, save_api_key,
                create_task, update_task, get_task, list_tasks,
                insert_alerts, update_alert, list_alerts, batch_update_alerts)
from core import cluster_stage1, cluster_stage2_semantic, jaccard_similarity

app = Flask(__name__)
app.secret_key = "secinsight-pro-secret-key-2026"
init_db()


# ============ LLM 真实调用 ============
def call_deepseek(api_key: str, alert: dict, few_shot: list = None) -> dict:
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
    examples = ""
    for ex in (few_shot or [])[-3:]:
        examples += f"\n历史案例: {ex['alert'].get('payload','')} => 人工判定: {ex['human_verdict']}\n"
    prompt = f"""你是安全分析师。判断以下 API 审计告警是否为误报。只返回JSON：
{{"is_false_positive": true/false, "risk_level": "high/medium/low/info", "reason": "一句话说明"}}
{examples}
告警: 规则={alert['rule_id']}, 路径={alert['method']} {alert['path_template']}, Payload={alert['payload']}, 来源IP={alert['src_ip']}"""
    resp = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.3,
    )
    return json.loads(resp.choices[0].message.content)


# ============ 后台分析任务 ============
def run_task(task_id: int, alerts: list, user_key: str):
    update_task(task_id, status="running")
    try:
        clusters = cluster_stage1(alerts)
        total = len(alerts)
        analyzed = 0
        attack = 0
        fp = 0
        verdicts_map = {}  # alert id (内存对象) -> {verdict, risk_level, reason}
        for key, group in clusters.items():
            for sg in cluster_stage2_semantic(group, 0.35):
                sample = sg[0]
                if user_key:
                    try:
                        r = call_deepseek(user_key, sample)
                    except Exception as e:
                        r = {"is_false_positive": False, "risk_level": "medium", "reason": f"API错误: {e}"}
                else:
                    r = {"is_false_positive": len(sample.get("payload","")) < 5,
                         "risk_level": "low" if len(sample.get("payload","")) < 5 else "high",
                         "reason": "规则模拟（未配置API key）"}
                verdict = "误报" if r["is_false_positive"] else "真实告警"
                risk = r.get("risk_level", "high" if verdict == "真实告警" else "low")
                reason = r.get("reason", "")
                if r["is_false_positive"]:
                    fp += len(sg)
                else:
                    attack += len(sg)
                for a in sg:
                    analyzed += 1
                    verdicts_map[id(a)] = {"verdict": verdict, "risk_level": risk, "reason": reason}
                update_task(task_id, analyzed=analyzed, attack_count=attack, fp_count=fp)
        # 批量写回每条告警的结论到数据库
        verdicts_list = [verdicts_map[id(a)] for a in alerts]
        batch_update_alerts(task_id, verdicts_list)
        update_task(task_id, status="done", analyzed=analyzed, attack_count=attack, fp_count=fp)
    except Exception as e:
        update_task(task_id, status="failed", error=str(e))


# ============ 装饰器：登录校验 ============
def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# ============ 路由 ============
@app.route("/")
@login_required
def dashboard():
    uid = session["uid"]
    user = get_user(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))
    tasks = list_tasks(uid)
    key_bound = bool(user.get("deepseek_key"))
    return render_template("dashboard.html", active="dashboard",
                           tasks=tasks[:5], key_bound=key_bound, user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = verify_user(request.form["username"], request.form["password"])
        if u:
            session["uid"] = u["id"]
            session["username"] = u["username"]
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uid = create_user(request.form["username"], request.form["password"])
        if uid > 0:
            return redirect(url_for("login"))
        return render_template("register.html", error="用户名已存在")
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    uid = session["uid"]
    if request.method == "POST":
        save_api_key(uid, request.form["deepseek_key"].strip())
        return redirect(url_for("settings"))
    user = get_user(uid)
    return render_template("settings.html", active="settings", user=user)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        alerts = json.load(f) if f else json.loads(request.form.get("alerts_json", "[]"))
        uid = session["uid"]
        user = get_user(uid)
        tid = create_task(uid, f.filename if f else "manual.json", len(alerts))
        insert_alerts(tid, alerts)
        # 后台线程跑分析
        threading.Thread(target=run_task, args=(tid, alerts, user.get("deepseek_key","")), daemon=True).start()
        return redirect(url_for("task_detail", tid=tid))
    return render_template("upload.html", active="upload")


@app.route("/load_sample")
@login_required
def load_sample():
    with open(os.path.join(os.path.dirname(__file__), "sample_alerts.json"), "r", encoding="utf-8") as f:
        alerts = json.load(f)
    uid = session["uid"]
    user = get_user(uid)
    tid = create_task(uid, "sample_alerts.json", len(alerts))
    insert_alerts(tid, alerts)
    threading.Thread(target=run_task, args=(tid, alerts, user.get("deepseek_key","")), daemon=True).start()
    return redirect(url_for("task_detail", tid=tid))


@app.route("/task/<int:tid>")
@login_required
def task_detail(tid):
    task = get_task(tid)
    if not task or task["user_id"] != session["uid"]:
        return "任务不存在", 404
    alerts = list_alerts(tid)
    return render_template("task_detail.html", active="tasks", task=task, alerts=alerts)


@app.route("/task/<int:tid>/status")
@login_required
def task_status(tid):
    task = get_task(tid)
    return jsonify({"status": task["status"], "analyzed": task["analyzed"],
                    "total": task["total"], "attack": task["attack_count"],
                    "fp": task["fp_count"], "error": task.get("error","")})


@app.route("/task/<int:tid>/export")
@login_required
def export_report(tid):
    task = get_task(tid)
    if not task or task["user_id"] != session["uid"]:
        return "任务不存在", 404
    alerts = list_alerts(tid)
    attacks = [a for a in alerts if a["verdict"] == "真实告警"]
    fps = [a for a in alerts if a["verdict"] == "误报"]
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>分析报告 #{tid}</title>
<style>
body{{font-family:-apple-system,"Microsoft YaHei",sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#2c3e50}}
h1{{font-size:22px;border-bottom:2px solid #1f3a5f;padding-bottom:10px}}
.meta{{color:#888;font-size:13px;margin-bottom:24px}}
.summary{{display:flex;gap:30px;margin:20px 0}}
.summary div{{padding:14px 20px;border-radius:8px;background:#f8f9fa}}
.summary .attack{{color:#c0392b}}
.summary .fp{{color:#16a34a}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th{{background:#fafbfc;padding:10px;text-align:left;font-size:12px;border-bottom:2px solid #e8e8e8}}
td{{padding:10px;font-size:13px;border-bottom:1px solid #f0f0f0}}
.section{{margin-top:28px}}
.section h2{{font-size:16px;color:#1f3a5f;margin-bottom:12px}}
</style></head><body>
<h1>API 审计告警分析报告</h1>
<p class="meta">任务 #{tid} · 数据源：{task['filename']} · 分析时间：{task['created_at']}</p>
<div class="summary">
  <div>总告警：<b>{task['total']}</b></div>
  <div class="attack">真实攻击：<b>{task['attack_count']}</b></div>
  <div class="fp">误报：<b>{task['fp_count']}</b></div>
</div>
<div class="section"><h2>真实攻击明细</h2><table>
<tr><th>路径</th><th>来源 IP</th><th>规则</th><th>分析结论</th></tr>
{"".join(f'<tr><td>{a["method"]} {a["path_template"]}</td><td>{a["src_ip"]}</td><td>{a["rule_id"]}</td><td>{a["llm_reason"]}</td></tr>' for a in attacks) or '<tr><td colspan="4">无</td></tr>'}
</table></div>
<div class="section"><h2>误报明细</h2><table>
<tr><th>路径</th><th>来源 IP</th><th>规则</th><th>误报原因</th></tr>
{"".join(f'<tr><td>{a["method"]} {a["path_template"]}</td><td>{a["src_ip"]}</td><td>{a["rule_id"]}</td><td>{a["llm_reason"]}</td></tr>' for a in fps) or '<tr><td colspan="4">无</td></tr>'}
</table></div>
<p class="meta" style="margin-top:40px">本报告由 sec-analyzer 自动生成</p>
</body></html>"""
    from flask import Response
    return Response(html, mimetype="text/html; charset=utf-8")


@app.route("/packet_analyzer")
@login_required
def packet_analyzer():
    return render_template("packet_analyzer.html", active="packet")


@app.route("/api/analyze_packet", methods=["POST"])
@login_required
def analyze_packet():
    pkt = request.json.get("packet", "")
    user = get_user(session["uid"])
    key = user.get("deepseek_key", "")

    # 规则引擎兜底：即使没绑 key 也能先给出基础判定
    def rule_based(p):
        p_low = p.lower()
        if "' or '1'='1" in p_low or "' or 1=1" in p_low or "union select" in p_low or "extractvalue" in p_low or "updatexml" in p_low:
            return {"is_attack": True, "attack_type": "SQL注入", "risk_level": "high",
                    "reason": "报文中检测到 SQL 注入特征（逻辑永真式/报错注入函数）",
                    "remediation": "登录接口改用参数化查询（PreparedStatement），WAF 拦截含单引号+OR 的请求，封禁该源 IP"}
        if "<script" in p_low or "onerror=" in p_low or "onclick=" in p_low and "fetch(" in p_low:
            return {"is_attack": True, "attack_type": "XSS", "risk_level": "high",
                    "reason": "报文中检测到反射型 XSS payload（script 标签/事件处理器）",
                    "remediation": "输出处做 HTML 转义，CSP 头限制脚本源，WAF 拦截含 <script> 的请求参数"}
        if "/.env" in p_low or "/.git" in p_low or "/wp-admin" in p_low or "/phpmyadmin" in p_low:
            return {"is_attack": True, "attack_type": "敏感路径扫描", "risk_level": "medium",
                    "reason": "请求探测敏感配置路径，典型自动化扫描行为",
                    "remediation": "WAF 拦截 /.env /.git 等路径访问，该源 IP 限速或临时封禁"}
        if "admin'--" in p_low or "or 1=1--" in p_low:
            return {"is_attack": True, "attack_type": "SQL注入", "risk_level": "high",
                    "reason": "报文中检测到 SQL 注入特征（注释截断）",
                    "remediation": "参数化查询，WAF 规则补充"}
        return {"is_attack": False, "attack_type": "正常请求", "risk_level": "info",
                "reason": "未检测到明显攻击特征，报文结构正常",
                "remediation": "无需处置，持续监控即可"}

    if not key:
        return jsonify(rule_based(pkt))

    try:
        from openai import OpenAI
        client = OpenAI(api_key=key, base_url="https://api.deepseek.com")
        prompt = f"""你是网络安全工程师。分析以下 HTTP 请求报文，判断是否为攻击，并给出处置建议。
只返回 JSON：{{"is_attack": true/false, "attack_type": "SQL注入/XSS/扫描/正常/...", "risk_level": "high/medium/low/info", "reason": "详细分析该报文为何是/不是攻击", "remediation": "针对该攻击类型的具体修复建议（如下游如何防御、WAF规则、代码修复方向）"}}

报文：
{pkt}"""
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.2,
            timeout=15,
        )
        return jsonify(json.loads(resp.choices[0].message.content))
    except Exception:
        # LLM 调用失败时降级到规则引擎
        return jsonify(rule_based(pkt))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
