import json
import re
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)

ACCOUNTS_FILE = "accounts.json"
CODE_REGEX = r"\b(\d{6})\b"

def load_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    return []

def save_accounts(accounts):
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, ensure_ascii=False, indent=2)

@app.route("/")
def index():
    accounts = load_accounts()
    return render_template("index.html", accounts=[a["user"] for a in accounts])

@app.route("/getmail", methods=["POST"])
def getmail():
    user = request.form.get("user")
    accounts = load_accounts()
    account = next((a for a in accounts if a["user"] == user), None)
    if not account:
        return jsonify({"error": "未找到该账号"})
    try:
        from imapclient import IMAPClient
        import email
        with IMAPClient(account["host"]) as server:
            server.login(account["user"], account["password"])
            server.select_folder("INBOX")
            messages = server.search('ALL')
            if not messages:
                return jsonify({"subject": "无邮件", "body": "邮箱为空。"})
            latest_uid = messages[-1]
            raw_message = server.fetch([latest_uid], ['RFC822'])[latest_uid][b'RFC822']
            msg = email.message_from_bytes(raw_message)
            subject = email.header.make_header(email.header.decode_header(msg.get("Subject", "")))
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        text = part.get_payload(decode=True)
                        if text:
                            body += text.decode(errors="ignore")
            else:
                text = msg.get_payload(decode=True)
                if text:
                    body = text.decode(errors="ignore")
            code_match = re.search(CODE_REGEX, body)
            code = code_match.group(1) if code_match else ""
            return jsonify({"subject": str(subject), "body": body, "code": code})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        name = request.form.get("name", "")
        host = request.form.get("host", "")
        user = request.form.get("user", "")
        password = request.form.get("password", "")
        if not (host and user and password):
            return render_template("admin.html", accounts=load_accounts(), error="请填写完整信息")
        accounts = load_accounts()
        if any(a["user"] == user for a in accounts):
            return render_template("admin.html", accounts=accounts, error="该账号已存在")
        accounts.append({"name": name, "host": host, "user": user, "password": password})
        save_accounts(accounts)
        return redirect(url_for("admin"))
    return render_template("admin.html", accounts=load_accounts(), error=None)

@app.route("/del_account", methods=["POST"])
def del_account():
    user = request.form.get("user")
    accounts = load_accounts()
    accounts = [a for a in accounts if a["user"] != user]
    save_accounts(accounts)
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)