import json
import re
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from models import db, AdminUser

app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "a_very_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def init_admin():
    with app.app_context():
        db.create_all()
        if not AdminUser.query.filter_by(username='admin').first():
            user = AdminUser(username='admin')
            user.set_password('123456')
            db.session.add(user)
            db.session.commit()
init_admin()

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = AdminUser.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('admin'))
        else:
            error = "用户名或密码错误"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == "POST":
        name = request.form.get("name", "")
        host = request.form.get("host", "")
        user = request.form.get("user", "")
        password = request.form.get("password", "")
        if not (host and user and password):
            return render_template("admin.html", accounts=load_accounts(), error="请填写完整信息", username=session.get('username'))
        accounts = load_accounts()
        if any(a["user"] == user for a in accounts):
            return render_template("admin.html", accounts=accounts, error="该账号已存在", username=session.get('username'))
        accounts.append({"name": name, "host": host, "user": user, "password": password})
        save_accounts(accounts)
        return redirect(url_for("admin"))
    return render_template("admin.html", accounts=load_accounts(), error=None, username=session.get('username'))

@app.route("/del_account", methods=["POST"])
def del_account():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = request.form.get("user")
    accounts = load_accounts()
    accounts = [a for a in accounts if a["user"] != user]
    save_accounts(accounts)
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
