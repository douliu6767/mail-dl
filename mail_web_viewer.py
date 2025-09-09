import re
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, Response
from models import db, AdminUser, MailAccount

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

CODE_REGEX = r"\b(\d{6})\b"

@app.route("/")
def index():
    accounts = MailAccount.query.all()
    return render_template("index.html", accounts=[a.user for a in accounts])

@app.route("/getmail", methods=["POST"])
def getmail():
    user = request.form.get("user")
    account = MailAccount.query.filter_by(user=user).first()
    if not account:
        return jsonify({"error": "未找到该账号"})
    try:
        from imapclient import IMAPClient
        import email
        with IMAPClient(account.host) as server:
            server.login(account.user, account.password)
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
    error = None
    if request.method == "POST":
        name = request.form.get("name", "")
        host = request.form.get("host", "")
        user = request.form.get("user", "")
        password = request.form.get("password", "")
        if not (host and user and password):
            error = "请填写完整信息"
        elif MailAccount.query.filter_by(user=user).first():
            error = "该账号已存在"
        else:
            new_acc = MailAccount(name=name, host=host, user=user, password=password)
            db.session.add(new_acc)
            db.session.commit()
            return redirect(url_for("admin"))
    accounts = MailAccount.query.all()
    admin_user = AdminUser.query.filter_by(username=session.get('username')).first()
    return render_template("admin.html", accounts=accounts, error=error, username=session.get('username'), admin_user=admin_user)

@app.route("/change_admin_info", methods=['POST'])
def change_admin_info():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    new_username = request.form.get('new_username', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()
    user = AdminUser.query.filter_by(username=session.get('username')).first()
    if not user:
        flash('管理员账号不存在', 'danger')
    else:
        # 修改用户名
        if new_username and new_username != user.username:
            # 检查新用户名是否已存在
            if AdminUser.query.filter_by(username=new_username).first():
                flash('新用户名已存在', 'danger')
            else:
                user.username = new_username
                session['username'] = new_username
                flash('管理员账号修改成功', 'success')
        # 修改密码
        if new_password:
            if new_password != confirm_password:
                flash('两次密码输入不一致', 'danger')
            elif len(new_password) < 6:
                flash('密码长度至少6位', 'danger')
            else:
                user.set_password(new_password)
                flash('管理员密码修改成功', 'success')
        db.session.commit()
    return redirect(url_for('admin'))

@app.route("/del_account", methods=["POST"])
def del_account():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = request.form.get("user")
    account = MailAccount.query.filter_by(user=user).first()
    if account:
        db.session.delete(account)
        db.session.commit()
    return redirect(url_for("admin"))

@app.route("/test_account", methods=["POST"])
def test_account():
    if not session.get('logged_in'):
        return jsonify({"result": "未登录"})
    user = request.form.get("user")
    account = MailAccount.query.filter_by(user=user).first()
    if not account:
        return jsonify({"result": "账号不存在"})
    try:
        from imapclient import IMAPClient
        with IMAPClient(account.host) as server:
            server.login(account.user, account.password)
        return jsonify({"result": "连接成功"})
    except Exception as e:
        return jsonify({"result": f"连接失败：{str(e)}"})

@app.route("/export_accounts")
def export_accounts():
    if not session.get('logged_in'):
        return jsonify([])
    accounts = MailAccount.query.all()
    return jsonify([
        {"name": a.name, "host": a.host, "user": a.user, "password": a.password}
        for a in accounts
    ])

@app.route("/import_accounts", methods=["POST"])
def import_accounts():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        accounts = request.get_json(force=True)
        for acc in accounts:
            if not MailAccount.query.filter_by(user=acc.get("user")).first():
                new_acc = MailAccount(
                    name=acc.get("name"),
                    host=acc.get("host"),
                    user=acc.get("user"),
                    password=acc.get("password")
                )
                db.session.add(new_acc)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/batch_delete", methods=["POST"])
def batch_delete():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        users = request.json.get("users", [])
        for user in users:
            acc = MailAccount.query.filter_by(user=user).first()
            if acc:
                db.session.delete(acc)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
