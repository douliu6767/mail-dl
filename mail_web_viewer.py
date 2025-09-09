import json
import re
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from models import db, AdminUser, MailAccount

app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "a_very_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mail_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def init_db():
    with app.app_context():
        db.create_all()
        # 创建默认管理员账号
        if not AdminUser.query.filter_by(username='admin').first():
            user = AdminUser(username='admin')
            user.set_password('123456')
            db.session.add(user)
            db.session.commit()

init_db()

CODE_REGEX = r"\b(\d{6})\b"

@app.route("/")
def index():
    # 前端页面不显示账号列表，只提供输入框
    return render_template("index.html")

@app.route("/getmail", methods=["POST"])
def getmail():
    user = request.form.get("user")
    if not user:
        return jsonify({"error": "请输入邮箱地址"})
    
    # 从数据库查找账号
    account = MailAccount.query.filter_by(user=user).first()
    if not account:
        return jsonify({"error": "未找到该邮箱账号，请联系管理员添加"})
    
    try:
        from imapclient import IMAPClient
        import email
        
        # 使用解密后的密码登录
        password = account.get_password()
        with IMAPClient(account.host) as server:
            server.login(account.user, password)
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
            accounts = MailAccount.query.all()
            return render_template("admin.html", accounts=accounts, error="请填写完整信息", username=session.get('username'))
        
        # 检查账号是否已存在
        existing_account = MailAccount.query.filter_by(user=user).first()
        if existing_account:
            accounts = MailAccount.query.all()
            return render_template("admin.html", accounts=accounts, error="该账号已存在", username=session.get('username'))
        
        # 创建新账号
        new_account = MailAccount(name=name, host=host, user=user)
        new_account.set_password(password)
        db.session.add(new_account)
        db.session.commit()
        
        return redirect(url_for("admin"))
    
    accounts = MailAccount.query.all()
    return render_template("admin.html", accounts=accounts, error=None, username=session.get('username'))

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

# 测试账号连接
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
        password = account.get_password()
        with IMAPClient(account.host) as server:
            server.login(account.user, password)
        return jsonify({"result": "连接成功"})
    except Exception as e:
        return jsonify({"result": f"连接失败：{str(e)}"})

# 导出账号
@app.route("/export_accounts")
def export_accounts():
    if not session.get('logged_in'):
        return jsonify([])
    
    accounts = MailAccount.query.all()
    export_data = []
    for account in accounts:
        export_data.append({
            "name": account.name,
            "host": account.host,
            "user": account.user,
            "password": account.get_password()  # 导出时解密密码
        })
    return jsonify(export_data)

# 导入账号
@app.route("/import_accounts", methods=["POST"])
def import_accounts():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        accounts_data = json.loads(request.data)
        
        for acc_data in accounts_data:
            # 检查账号是否已存在
            existing = MailAccount.query.filter_by(user=acc_data["user"]).first()
            if not existing:
                new_account = MailAccount(
                    name=acc_data.get("name", ""),
                    host=acc_data["host"],
                    user=acc_data["user"]
                )
                new_account.set_password(acc_data["password"])
                db.session.add(new_account)
        
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# 批量删除账号
@app.route("/batch_delete", methods=["POST"])
def batch_delete():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        users = request.json.get("users", [])
        for user in users:
            account = MailAccount.query.filter_by(user=user).first()
            if account:
                db.session.delete(account)
        
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
