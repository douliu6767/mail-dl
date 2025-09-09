import json
import re
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
from models import db, AdminUser, SystemSettings, ProxyPool

app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "a_very_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
        return jsonify({"error": "邮箱不存在"})
    try:
        # 获取协议、端口和SSL设置，提供默认值以支持旧账号
        protocol = account.get("protocol", "IMAP")
        port = account.get("port", 993 if account.get("ssl", True) else 143)
        ssl = account.get("ssl", True)
        host = account["host"]
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            import email
            with IMAPClient(host, port=port, ssl=ssl) as server:
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
        else:  # POP3
            import poplib
            import email
            if ssl:
                server = poplib.POP3_SSL(host, port)
            else:
                server = poplib.POP3(host, port)
            server.user(account["user"])
            server.pass_(account["password"])
            
            # 获取邮件数量
            num_messages = len(server.list()[1])
            if num_messages == 0:
                server.quit()
                return jsonify({"subject": "无邮件", "body": "邮箱为空。"})
            
            # 获取最新邮件
            raw_message = b"\n".join(server.retr(num_messages)[1])
            server.quit()
            
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
    
    # 获取自定义logo设置
    custom_logo = SystemSettings.get_setting('custom_logo', 'logo.png')
    return render_template('login.html', error=error, custom_logo=custom_logo)

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
        protocol = request.form.get("protocol", "IMAP")  # 新增协议字段
        port = request.form.get("port", "")  # 新增端口字段
        ssl = request.form.get("ssl") == "on"  # 新增SSL字段
        
        if not (host and user and password):
            proxy_count = ProxyPool.query.count()
            return render_template("admin.html", accounts=load_accounts(), error="请填写完整信息", username=session.get('username'), proxy_count=proxy_count)
        
        # 如果端口为空，根据协议和SSL设置默认端口
        if not port:
            if protocol == "IMAP":
                port = "993" if ssl else "143"
            else:  # POP3
                port = "995" if ssl else "110"
        
        accounts = load_accounts()
        if any(a["user"] == user for a in accounts):
            proxy_count = ProxyPool.query.count()
            return render_template("admin.html", accounts=accounts, error="该账号已存在", username=session.get('username'), proxy_count=proxy_count)
        
        # 创建包含新字段的账号数据
        new_account = {
            "name": name, 
            "host": host, 
            "user": user, 
            "password": password,
            "protocol": protocol,
            "port": int(port) if port.isdigit() else port,
            "ssl": ssl
        }
        accounts.append(new_account)
        save_accounts(accounts)
        
        # 不重定向到首页，而是重新渲染当前页面
        proxy_count = ProxyPool.query.count()
        return render_template("admin.html", accounts=load_accounts(), error=None, success="账号添加成功！", username=session.get('username'), proxy_count=proxy_count)
    
    proxy_count = ProxyPool.query.count()
    return render_template("admin.html", accounts=load_accounts(), error=None, username=session.get('username'), proxy_count=proxy_count)

@app.route("/del_account", methods=["POST"])
def del_account():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = request.form.get("user")
    accounts = load_accounts()
    accounts = [a for a in accounts if a["user"] != user]
    save_accounts(accounts)
    # 不重定向到首页，而是重新渲染当前页面
    proxy_count = ProxyPool.query.count()
    return render_template("admin.html", accounts=load_accounts(), error=None, success="账号删除成功！", username=session.get('username'), proxy_count=proxy_count)

# 新增：测试账号连接
@app.route("/test_account", methods=["POST"])
def test_account():
    if not session.get('logged_in'):
        return jsonify({"result": "未登录"})
    user = request.form.get("user")
    accounts = load_accounts()
    account = next((a for a in accounts if a["user"] == user), None)
    if not account:
        return jsonify({"result": "账号不存在"})
    try:
        # 获取协议、端口和SSL设置，提供默认值以支持旧账号
        protocol = account.get("protocol", "IMAP")
        port = account.get("port", 993 if account.get("ssl", True) else 143)
        ssl = account.get("ssl", True)
        host = account["host"]
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            with IMAPClient(host, port=port, ssl=ssl) as server:
                server.login(account["user"], account["password"])
        else:  # POP3
            import poplib
            if ssl:
                server = poplib.POP3_SSL(host, port)
            else:
                server = poplib.POP3(host, port)
            server.user(account["user"])
            server.pass_(account["password"])
            server.quit()
        
        return jsonify({"result": "连接成功"})
    except Exception as e:
        return jsonify({"result": f"连接失败：{str(e)}"})

# 新增：导出账号
@app.route("/export_accounts")
def export_accounts():
    if not session.get('logged_in'):
        return jsonify([])
    return jsonify(load_accounts())

# 新增：导入账号
@app.route("/import_accounts", methods=["POST"])
def import_accounts():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        accounts = json.loads(request.data)
        save_accounts(accounts)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# 新增：批量删除账号
@app.route("/batch_delete", methods=["POST"])
def batch_delete():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        users = request.json.get("users", [])
        accounts = load_accounts()
        accounts = [a for a in accounts if a["user"] not in users]
        save_accounts(accounts)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# 系统设置相关路由
@app.route("/upload_logo", methods=["POST"])
def upload_logo():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    if 'logo' not in request.files:
        return jsonify({"success": False, "error": "没有选择文件"})
    
    file = request.files['logo']
    if file.filename == '':
        return jsonify({"success": False, "error": "没有选择文件"})
    
    if file and allowed_file(file.filename):
        try:
            # 删除旧的logo文件
            old_logo = SystemSettings.get_setting('custom_logo')
            if old_logo and old_logo != 'logo.png':
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_logo)
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            # 保存新文件
            filename = secure_filename(file.filename)
            filename = f"custom_logo_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # 更新数据库设置
            SystemSettings.set_setting('custom_logo', filename)
            
            return jsonify({"success": True, "filename": filename})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
    else:
        return jsonify({"success": False, "error": "文件格式不支持，请上传 PNG、JPG 或 JPEG 格式"})

@app.route("/reset_logo", methods=["POST"])
def reset_logo():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        # 删除自定义logo文件
        old_logo = SystemSettings.get_setting('custom_logo')
        if old_logo and old_logo != 'logo.png':
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_logo)
            if os.path.exists(old_path):
                os.remove(old_path)
        
        # 重置为默认logo
        SystemSettings.set_setting('custom_logo', 'logo.png')
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# 代理池管理路由
@app.route("/api/proxy", methods=["GET"])
def get_proxies():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    proxies = ProxyPool.query.all()
    return jsonify({"success": True, "data": [proxy.to_dict() for proxy in proxies]})

@app.route("/api/proxy", methods=["POST"])
def add_proxy():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        data = request.json
        proxy = ProxyPool(
            name=data.get('name'),
            host=data.get('host'),
            port=int(data.get('port')),
            username=data.get('username'),
            password=data.get('password'),
            protocol=data.get('protocol', 'HTTP')
        )
        db.session.add(proxy)
        db.session.commit()
        return jsonify({"success": True, "data": proxy.to_dict()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/proxy/<int:proxy_id>", methods=["PUT"])
def update_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        proxy = ProxyPool.query.get_or_404(proxy_id)
        data = request.json
        
        proxy.name = data.get('name', proxy.name)
        proxy.host = data.get('host', proxy.host)
        proxy.port = int(data.get('port', proxy.port))
        proxy.username = data.get('username', proxy.username)
        proxy.password = data.get('password', proxy.password)
        proxy.protocol = data.get('protocol', proxy.protocol)
        proxy.is_active = data.get('is_active', proxy.is_active)
        
        db.session.commit()
        return jsonify({"success": True, "data": proxy.to_dict()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/proxy/<int:proxy_id>", methods=["DELETE"])
def delete_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        proxy = ProxyPool.query.get_or_404(proxy_id)
        db.session.delete(proxy)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/proxy/<int:proxy_id>/toggle", methods=["POST"])
def toggle_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        proxy = ProxyPool.query.get_or_404(proxy_id)
        proxy.is_active = not proxy.is_active
        db.session.commit()
        return jsonify({"success": True, "data": proxy.to_dict()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# 获取系统设置
@app.route("/api/settings", methods=["GET"])
def get_settings():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    settings = {
        'custom_logo': SystemSettings.get_setting('custom_logo', 'logo.png')
    }
    return jsonify({"success": True, "data": settings})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
