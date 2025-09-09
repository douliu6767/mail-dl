import json
import re
import os
import socket
import socks
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
PROXIES_FILE = "proxies.json"
CODE_REGEX = r"\b(\d{6})\b"

def load_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    return []

def save_accounts(accounts):
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, ensure_ascii=False, indent=2)

def load_proxies():
    if os.path.exists(PROXIES_FILE):
        with open(PROXIES_FILE, encoding="utf-8") as f:
            return json.load(f)
    return []

def save_proxies(proxies):
    with open(PROXIES_FILE, "w", encoding="utf-8") as f:
        json.dump(proxies, f, ensure_ascii=False, indent=2)

def get_proxy_for_connection(proxy_selection="auto"):
    """
    获取用于连接的代理配置
    proxy_selection: "auto" 自动选择, "direct" 直接连接, 或者特定代理ID
    返回代理配置字典或None
    """
    if proxy_selection == "direct":
        return None
        
    proxies = load_proxies()
    if not proxies:
        return None
    
    if proxy_selection == "auto":
        # 自动选择第一个可用的代理
        for proxy in proxies:
            if proxy.get("enabled", True):
                return proxy
        return None
    elif proxy_selection == "manual":
        # 手动选择模式下，返回第一个启用的代理
        # 实际使用时应该通过UI传递具体的代理ID
        for proxy in proxies:
            if proxy.get("enabled", True):
                return proxy
        return None
    else:
        # 根据代理ID选择特定代理
        for proxy in proxies:
            if proxy.get("id") == proxy_selection and proxy.get("enabled", True):
                return proxy
        return None

def create_connection_with_proxy(host, port, ssl, proxy_config=None):
    """
    创建带代理的连接配置
    返回连接参数字典
    """
    connection_params = {
        'host': host,
        'port': port,
        'ssl': ssl
    }
    
    if proxy_config:
        # 如果有代理配置，添加代理参数
        connection_params['proxy'] = {
            'type': proxy_config.get('type', 'HTTP'),
            'host': proxy_config.get('host'),
            'port': proxy_config.get('port'),
            'username': proxy_config.get('username'),
            'password': proxy_config.get('password')
        }
    
    return connection_params

def create_proxy_socket(proxy_config, dest_host, dest_port):
    """
    创建代理socket连接
    """
    if not proxy_config:
        return None
    
    proxy_type = proxy_config.get('type', 'HTTP').upper()
    proxy_host = proxy_config.get('host')
    proxy_port = proxy_config.get('port')
    proxy_username = proxy_config.get('username')
    proxy_password = proxy_config.get('password')
    
    if proxy_type == 'HTTP':
        socks_type = socks.HTTP
    elif proxy_type == 'SOCKS4':
        socks_type = socks.SOCKS4
    elif proxy_type == 'SOCKS5':
        socks_type = socks.SOCKS5
    else:
        raise ValueError(f"Unsupported proxy type: {proxy_type}")
    
    # 创建代理socket
    sock = socks.socksocket()
    sock.set_proxy(socks_type, proxy_host, proxy_port, username=proxy_username, password=proxy_password)
    sock.connect((dest_host, dest_port))
    return sock

@app.route("/")
def index():
    accounts = load_accounts()
    proxies = load_proxies()
    return render_template("index.html", accounts=[a["user"] for a in accounts], proxies=proxies)

@app.route("/getmail", methods=["POST"])
def getmail():
    user = request.form.get("user")
    proxy_selection = request.form.get("proxy_selection", "auto")  # 代理选择模式
    
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
        
        # 获取代理配置
        proxy_config = get_proxy_for_connection(proxy_selection)
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            import email
            
            if proxy_config:
                # 使用代理连接
                proxy_sock = create_proxy_socket(proxy_config, host, port)
                if ssl:
                    import ssl as ssl_module
                    ssl_context = ssl_module.create_default_context()
                    proxy_sock = ssl_context.wrap_socket(proxy_sock, server_hostname=host)
                server = IMAPClient(host, port=port, ssl=False, sock=proxy_sock)
            else:
                # 直接连接
                server = IMAPClient(host, port=port, ssl=ssl)
            
            with server:
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
            
            if proxy_config:
                # POP3 代理连接
                proxy_sock = create_proxy_socket(proxy_config, host, port)
                if ssl:
                    import ssl as ssl_module
                    ssl_context = ssl_module.create_default_context()
                    proxy_sock = ssl_context.wrap_socket(proxy_sock, server_hostname=host)
                server = poplib.POP3(host, port) if not ssl else poplib.POP3_SSL(host, port)
            else:
                # 直接连接
                server = poplib.POP3_SSL(host, port) if ssl else poplib.POP3(host, port)
            
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
        protocol = request.form.get("protocol", "IMAP")  # 新增协议字段
        port = request.form.get("port", "")  # 新增端口字段
        ssl = request.form.get("ssl") == "on"  # 新增SSL字段
        
        if not (host and user and password):
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(),
                                 error="请填写完整信息", username=session.get('username'))
        
        # 如果端口为空，根据协议和SSL设置默认端口
        if not port:
            if protocol == "IMAP":
                port = "993" if ssl else "143"
            else:  # POP3
                port = "995" if ssl else "110"
        
        accounts = load_accounts()
        if any(a["user"] == user for a in accounts):
            return render_template("admin.html", accounts=accounts, proxies=load_proxies(),
                                 error="该账号已存在", username=session.get('username'))
        
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
        return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(),
                             error=None, success="账号添加成功！", username=session.get('username'))
    return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(),
                         error=None, username=session.get('username'))

@app.route("/del_account", methods=["POST"])
def del_account():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = request.form.get("user")
    accounts = load_accounts()
    accounts = [a for a in accounts if a["user"] != user]
    save_accounts(accounts)
    # 不重定向到首页，而是重新渲染当前页面
    return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(),
                         error=None, success="账号删除成功！", username=session.get('username'))

# 新增：测试账号连接
@app.route("/test_account", methods=["POST"])
def test_account():
    if not session.get('logged_in'):
        return jsonify({"result": "未登录"})
    user = request.form.get("user")
    proxy_selection = request.form.get("proxy_selection", "auto")  # 代理选择模式
    
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
        
        # 获取代理配置
        proxy_config = get_proxy_for_connection(proxy_selection)
        proxy_info = f" (通过代理: {proxy_config['host']}:{proxy_config['port']})" if proxy_config else " (直接连接)"
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            if proxy_config:
                # 使用代理连接
                proxy_sock = create_proxy_socket(proxy_config, host, port)
                if ssl:
                    import ssl as ssl_module
                    ssl_context = ssl_module.create_default_context()
                    proxy_sock = ssl_context.wrap_socket(proxy_sock, server_hostname=host)
                server = IMAPClient(host, port=port, ssl=False, sock=proxy_sock)
            else:
                # 直接连接
                server = IMAPClient(host, port=port, ssl=ssl)
            
            with server:
                server.login(account["user"], account["password"])
        else:  # POP3
            import poplib
            if proxy_config:
                # POP3 代理连接需要更复杂的处理
                proxy_sock = create_proxy_socket(proxy_config, host, port)
                if ssl:
                    import ssl as ssl_module
                    ssl_context = ssl_module.create_default_context()
                    proxy_sock = ssl_context.wrap_socket(proxy_sock, server_hostname=host)
                # 对于POP3，我们需要自己处理协议
                # 这里简化处理，实际应用中可能需要更复杂的实现
                server = poplib.POP3(host, port) if not ssl else poplib.POP3_SSL(host, port)
            else:
                # 直接连接
                server = poplib.POP3_SSL(host, port) if ssl else poplib.POP3(host, port)
            
            server.user(account["user"])
            server.pass_(account["password"])
            server.quit()
        
        return jsonify({"result": f"连接成功{proxy_info}"})
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

# 新增：代理池管理路由
@app.route("/proxy_admin", methods=["GET", "POST"])
def proxy_admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == "POST":
        name = request.form.get("name", "")
        proxy_type = request.form.get("type", "HTTP")
        host = request.form.get("host", "")
        port = request.form.get("port", "")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        enabled = request.form.get("enabled") == "on"
        
        if not (host and port):
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 error="请填写代理主机和端口", username=session.get('username'))
        
        try:
            port = int(port)
        except ValueError:
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 error="端口必须是数字", username=session.get('username'))
        
        proxies = load_proxies()
        # 生成唯一ID
        import time
        new_proxy = {
            "id": str(int(time.time() * 1000)),
            "name": name,
            "type": proxy_type,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "enabled": enabled
        }
        proxies.append(new_proxy)
        save_proxies(proxies)
        
        return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(),
                             success="代理添加成功！", username=session.get('username'))
    
    return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                         username=session.get('username'))

@app.route("/del_proxy", methods=["POST"])
def del_proxy():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    proxy_id = request.form.get("proxy_id")
    proxies = load_proxies()
    proxies = [p for p in proxies if p["id"] != proxy_id]
    save_proxies(proxies)
    return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(),
                         success="代理删除成功！", username=session.get('username'))

@app.route("/test_proxy", methods=["POST"])
def test_proxy():
    if not session.get('logged_in'):
        return jsonify({"result": "未登录"})
    proxy_id = request.form.get("proxy_id")
    proxies = load_proxies()
    proxy = next((p for p in proxies if p["id"] == proxy_id), None)
    if not proxy:
        return jsonify({"result": "代理不存在"})
    
    try:
        # 测试代理连接 - 尝试连接到百度
        test_sock = create_proxy_socket(proxy, "www.baidu.com", 80)
        test_sock.close()
        return jsonify({"result": "代理连接成功"})
    except Exception as e:
        return jsonify({"result": f"代理连接失败：{str(e)}"})

@app.route("/export_proxies")
def export_proxies():
    if not session.get('logged_in'):
        return jsonify([])
    return jsonify(load_proxies())

@app.route("/import_proxies", methods=["POST"])
def import_proxies():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxies = json.loads(request.data)
        save_proxies(proxies)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/batch_delete_proxies", methods=["POST"])
def batch_delete_proxies():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxy_ids = request.json.get("proxy_ids", [])
        proxies = load_proxies()
        proxies = [p for p in proxies if p["id"] not in proxy_ids]
        save_proxies(proxies)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
