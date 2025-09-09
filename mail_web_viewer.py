import json
import re
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
from models import db, AdminUser

app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "a_very_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
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

def get_proxy_for_connection():
    """获取一个可用的代理进行连接"""
    proxies = load_proxies()
    active_proxies = [p for p in proxies if p.get("status", "active") == "active"]
    if active_proxies:
        # 简单轮询选择，可以后续优化为更智能的选择策略
        import random
        return random.choice(active_proxies)
    return None

def create_proxy_connection(proxy_info, target_host, target_port, ssl=True):
    """使用代理创建连接"""
    if not proxy_info:
        return None
    
    try:
        if proxy_info["type"] in ["SOCKS4", "SOCKS5"]:
            import socks
            import socket
            
            # 创建SOCKS代理连接
            sock = socks.socksocket()
            if proxy_info["type"] == "SOCKS4":
                sock.set_proxy(socks.SOCKS4, proxy_info["host"], proxy_info["port"])
            else:  # SOCKS5
                if proxy_info.get("username") and proxy_info.get("password"):
                    sock.set_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"], 
                                 username=proxy_info["username"], password=proxy_info["password"])
                else:
                    sock.set_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"])
            
            sock.connect((target_host, target_port))
            return sock
        elif proxy_info["type"] in ["HTTP", "HTTPS"]:
            # HTTP代理需要特殊处理，暂时不实现直接的IMAP HTTP代理
            # 因为IMAP协议本身不支持HTTP代理，需要使用CONNECT方法
            return None
    except Exception as e:
        print(f"代理连接失败: {e}")
        return None
    
    return None

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
    
    # 获取代理进行连接
    proxy_info = get_proxy_for_connection()
    
    try:
        # 获取协议、端口和SSL设置，提供默认值以支持旧账号
        protocol = account.get("protocol", "IMAP")
        port = account.get("port", 993 if account.get("ssl", True) else 143)
        ssl = account.get("ssl", True)
        host = account["host"]
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            import email
            
            # 尝试使用代理连接
            if proxy_info:
                try:
                    import socks
                    import socket
                    # 配置全局代理
                    if proxy_info["type"] == "SOCKS5":
                        if proxy_info.get("username") and proxy_info.get("password"):
                            socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"], 
                                                  username=proxy_info["username"], password=proxy_info["password"])
                        else:
                            socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"])
                    elif proxy_info["type"] == "SOCKS4":
                        socks.set_default_proxy(socks.SOCKS4, proxy_info["host"], proxy_info["port"])
                    
                    socket.socket = socks.socksocket
                except Exception as e:
                    print(f"代理设置失败，使用直连: {e}")
            
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
            
            # 尝试使用代理连接
            if proxy_info:
                try:
                    import socks
                    import socket
                    # 配置全局代理
                    if proxy_info["type"] == "SOCKS5":
                        if proxy_info.get("username") and proxy_info.get("password"):
                            socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"], 
                                                  username=proxy_info["username"], password=proxy_info["password"])
                        else:
                            socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"])
                    elif proxy_info["type"] == "SOCKS4":
                        socks.set_default_proxy(socks.SOCKS4, proxy_info["host"], proxy_info["port"])
                    
                    socket.socket = socks.socksocket
                except Exception as e:
                    print(f"代理设置失败，使用直连: {e}")
            
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
    finally:
        # 重置socket以避免影响其他连接
        try:
            import socket
            import socks
            socket.socket = socks.socksocket.__bases__[0]
        except:
            pass

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
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), error="请填写完整信息", username=session.get('username'))
        
        # 如果端口为空，根据协议和SSL设置默认端口
        if not port:
            if protocol == "IMAP":
                port = "993" if ssl else "143"
            else:  # POP3
                port = "995" if ssl else "110"
        
        accounts = load_accounts()
        if any(a["user"] == user for a in accounts):
            return render_template("admin.html", accounts=accounts, proxies=load_proxies(), error="该账号已存在", username=session.get('username'))
        
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
        return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), error=None, success="账号添加成功！", username=session.get('username'))
    return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), error=None, username=session.get('username'))

@app.route("/del_account", methods=["POST"])
def del_account():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = request.form.get("user")
    accounts = load_accounts()
    accounts = [a for a in accounts if a["user"] != user]
    save_accounts(accounts)
    # 不重定向到首页，而是重新渲染当前页面
    return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), error=None, success="账号删除成功！", username=session.get('username'))

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
    
    # 获取代理进行连接
    proxy_info = get_proxy_for_connection()
    
    try:
        # 获取协议、端口和SSL设置，提供默认值以支持旧账号
        protocol = account.get("protocol", "IMAP")
        port = account.get("port", 993 if account.get("ssl", True) else 143)
        ssl = account.get("ssl", True)
        host = account["host"]
        
        # 尝试使用代理连接
        if proxy_info:
            try:
                import socks
                import socket
                # 配置全局代理
                if proxy_info["type"] == "SOCKS5":
                    if proxy_info.get("username") and proxy_info.get("password"):
                        socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"], 
                                              username=proxy_info["username"], password=proxy_info["password"])
                    else:
                        socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"])
                elif proxy_info["type"] == "SOCKS4":
                    socks.set_default_proxy(socks.SOCKS4, proxy_info["host"], proxy_info["port"])
                
                socket.socket = socks.socksocket
            except Exception as e:
                print(f"代理设置失败，使用直连: {e}")
        
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
        
        proxy_msg = f" (通过代理: {proxy_info['name']})" if proxy_info else " (直连)"
        return jsonify({"result": f"连接成功{proxy_msg}"})
    except Exception as e:
        return jsonify({"result": f"连接失败：{str(e)}"})
    finally:
        # 重置socket以避免影响其他连接
        try:
            import socket
            import socks
            socket.socket = socks.socksocket.__bases__[0]
        except:
            pass

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

# 新增：代理池管理
@app.route("/proxies", methods=["GET"])
def get_proxies():
    if not session.get('logged_in'):
        return jsonify([])
    return jsonify(load_proxies())

@app.route("/proxies", methods=["POST"])
def add_proxy():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        data = request.get_json()
        proxy_type = data.get("type", "").upper()
        host = data.get("host", "").strip()
        port = data.get("port")
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        name = data.get("name", "").strip()
        
        if not (proxy_type and host and port):
            return jsonify({"success": False, "error": "请填写完整的代理信息"})
        
        if proxy_type not in ["HTTP", "HTTPS", "SOCKS4", "SOCKS5"]:
            return jsonify({"success": False, "error": "不支持的代理类型"})
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("端口范围无效")
        except ValueError:
            return jsonify({"success": False, "error": "端口必须是1-65535之间的数字"})
        
        proxies = load_proxies()
        
        # 检查是否已存在相同的代理
        for proxy in proxies:
            if proxy["host"] == host and proxy["port"] == port:
                return jsonify({"success": False, "error": "该代理已存在"})
        
        new_proxy = {
            "id": len(proxies) + 1,
            "name": name or f"{proxy_type}://{host}:{port}",
            "type": proxy_type,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "status": "active",
            "created_at": __import__('datetime').datetime.now().isoformat()
        }
        
        proxies.append(new_proxy)
        save_proxies(proxies)
        return jsonify({"success": True, "message": "代理添加成功"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/proxies/<int:proxy_id>", methods=["DELETE"])
def delete_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxies = load_proxies()
        proxies = [p for p in proxies if p["id"] != proxy_id]
        save_proxies(proxies)
        return jsonify({"success": True, "message": "代理删除成功"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/proxies/<int:proxy_id>/test", methods=["POST"])
def test_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxies = load_proxies()
        proxy = next((p for p in proxies if p["id"] == proxy_id), None)
        if not proxy:
            return jsonify({"success": False, "error": "代理不存在"})
        
        # 简单的代理连接测试
        import socket
        import time
        start_time = time.time()
        
        try:
            if proxy["type"] in ["HTTP", "HTTPS"]:
                # HTTP代理测试
                import urllib.request
                proxy_handler = urllib.request.ProxyHandler({
                    'http': f'http://{proxy["host"]}:{proxy["port"]}',
                    'https': f'http://{proxy["host"]}:{proxy["port"]}'
                })
                opener = urllib.request.build_opener(proxy_handler)
                urllib.request.install_opener(opener)
                response = urllib.request.urlopen('http://httpbin.org/ip', timeout=10)
                response.read()
            else:
                # SOCKS代理测试 - 简单的socket连接测试
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((proxy["host"], proxy["port"]))
                sock.close()
            
            response_time = round((time.time() - start_time) * 1000, 2)
            return jsonify({"success": True, "message": f"代理连接成功 ({response_time}ms)"})
        except Exception as e:
            return jsonify({"success": False, "error": f"代理连接失败: {str(e)}"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/proxies/batch_delete", methods=["POST"])
def batch_delete_proxies():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxy_ids = request.json.get("ids", [])
        proxies = load_proxies()
        proxies = [p for p in proxies if p["id"] not in proxy_ids]
        save_proxies(proxies)
        return jsonify({"success": True, "message": "批量删除成功"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# 新增：系统设置相关路由
@app.route("/upload_logo", methods=["POST"])
def upload_logo():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    if 'logo' not in request.files:
        return jsonify({"success": False, "error": "没有选择文件"})
    
    file = request.files['logo']
    if file.filename == '':
        return jsonify({"success": False, "error": "没有选择文件"})
    
    # 检查文件类型
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({"success": False, "error": "只支持PNG、JPG、JPEG、GIF、SVG格式的图片"})
    
    try:
        # 保存文件为 logo.png (覆盖原有文件)
        filename = "logo.png"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # 确保上传目录存在
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        file.save(file_path)
        return jsonify({"success": True, "message": "Logo上传成功"})
    except Exception as e:
        return jsonify({"success": False, "error": f"上传失败：{str(e)}"})

@app.route("/get_logo")
def get_logo():
    """获取当前logo文件"""
    logo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'logo.png')
    if os.path.exists(logo_path):
        return send_from_directory(app.config['UPLOAD_FOLDER'], 'logo.png')
    else:
        # 如果没有上传的logo，返回默认的placeholder
        return send_from_directory('static', 'logo.png')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
