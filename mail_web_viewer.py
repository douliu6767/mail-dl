import json
import re
import os
import secrets
import uuid
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
from models import db, AdminUser, EmailAccount, Proxy, Card, EmailLog, CardLog
from datetime import datetime, timedelta
from sqlalchemy import and_, or_

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
        
        # Migrate data from JSON files to database if needed
        migrate_json_to_db()

def migrate_json_to_db():
    """Migrate existing JSON data to database"""
    accounts_file = "accounts.json"
    proxies_file = "proxies.json"
    
    # Migrate accounts
    if os.path.exists(accounts_file) and EmailAccount.query.count() == 0:
        try:
            with open(accounts_file, encoding="utf-8") as f:
                accounts_data = json.load(f)
            
            for account_data in accounts_data:
                account = EmailAccount(
                    name=account_data.get('name', ''),
                    host=account_data['host'],
                    user=account_data['user'],
                    password=account_data['password'],
                    protocol=account_data.get('protocol', 'IMAP'),
                    port=account_data.get('port', 993 if account_data.get('ssl', True) else 143),
                    ssl=account_data.get('ssl', True)
                )
                db.session.add(account)
            
            db.session.commit()
            print("Migrated accounts from JSON to database")
        except Exception as e:
            print(f"Error migrating accounts: {e}")
            db.session.rollback()
    
    # Migrate proxies
    if os.path.exists(proxies_file) and Proxy.query.count() == 0:
        try:
            with open(proxies_file, encoding="utf-8") as f:
                proxies_data = json.load(f)
            
            for proxy_data in proxies_data:
                proxy = Proxy(
                    name=proxy_data.get('name', ''),
                    type=proxy_data['type'],
                    host=proxy_data['host'],
                    port=proxy_data['port'],
                    username=proxy_data.get('username', ''),
                    password=proxy_data.get('password', ''),
                    status=proxy_data.get('status', 'active')
                )
                db.session.add(proxy)
            
            db.session.commit()
            print("Migrated proxies from JSON to database")
        except Exception as e:
            print(f"Error migrating proxies: {e}")
            db.session.rollback()

init_admin()

ACCOUNTS_FILE = "accounts.json"
PROXIES_FILE = "proxies.json"
CODE_REGEX = r"\b(\d{6})\b"

def load_accounts():
    """Load accounts from database"""
    accounts = EmailAccount.query.all()
    return [account.to_dict() for account in accounts]

def save_accounts(accounts):
    """Deprecated - accounts are now managed through database"""
    pass

def load_proxies():
    """Load proxies from database"""
    proxies = Proxy.query.filter_by(status='active').all()
    return [proxy.to_dict() for proxy in proxies]

def save_proxies(proxies):
    """Deprecated - proxies are now managed through database"""
    pass

def get_proxy_for_connection():
    """获取一个可用的代理进行连接"""
    proxies = Proxy.query.filter_by(status='active').all()
    if proxies:
        # 简单轮询选择，可以后续优化为更智能的选择策略
        import random
        return random.choice(proxies).to_dict()
    return None

def test_proxy_connection(proxy_info):
    """测试代理连接是否可用"""
    if not proxy_info:
        return False
    
    try:
        # 根据代理类型进行不同的测试
        if proxy_info["type"] in ["HTTP", "HTTPS"]:
            import urllib.request
            import socket
            
            proxy_handler = urllib.request.ProxyHandler({
                'http': f'http://{proxy_info["host"]}:{proxy_info["port"]}',
                'https': f'http://{proxy_info["host"]}:{proxy_info["port"]}'
            })
            opener = urllib.request.build_opener(proxy_handler)
            opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
            
            # 简单的连接测试
            response = opener.open('http://httpbin.org/ip', timeout=10)
            return response.getcode() == 200
            
        elif proxy_info["type"] == "SOCKS5":
            import socks
            import socket
            
            # 创建SOCKS5代理测试
            sock = socks.socksocket()
            if proxy_info.get("username") and proxy_info.get("password"):
                sock.set_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"], 
                             username=proxy_info["username"], password=proxy_info["password"])
            else:
                sock.set_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"])
            
            # 测试连接到一个外部服务
            sock.settimeout(10)
            sock.connect(("8.8.8.8", 53))  # 连接到Google DNS
            sock.close()
            return True
            
    except Exception as e:
        print(f"代理测试失败: {e}")
        return False
    
    return False

def get_available_proxy():
    """获取一个经过测试的可用代理"""
    proxies = Proxy.query.filter_by(status='active').all()
    
    for proxy in proxies:
        proxy_dict = proxy.to_dict()
        if test_proxy_connection(proxy_dict):
            return proxy_dict
    
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
    accounts = EmailAccount.query.all()
    return render_template("index.html", accounts=[a.user for a in accounts])

@app.route("/getmail", methods=["POST"])
def getmail():
    user = request.form.get("user")
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    # Find account in database
    account = EmailAccount.query.filter_by(user=user).first()
    if not account:
        return jsonify({"error": "邮箱不存在，获取失败"})
    
    # 强制要求使用代理池中的代理
    proxy_info = get_available_proxy()
    if not proxy_info:
        return jsonify({"error": "暂无可用代理，请添加代理后再试"})
    
    email_log = EmailLog(
        email_account_id=account.id,
        ip_address=client_ip,
        user_agent=user_agent,
        success=False
    )
    
    try:
        # 获取协议、端口和SSL设置
        protocol = account.protocol
        port = account.port
        ssl = account.ssl
        host = account.host
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            import email
            
            # 尝试使用代理连接
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
                elif proxy_info["type"] == "HTTP":
                    return jsonify({"error": "HTTP代理暂不支持IMAP连接，请使用SOCKS5代理"})
                
                socket.socket = socks.socksocket
            except ImportError:
                return jsonify({"error": "缺少 PySocks 模块，请安装后重试"})
            except Exception as e:
                return jsonify({"error": f"代理设置失败: {str(e)}"})
            
            with IMAPClient(host, port=port, ssl=ssl) as server:
                server.login(account.user, account.password)
                server.select_folder("INBOX")
                messages = server.search('ALL')
                if not messages:
                    email_log.success = True
                    email_log.error_message = "邮箱为空"
                    db.session.add(email_log)
                    db.session.commit()
                    return jsonify({"subject": "无邮件", "body": "邮箱为空。"})
                
                latest_uid = messages[-1]
                raw_message = server.fetch([latest_uid], ['RFC822'])[latest_uid][b'RFC822']
                msg = email.message_from_bytes(raw_message)
                subject = email.header.make_header(email.header.decode_header(msg.get("Subject", "")))
                sender = msg.get("From", "")
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
                
                # 记录成功的邮件日志
                email_log.sender = sender
                email_log.subject = str(subject)
                email_log.body_preview = body[:500] + "..." if len(body) > 500 else body
                email_log.verification_code = code
                email_log.success = True
                db.session.add(email_log)
                db.session.commit()
                
                return jsonify({"subject": str(subject), "body": body, "code": code})
        else:  # POP3
            import poplib
            import email
            
            # 尝试使用代理连接
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
                elif proxy_info["type"] == "HTTP":
                    return jsonify({"error": "HTTP代理暂不支持POP3连接，请使用SOCKS5代理"})
                
                socket.socket = socks.socksocket
            except ImportError:
                return jsonify({"error": "缺少 PySocks 模块，请安装后重试"})
            except Exception as e:
                return jsonify({"error": f"代理设置失败: {str(e)}"})
            
            if ssl:
                server = poplib.POP3_SSL(host, port)
            else:
                server = poplib.POP3(host, port)
            server.user(account.user)
            server.pass_(account.password)
            
            # 获取邮件数量
            num_messages = len(server.list()[1])
            if num_messages == 0:
                server.quit()
                email_log.success = True
                email_log.error_message = "邮箱为空"
                db.session.add(email_log)
                db.session.commit()
                return jsonify({"subject": "无邮件", "body": "邮箱为空。"})
            
            # 获取最新邮件
            raw_message = b"\n".join(server.retr(num_messages)[1])
            server.quit()
            
            msg = email.message_from_bytes(raw_message)
            subject = email.header.make_header(email.header.decode_header(msg.get("Subject", "")))
            sender = msg.get("From", "")
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
            
            # 记录成功的邮件日志
            email_log.sender = sender
            email_log.subject = str(subject)
            email_log.body_preview = body[:500] + "..." if len(body) > 500 else body
            email_log.verification_code = code
            email_log.success = True
            db.session.add(email_log)
            db.session.commit()
            
            return jsonify({"subject": str(subject), "body": body, "code": code})
            
    except Exception as e:
        error_msg = str(e)
        email_log.error_message = error_msg
        db.session.add(email_log)
        db.session.commit()
        return jsonify({"error": error_msg})
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
    
    # Get the active section from request
    active_section = request.args.get('section', 'dashboard')
    
    if request.method == "POST":
        name = request.form.get("name", "")
        host = request.form.get("host", "")
        user = request.form.get("user", "")
        password = request.form.get("password", "")
        protocol = request.form.get("protocol", "IMAP")
        port = request.form.get("port", "")
        ssl = request.form.get("ssl") == "on"
        
        if not (host and user and password):
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 error="请填写完整信息", username=session.get('username'), 
                                 active_section='email-management')
        
        # 如果端口为空，根据协议和SSL设置默认端口
        if not port:
            if protocol == "IMAP":
                port = "993" if ssl else "143"
            else:  # POP3
                port = "995" if ssl else "110"
        
        # 检查账号是否已存在
        if EmailAccount.query.filter_by(user=user).first():
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 error="该账号已存在", username=session.get('username'),
                                 active_section='email-management')
        
        # 创建新账号
        try:
            new_account = EmailAccount(
                name=name,
                host=host,
                user=user,
                password=password,
                protocol=protocol,
                port=int(port) if port.isdigit() else int(port),
                ssl=ssl
            )
            db.session.add(new_account)
            db.session.commit()
            
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 success="账号添加成功！", username=session.get('username'),
                                 active_section='email-management')
        except Exception as e:
            db.session.rollback()
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 error=f"添加失败: {str(e)}", username=session.get('username'),
                                 active_section='email-management')
    
    return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                         username=session.get('username'), active_section=active_section)

@app.route("/del_account", methods=["POST"])
def del_account():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user = request.form.get("user")
    redirect_section = request.form.get("redirect_section", "email-management")
    
    try:
        account = EmailAccount.query.filter_by(user=user).first()
        if account:
            db.session.delete(account)
            db.session.commit()
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 success="账号删除成功！", username=session.get('username'),
                                 active_section=redirect_section)
        else:
            return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                                 error="账号不存在", username=session.get('username'),
                                 active_section=redirect_section)
    except Exception as e:
        db.session.rollback()
        return render_template("admin.html", accounts=load_accounts(), proxies=load_proxies(), 
                             error=f"删除失败: {str(e)}", username=session.get('username'),
                             active_section=redirect_section)

# 新增：编辑账号
@app.route("/edit_account", methods=["POST"])
def edit_account():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        account_id = request.form.get("account_id")
        account = EmailAccount.query.get(account_id)
        if not account:
            return jsonify({"success": False, "error": "账号不存在"})
        
        # 更新账号信息
        account.name = request.form.get("name", account.name)
        account.host = request.form.get("host", account.host)
        account.user = request.form.get("user", account.user)
        account.password = request.form.get("password", account.password)
        account.protocol = request.form.get("protocol", account.protocol)
        account.port = int(request.form.get("port", account.port))
        account.ssl = request.form.get("ssl") == "on"
        account.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({"success": True, "message": "账号更新成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

# 新增：测试账号连接
@app.route("/test_account", methods=["POST"])
def test_account():
    if not session.get('logged_in'):
        return jsonify({"result": "未登录"})
    
    user = request.form.get("user")
    account = EmailAccount.query.filter_by(user=user).first()
    if not account:
        return jsonify({"result": "账号不存在"})
    
    # 强制要求使用代理池中的代理
    proxy_info = get_available_proxy()
    if not proxy_info:
        return jsonify({"result": "暂无可用代理，请添加代理后再试"})
    
    try:
        # 获取协议、端口和SSL设置
        protocol = account.protocol
        port = account.port
        ssl = account.ssl
        host = account.host
        
        # 尝试使用代理连接
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
            elif proxy_info["type"] == "HTTP":
                return jsonify({"result": "HTTP代理暂不支持邮箱连接测试，请使用SOCKS5代理"})
            
            socket.socket = socks.socksocket
        except ImportError:
            return jsonify({"result": "缺少 PySocks 模块，请安装后重试"})
        except Exception as e:
            return jsonify({"result": f"代理设置失败: {str(e)}"})
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            with IMAPClient(host, port=port, ssl=ssl) as server:
                server.login(account.user, account.password)
        else:  # POP3
            import poplib
            if ssl:
                server = poplib.POP3_SSL(host, port)
            else:
                server = poplib.POP3(host, port)
            server.user(account.user)
            server.pass_(account.password)
            server.quit()
        
        proxy_msg = f" (通过代理: {proxy_info['name']})" if proxy_info else ""
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
        # Delete from database
        EmailAccount.query.filter(EmailAccount.user.in_(users)).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({"success": True, "message": "批量删除成功"})
    except Exception as e:
        db.session.rollback()
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
        
        # 限制代理类型为 HTTP 和 SOCKS5
        if proxy_type not in ["HTTP", "SOCKS5"]:
            return jsonify({"success": False, "error": "仅支持 HTTP 和 SOCKS5 类型的代理"})
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("端口范围无效")
        except ValueError:
            return jsonify({"success": False, "error": "端口必须是1-65535之间的数字"})
        
        # 检查是否已存在相同的代理
        existing_proxy = Proxy.query.filter_by(host=host, port=port).first()
        if existing_proxy:
            return jsonify({"success": False, "error": "该代理已存在"})
        
        new_proxy = Proxy(
            name=name or f"{proxy_type}://{host}:{port}",
            type=proxy_type,
            host=host,
            port=port,
            username=username,
            password=password,
            status="active"
        )
        
        db.session.add(new_proxy)
        db.session.commit()
        return jsonify({"success": True, "message": "代理添加成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

# 新增：编辑代理
@app.route("/proxies/<int:proxy_id>", methods=["PUT"])
def edit_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxy = Proxy.query.get(proxy_id)
        if not proxy:
            return jsonify({"success": False, "error": "代理不存在"})
        
        data = request.get_json()
        proxy_type = data.get("type", "").upper()
        host = data.get("host", "").strip()
        port = data.get("port")
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        name = data.get("name", "").strip()
        
        if not (proxy_type and host and port):
            return jsonify({"success": False, "error": "请填写完整的代理信息"})
        
        # 限制代理类型为 HTTP 和 SOCKS5
        if proxy_type not in ["HTTP", "SOCKS5"]:
            return jsonify({"success": False, "error": "仅支持 HTTP 和 SOCKS5 类型的代理"})
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("端口范围无效")
        except ValueError:
            return jsonify({"success": False, "error": "端口必须是1-65535之间的数字"})
        
        # 检查是否与其他代理冲突（排除自己）
        existing_proxy = Proxy.query.filter(
            and_(Proxy.host == host, Proxy.port == port, Proxy.id != proxy_id)
        ).first()
        if existing_proxy:
            return jsonify({"success": False, "error": "该代理地址已被其他代理使用"})
        
        # 更新代理信息
        proxy.name = name or f"{proxy_type}://{host}:{port}"
        proxy.type = proxy_type
        proxy.host = host
        proxy.port = port
        proxy.username = username
        proxy.password = password
        proxy.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({"success": True, "message": "代理更新成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

@app.route("/proxies/update", methods=["POST"])
def update_proxy_form():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxy_id = request.form.get('proxy_id')
        proxy = Proxy.query.get(proxy_id)
        if not proxy:
            return jsonify({"success": False, "error": "代理不存在"})
        
        proxy_type = request.form.get('type', '').upper()
        if proxy_type not in ["HTTP", "SOCKS5"]:
            return jsonify({"success": False, "error": "仅支持 HTTP 和 SOCKS5 类型的代理"})
        
        host = request.form.get('host', '').strip()
        port = request.form.get('port')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        name = request.form.get('name', '').strip()
        status = request.form.get('status', 'active')
        
        if not (proxy_type and host and port):
            return jsonify({"success": False, "error": "请填写完整的代理信息"})
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("端口范围无效")
        except ValueError:
            return jsonify({"success": False, "error": "端口必须是1-65535之间的数字"})
        
        # 检查是否与其他代理冲突（排除自己）
        existing_proxy = Proxy.query.filter(
            and_(Proxy.host == host, Proxy.port == port, Proxy.id != proxy_id)
        ).first()
        if existing_proxy:
            return jsonify({"success": False, "error": "该代理地址已被其他代理使用"})
        
        # 更新代理信息
        proxy.name = name or f"{proxy_type}://{host}:{port}"
        proxy.type = proxy_type
        proxy.host = host
        proxy.port = port
        proxy.username = username
        proxy.password = password
        proxy.status = status
        proxy.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({"success": True, "message": "代理更新成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"更新失败：{str(e)}"})

@app.route("/proxies/<int:proxy_id>", methods=["DELETE"])
def delete_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxy = Proxy.query.get(proxy_id)
        if not proxy:
            return jsonify({"success": False, "error": "代理不存在"})
        
        db.session.delete(proxy)
        db.session.commit()
        return jsonify({"success": True, "message": "代理删除成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

@app.route("/proxies/<int:proxy_id>/test", methods=["POST"])
def test_proxy(proxy_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxy = Proxy.query.get(proxy_id)
        if not proxy:
            return jsonify({"success": False, "error": "代理不存在"})
        
        proxy_dict = proxy.to_dict()
        if test_proxy_connection(proxy_dict):
            return jsonify({"success": True, "message": "代理连接成功"})
        else:
            return jsonify({"success": False, "error": "代理连接失败"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/proxies/batch_delete", methods=["POST"])
def batch_delete_proxies():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    try:
        proxy_ids = request.json.get("ids", [])
        Proxy.query.filter(Proxy.id.in_(proxy_ids)).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({"success": True, "message": "批量删除成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

# 卡密管理功能
# Card management routes
@app.route("/cards", methods=["GET"])
def list_cards():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    search = request.args.get('search', '')
    status = request.args.get('status', '')
    
    query = Card.query
    
    if search:
        query = query.filter(
            or_(Card.code.like(f'%{search}%'), Card.name.like(f'%{search}%'))
        )
    
    if status:
        query = query.filter(Card.status == status)
    
    cards = query.order_by(Card.created_at.desc()).all()
    return jsonify({"success": True, "cards": [card.to_dict() for card in cards]})

@app.route("/cards", methods=["POST"])
def add_card():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        code = request.form.get('code')
        name = request.form.get('name', '')
        usage_limit = int(request.form.get('usage_limit', 1))
        expires_at = request.form.get('expires_at')
        
        if not code:
            return jsonify({"success": False, "error": "卡密编号不能为空"})
        
        # Check if card already exists
        if Card.query.filter_by(code=code).first():
            return jsonify({"success": False, "error": "该卡密编号已存在"})
        
        # Parse expiration date
        expires_at_date = None
        if expires_at:
            try:
                from datetime import datetime
                expires_at_date = datetime.fromisoformat(expires_at)
            except ValueError:
                return jsonify({"success": False, "error": "过期时间格式错误"})
        
        # Generate access link
        import uuid
        access_link = f"/card_access/{uuid.uuid4().hex}"
        
        new_card = Card(
            code=code,
            name=name,
            usage_limit=usage_limit,
            expires_at=expires_at_date,
            access_link=access_link
        )
        
        db.session.add(new_card)
        db.session.commit()
        
        return jsonify({"success": True, "message": "卡密添加成功", "card": new_card.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"添加失败：{str(e)}"})

@app.route("/cards/update", methods=["POST"])
def update_card():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        card_id = request.form.get('card_id')
        card = Card.query.get(card_id)
        if not card:
            return jsonify({"success": False, "error": "卡密不存在"})
        
        card.code = request.form.get('code', card.code)
        card.name = request.form.get('name', card.name)
        card.usage_limit = int(request.form.get('usage_limit', card.usage_limit))
        card.status = request.form.get('status', card.status)
        
        expires_at = request.form.get('expires_at')
        if expires_at:
            try:
                from datetime import datetime
                card.expires_at = datetime.fromisoformat(expires_at)
            except ValueError:
                return jsonify({"success": False, "error": "过期时间格式错误"})
        else:
            card.expires_at = None
        
        card.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"success": True, "message": "卡密更新成功", "card": card.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"更新失败：{str(e)}"})

@app.route("/cards/<int:card_id>", methods=["PUT"])
def update_card_route():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        card_id = request.form.get('card_id')
        card = Card.query.get(card_id)
        if not card:
            return jsonify({"success": False, "error": "卡密不存在"})
        
        card.code = request.form.get('code', card.code)
        card.name = request.form.get('name', card.name)
        card.usage_limit = int(request.form.get('usage_limit', card.usage_limit))
        card.status = request.form.get('status', card.status)
        
        expires_at = request.form.get('expires_at')
        if expires_at:
            try:
                from datetime import datetime
                card.expires_at = datetime.fromisoformat(expires_at)
            except ValueError:
                return jsonify({"success": False, "error": "过期时间格式错误"})
        else:
            card.expires_at = None
        
        card.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"success": True, "message": "卡密更新成功", "card": card.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"更新失败：{str(e)}"})

@app.route("/cards/<int:card_id>", methods=["DELETE"])
def delete_card(card_id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        card = Card.query.get(card_id)
        if not card:
            return jsonify({"success": False, "error": "卡密不存在"})
        
        db.session.delete(card)
        db.session.commit()
        
        return jsonify({"success": True, "message": "卡密删除成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"删除失败：{str(e)}"})

@app.route("/cards/batch_delete", methods=["POST"])
def batch_delete_cards():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        card_ids = request.json.get("ids", [])
        Card.query.filter(Card.id.in_(card_ids)).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({"success": True, "message": "批量删除成功"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})

@app.route("/cards/import", methods=["POST"])
def import_cards():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    try:
        cards_text = request.form.get('cards_text', '')
        if not cards_text:
            return jsonify({"success": False, "error": "没有提供卡密数据"})
        
        lines = cards_text.strip().split('\n')
        added_count = 0
        errors = []
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(',')
            if len(parts) < 1:
                errors.append(f"第{line_num}行格式错误")
                continue
            
            code = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 else ''
            usage_limit = int(parts[2].strip()) if len(parts) > 2 and parts[2].strip().isdigit() else 1
            expires_at = None
            
            if len(parts) > 3 and parts[3].strip():
                try:
                    from datetime import datetime
                    expires_at = datetime.fromisoformat(parts[3].strip())
                except ValueError:
                    errors.append(f"第{line_num}行过期时间格式错误")
                    continue
            
            # Check if card already exists
            if Card.query.filter_by(code=code).first():
                errors.append(f"第{line_num}行卡密编号已存在: {code}")
                continue
            
            # Generate access link
            import uuid
            access_link = f"/card_access/{uuid.uuid4().hex}"
            
            new_card = Card(
                code=code,
                name=name,
                usage_limit=usage_limit,
                expires_at=expires_at,
                access_link=access_link
            )
            
            db.session.add(new_card)
            added_count += 1
        
        db.session.commit()
        
        result_message = f"成功导入 {added_count} 个卡密"
        if errors:
            result_message += f"，{len(errors)} 个错误：" + "; ".join(errors[:5])
            if len(errors) > 5:
                result_message += "..."
        
        return jsonify({"success": True, "message": result_message})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"导入失败：{str(e)}"})

@app.route("/cards/export", methods=["GET"])
def export_cards():
    if not session.get('logged_in'):
        return jsonify([])
    
    cards = Card.query.all()
    export_data = []
    for card in cards:
        export_data.append({
            'code': card.code,
            'name': card.name,
            'usage_limit': card.usage_limit,
            'usage_count': card.usage_count,
            'status': card.status,
            'expires_at': card.expires_at.isoformat() if card.expires_at else '',
            'access_link': card.access_link,
            'created_at': card.created_at.isoformat() if card.created_at else ''
        })
    
    return jsonify(export_data)

# Email and Card logging routes
@app.route("/email_logs", methods=["GET"])
def get_email_logs():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    email_search = request.args.get('email', '')
    card_search = request.args.get('card', '')
    date_filter = request.args.get('date', '')
    success_filter = request.args.get('success', '')
    
    query = EmailLog.query
    
    if email_search:
        query = query.join(EmailAccount).filter(EmailAccount.user.like(f'%{email_search}%'))
    
    if card_search:
        query = query.join(Card).filter(Card.code.like(f'%{card_search}%'))
    
    if date_filter:
        try:
            from datetime import datetime, date
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(db.func.date(EmailLog.created_at) == filter_date)
        except ValueError:
            pass
    
    if success_filter:
        query = query.filter(EmailLog.success == (success_filter.lower() == 'true'))
    
    logs = query.order_by(EmailLog.created_at.desc()).limit(1000).all()
    
    result = []
    for log in logs:
        log_dict = log.to_dict()
        if log.email_account:
            log_dict['email_account_user'] = log.email_account.user
        if log.card:
            log_dict['card_code'] = log.card.code
        result.append(log_dict)
    
    return jsonify({"success": True, "logs": result})

@app.route("/card_logs", methods=["GET"])
def get_card_logs():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    
    card_search = request.args.get('card', '')
    ip_search = request.args.get('ip', '')
    date_filter = request.args.get('date', '')
    action_filter = request.args.get('action', '')
    
    query = CardLog.query
    
    if card_search:
        query = query.filter(CardLog.card_code.like(f'%{card_search}%'))
    
    if ip_search:
        query = query.filter(CardLog.ip_address.like(f'%{ip_search}%'))
    
    if date_filter:
        try:
            from datetime import datetime, date
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            query = query.filter(db.func.date(CardLog.created_at) == filter_date)
        except ValueError:
            pass
    
    if action_filter:
        query = query.filter(CardLog.action == action_filter)
    
    logs = query.order_by(CardLog.created_at.desc()).limit(1000).all()
    return jsonify({"success": True, "logs": [log.to_dict() for log in logs]})

# Card access routes for frontend users
@app.route("/card_access/<access_token>", methods=["GET", "POST"])
def card_access(access_token):
    access_link = f"/card_access/{access_token}"
    card = Card.query.filter_by(access_link=access_link).first()
    
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    # Log the access attempt
    if card:
        card_log = CardLog(
            card_id=card.id,
            card_code=card.code,
            ip_address=client_ip,
            user_agent=user_agent,
            action='access',
            success=True
        )
        db.session.add(card_log)
    else:
        # Log failed access attempt
        card_log = CardLog(
            card_id=None,
            card_code='Unknown',
            ip_address=client_ip,
            user_agent=user_agent,
            action='access',
            success=False,
            error_message='Invalid access token'
        )
        db.session.add(card_log)
        db.session.commit()
        return render_template('card_error.html', error="无效的访问链接")
    
    # Check card validity
    if card.status != 'active':
        card_log.success = False
        card_log.error_message = f'Card status: {card.status}'
        db.session.commit()
        if card.status == 'used_up':
            return render_template('card_error.html', error="卡密已用完")
        elif card.status == 'expired':
            return render_template('card_error.html', error="卡密已过期")
        else:
            return render_template('card_error.html', error="卡密不可用")
    
    # Check if card is expired
    from datetime import datetime
    if card.expires_at and datetime.utcnow() > card.expires_at:
        card.status = 'expired'
        card_log.success = False
        card_log.error_message = 'Card expired'
        db.session.commit()
        return render_template('card_error.html', error="卡密已过期")
    
    # Check usage limit
    if card.usage_count >= card.usage_limit:
        card.status = 'used_up'
        card_log.success = False
        card_log.error_message = 'Usage limit exceeded'
        db.session.commit()
        return render_template('card_error.html', error="卡密已用完")
    
    db.session.commit()
    
    if request.method == 'POST':
        email_user = request.form.get('user')
        if not email_user:
            return render_template('card_access.html', card=card, error="请输入邮箱地址")
        
        # Find email account
        account = EmailAccount.query.filter_by(user=email_user).first()
        if not account:
            # Log failed attempt but don't deduct usage
            email_log = EmailLog(
                email_account_id=None,
                card_id=card.id,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                error_message="邮箱不存在，获取失败"
            )
            db.session.add(email_log)
            
            card_log = CardLog(
                card_id=card.id,
                card_code=card.code,
                ip_address=client_ip,
                user_agent=user_agent,
                action='use',
                success=False,
                error_message="邮箱不存在"
            )
            db.session.add(card_log)
            db.session.commit()
            
            return render_template('card_access.html', card=card, error="邮箱不存在，获取失败")
        
        # Check proxy availability
        proxy_info = get_available_proxy()
        if not proxy_info:
            # Log failed attempt but don't deduct usage
            email_log = EmailLog(
                email_account_id=account.id,
                card_id=card.id,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                error_message="暂无可用代理"
            )
            db.session.add(email_log)
            db.session.commit()
            
            return render_template('card_access.html', card=card, error="暂无可用代理，请稍后再试")
        
        # Attempt to get email (same logic as getmail route but with card validation)
        try:
            # Get email content using the same logic as in getmail route
            result = get_email_content(account, proxy_info)
            
            if 'error' in result:
                # Log failed attempt but don't deduct usage
                email_log = EmailLog(
                    email_account_id=account.id,
                    card_id=card.id,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    success=False,
                    error_message=result['error']
                )
                db.session.add(email_log)
                db.session.commit()
                
                return render_template('card_access.html', card=card, error=result['error'])
            else:
                # Success - deduct usage and log
                card.usage_count += 1
                if card.usage_count >= card.usage_limit:
                    card.status = 'used_up'
                
                email_log = EmailLog(
                    email_account_id=account.id,
                    card_id=card.id,
                    sender=result.get('sender', ''),
                    subject=result.get('subject', ''),
                    body_preview=result.get('body', '')[:500],
                    verification_code=result.get('code', ''),
                    ip_address=client_ip,
                    user_agent=user_agent,
                    success=True
                )
                db.session.add(email_log)
                
                card_log = CardLog(
                    card_id=card.id,
                    card_code=card.code,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    action='use',
                    success=True
                )
                db.session.add(card_log)
                
                db.session.commit()
                
                return render_template('card_access.html', card=card, 
                                     subject=result['subject'], body=result['body'], 
                                     code=result.get('code'), success=True)
        
        except Exception as e:
            # Log failed attempt but don't deduct usage
            email_log = EmailLog(
                email_account_id=account.id,
                card_id=card.id,
                ip_address=client_ip,
                user_agent=user_agent,
                success=False,
                error_message=str(e)
            )
            db.session.add(email_log)
            db.session.commit()
            
            return render_template('card_access.html', card=card, error=f"获取邮件失败: {str(e)}")
    
    # GET request - show the card access form
    return render_template('card_access.html', card=card)

def get_email_content(account, proxy_info):
    """Extract email getting logic into a separate function"""
    try:
        # Same email retrieval logic as in getmail route
        protocol = account.protocol
        port = account.port
        ssl = account.ssl
        host = account.host
        
        if protocol == "IMAP":
            from imapclient import IMAPClient
            import email
            
            # Set up proxy
            try:
                import socks
                import socket
                if proxy_info["type"] == "SOCKS5":
                    if proxy_info.get("username") and proxy_info.get("password"):
                        socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"], 
                                              username=proxy_info["username"], password=proxy_info["password"])
                    else:
                        socks.set_default_proxy(socks.SOCKS5, proxy_info["host"], proxy_info["port"])
                elif proxy_info["type"] == "HTTP":
                    return {"error": "HTTP代理暂不支持IMAP连接，请使用SOCKS5代理"}
                
                socket.socket = socks.socksocket
            except ImportError:
                return {"error": "缺少 PySocks 模块，请安装后重试"}
            except Exception as e:
                return {"error": f"代理设置失败: {str(e)}"}
            
            with IMAPClient(host, port=port, ssl=ssl) as server:
                server.login(account.user, account.password)
                server.select_folder("INBOX")
                messages = server.search('ALL')
                if not messages:
                    return {"subject": "无邮件", "body": "邮箱为空。"}
                
                latest_uid = messages[-1]
                raw_message = server.fetch([latest_uid], ['RFC822'])[latest_uid][b'RFC822']
                msg = email.message_from_bytes(raw_message)
                subject = email.header.make_header(email.header.decode_header(msg.get("Subject", "")))
                sender = msg.get("From", "")
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
                
                return {
                    "subject": str(subject),
                    "body": body,
                    "sender": sender,
                    "code": code
                }
        else:
            # POP3 implementation would go here
            return {"error": "POP3 protocol not yet supported for card access"}
    
    except Exception as e:
        return {"error": f"邮件获取失败: {str(e)}"}
    finally:
        # Reset socket
        try:
            import socket
            import socks
            socket.socket = socks.socksocket.__bases__[0]
        except:
            pass

@app.route("/get_logo")
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
    app.run(host="0.0.0.0", port=5000, debug=True)
