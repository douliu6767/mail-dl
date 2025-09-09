import os
import uuid
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
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

@app.route("/")
def index():
    return redirect(url_for('admin'))

@app.route("/admin", methods=["GET"])
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    # 筛选参数
    search_email = request.args.get('search_email', '')
    search_project = request.args.get('search_project', '')
    search_tag = request.args.get('search_tag', '')
    search_protocol = request.args.get('search_protocol', '')
    search_status = request.args.get('search_status', '')
    # 基础查询
    query = MailAccount.query
    if search_email:
        query = query.filter(MailAccount.email.contains(search_email))
    if search_project:
        query = query.filter(MailAccount.project.contains(search_project))
    if search_tag:
        query = query.filter(MailAccount.tags.contains(search_tag))
    if search_protocol:
        query = query.filter(MailAccount.protocol == search_protocol)
    if search_status:
        query = query.filter(MailAccount.status == search_status)
    accounts = query.all()
    return render_template("admin.html", accounts=accounts, username=session.get('username'))

@app.route("/login", methods=['GET', 'POST'])
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

@app.route("/account/add", methods=['POST'])
def add_account():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    data = request.form
    email = data.get('email', '').strip()
    if not email:
        return jsonify({"success": False, "error": "邮箱不能为空"})
    if MailAccount.query.filter_by(email=email).first():
        return jsonify({"success": False, "error": "邮箱已存在"})
    acc = MailAccount(
        id=str(uuid.uuid4()),
        email=email,
        password=data.get('password', ''),
        project=data.get('project', ''),
        tags=data.get('tags', ''),
        protocol=data.get('protocol', ''),
        login_status=data.get('login_status', ''),
        result_desc=data.get('result_desc', ''),
        use_proxy=data.get('use_proxy', ''),
        proxy_addr=data.get('proxy_addr', ''),
        proxy_type=data.get('proxy_type', ''),
        source=data.get('source', ''),
        status=data.get('status', ''),
        use_times=data.get('use_times', ''),
        expire_time=data.get('expire_time', ''),
        remark=data.get('remark', ''),
        app_id=data.get('app_id', ''),
        flag=data.get('flag', '')
    )
    db.session.add(acc)
    db.session.commit()
    return jsonify({"success": True})

@app.route("/account/<id>/update", methods=['POST'])
def update_account(id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    acc = MailAccount.query.filter_by(id=id).first()
    if not acc:
        return jsonify({"success": False, "error": "账号不存在"})
    data = request.form
    acc.email = data.get('email', acc.email)
    acc.password = data.get('password', acc.password)
    acc.project = data.get('project', acc.project)
    acc.tags = data.get('tags', acc.tags)
    acc.protocol = data.get('protocol', acc.protocol)
    acc.login_status = data.get('login_status', acc.login_status)
    acc.result_desc = data.get('result_desc', acc.result_desc)
    acc.use_proxy = data.get('use_proxy', acc.use_proxy)
    acc.proxy_addr = data.get('proxy_addr', acc.proxy_addr)
    acc.proxy_type = data.get('proxy_type', acc.proxy_type)
    acc.source = data.get('source', acc.source)
    acc.status = data.get('status', acc.status)
    acc.use_times = data.get('use_times', acc.use_times)
    acc.expire_time = data.get('expire_time', acc.expire_time)
    acc.remark = data.get('remark', acc.remark)
    acc.app_id = data.get('app_id', acc.app_id)
    acc.flag = data.get('flag', acc.flag)
    db.session.commit()
    return jsonify({"success": True})

@app.route("/account/<id>/delete", methods=['POST'])
def delete_account(id):
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    acc = MailAccount.query.filter_by(id=id).first()
    if not acc:
        return jsonify({"success": False, "error": "账号不存在"})
    db.session.delete(acc)
    db.session.commit()
    return jsonify({"success": True})

@app.route("/account/batch_delete", methods=['POST'])
def batch_delete():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    ids = request.json.get("ids", [])
    for _id in ids:
        acc = MailAccount.query.filter_by(id=_id).first()
        if acc:
            db.session.delete(acc)
    db.session.commit()
    return jsonify({"success": True})

@app.route("/account/batch_import", methods=['POST'])
def batch_import():
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "未登录"})
    # 支持 json 格式导入
    try:
        items = request.json.get('accounts', [])
        for data in items:
            if MailAccount.query.filter_by(email=data.get('email')).first():
                continue
            acc = MailAccount(
                id=str(uuid.uuid4()),
                email=data.get('email', ''),
                password=data.get('password', ''),
                project=data.get('project', ''),
                tags=data.get('tags', ''),
                protocol=data.get('protocol', ''),
                login_status=data.get('login_status', ''),
                result_desc=data.get('result_desc', ''),
                use_proxy=data.get('use_proxy', ''),
                proxy_addr=data.get('proxy_addr', ''),
                proxy_type=data.get('proxy_type', ''),
                source=data.get('source', ''),
                status=data.get('status', ''),
                use_times=data.get('use_times', ''),
                expire_time=data.get('expire_time', ''),
                remark=data.get('remark', ''),
                app_id=data.get('app_id', ''),
                flag=data.get('flag', '')
            )
            db.session.add(acc)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/account/batch_export", methods=['GET'])
def batch_export():
    if not session.get('logged_in'):
        return jsonify([])
    accounts = MailAccount.query.all()
    data = []
    for acc in accounts:
        data.append({
            "id": acc.id,
            "email": acc.email,
            "password": acc.password,
            "project": acc.project,
            "tags": acc.tags,
            "protocol": acc.protocol,
            "login_status": acc.login_status,
            "result_desc": acc.result_desc,
            "use_proxy": acc.use_proxy,
            "proxy_addr": acc.proxy_addr,
            "proxy_type": acc.proxy_type,
            "source": acc.source,
            "status": acc.status,
            "use_times": acc.use_times,
            "expire_time": acc.expire_time,
            "remark": acc.remark,
            "app_id": acc.app_id,
            "flag": acc.flag
        })
    return jsonify(data)

@app.route("/account/test_login/<id>", methods=["POST"])
def test_login(id):
    if not session.get('logged_in'):
        return jsonify({"result": "未登录"})
    acc = MailAccount.query.filter_by(id=id).first()
    if not acc:
        return jsonify({"result": "账号不存在"})
    # 测试 IMAP/POP3 连接逻辑
    try:
        # 实际测试逻辑略，请根据 protocol 字段实现
        # 这里只模拟
        if acc.protocol == "imap":
            result = "IMAP连接成功"
        elif acc.protocol == "pop3":
            result = "POP3连接成功"
        else:
            result = "未知协议"
        acc.login_status = result
        db.session.commit()
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"result": f"连接失败：{str(e)}"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=True)
