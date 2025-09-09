from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class AdminUser(db.Model):
    __tablename__ = 'admin_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class MailAccount(db.Model):
    __tablename__ = 'mail_accounts'
    id = db.Column(db.String(40), primary_key=True)  # 用uuid或hash字符串
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    project = db.Column(db.String(100))
    tags = db.Column(db.String(100))
    protocol = db.Column(db.String(20)) # pop3/imap
    login_status = db.Column(db.String(20))
    result_desc = db.Column(db.String(100))
    use_proxy = db.Column(db.String(20))
    proxy_addr = db.Column(db.String(100))
    proxy_type = db.Column(db.String(20))
    source = db.Column(db.String(50))
    status = db.Column(db.String(20))
    use_times = db.Column(db.String(20))
    expire_time = db.Column(db.String(50))
    remark = db.Column(db.String(100))
    app_id = db.Column(db.String(50))
    flag = db.Column(db.String(50))
