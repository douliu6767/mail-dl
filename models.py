from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import os

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
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))  # 备注名称
    host = db.Column(db.String(100), nullable=False)  # IMAP服务器
    user = db.Column(db.String(100), unique=True, nullable=False)  # 邮箱地址
    password_encrypted = db.Column(db.Text, nullable=False)  # 加密后的密码

    def set_password(self, password):
        """简单的base64编码加密（实际应用中应使用更安全的方法）"""
        self.password_encrypted = base64.b64encode(password.encode('utf-8')).decode('utf-8')

    def get_password(self):
        """解密获取原始密码"""
        try:
            return base64.b64decode(self.password_encrypted.encode('utf-8')).decode('utf-8')
        except:
            return ""
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'user': self.user
        }
