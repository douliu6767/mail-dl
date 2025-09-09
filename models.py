from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

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

class EmailAccount(db.Model):
    __tablename__ = 'email_accounts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(255), nullable=False)
    user = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    protocol = db.Column(db.String(10), default='IMAP', nullable=False)
    port = db.Column(db.Integer, nullable=False)
    ssl = db.Column(db.Boolean, default=True, nullable=False)
    proxy_id = db.Column(db.Integer, db.ForeignKey('proxies.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    proxy = db.relationship('Proxy', backref='email_accounts')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'host': self.host,
            'user': self.user,
            'password': self.password,
            'protocol': self.protocol,
            'port': self.port,
            'ssl': self.ssl,
            'proxy_id': self.proxy_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Proxy(db.Model):
    __tablename__ = 'proxies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # HTTP, SOCKS5
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default='active', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'host': self.host,
            'port': self.port,
            'username': self.username,
            'password': self.password,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Card(db.Model):
    __tablename__ = 'cards'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    usage_limit = db.Column(db.Integer, default=1, nullable=False)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    status = db.Column(db.String(20), default='active', nullable=False)  # active, used_up, expired
    expires_at = db.Column(db.DateTime, nullable=True)
    access_link = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'code': self.code,
            'name': self.name,
            'usage_limit': self.usage_limit,
            'usage_count': self.usage_count,
            'status': self.status,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'access_link': self.access_link,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class EmailLog(db.Model):
    __tablename__ = 'email_logs'
    id = db.Column(db.Integer, primary_key=True)
    email_account_id = db.Column(db.Integer, db.ForeignKey('email_accounts.id'), nullable=True)
    card_id = db.Column(db.Integer, db.ForeignKey('cards.id'), nullable=True)
    sender = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.Text, nullable=True)
    body_preview = db.Column(db.Text, nullable=True)
    verification_code = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, default=True, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    email_account = db.relationship('EmailAccount', backref='email_logs')
    card = db.relationship('Card', backref='email_logs')

    def to_dict(self):
        return {
            'id': self.id,
            'email_account_id': self.email_account_id,
            'card_id': self.card_id,
            'sender': self.sender,
            'subject': self.subject,
            'body_preview': self.body_preview,
            'verification_code': self.verification_code,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'success': self.success,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class CardLog(db.Model):
    __tablename__ = 'card_logs'
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey('cards.id'), nullable=False)
    card_code = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text, nullable=True)
    action = db.Column(db.String(50), nullable=False)  # access, use, verify
    success = db.Column(db.Boolean, default=True, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    card = db.relationship('Card', backref='card_logs')

    def to_dict(self):
        return {
            'id': self.id,
            'card_id': self.card_id,
            'card_code': self.card_code,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'action': self.action,
            'success': self.success,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
