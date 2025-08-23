#====================================
#                     >>>>MAIN APP <<<<
#====================================
import eventlet
eventlet.monkey_patch()
# =======================
# ✅ Standard Library Imports
# =======================
import os
import re
import json
import base64
import random
import secrets
import logging
import traceback
import subprocess
from datetime import datetime, timedelta
from functools import wraps
from threading import Timer
from collections import defaultdict
from typing import Dict, List, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus, quote
import time

# =======================
# ✅ Third-Party Imports
# =======================
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
from flask import (
    Flask, request, abort, flash, jsonify, redirect, render_template,
    render_template_string, Response, send_file, send_from_directory,
    session, stream_with_context, url_for
)
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user
)
from flask_mail import Mail
from flask_mail import Message as MailMessage
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, CSRFError
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.pool import NullPool
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from flask_session import Session
from flask_compress import Compress
from flask_socketio import SocketIO, emit, join_room, leave_room


#=============================

import os
import json
import time
import random
import re
import numpy as np
from datetime import datetime, timedelta
import requests
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_session import Session
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import make_pipeline
from sklearn.utils.class_weight import compute_class_weight
from difflib import get_close_matches
import joblib
from threading import Lock
import threading
from collections import Counter
import Levenshtein


# ============================
# CONFIGURATION & INIT
# ============================

app = Flask(__name__)
load_dotenv()

#======================================
# choose db Helper
#======================================
def choose_db_uri():
    supabase_uri = os.getenv('DATABASE_URL')  # Old Render DB (primary)
    render_uri = os.getenv('DATABASE_URL_2')      # Render DB (secondary)

    # Try Render Old DB first
    if supabase_uri:
        print("🔍 Trying Render Old DB (DATABASE_URL)...")
        try:
            engine = create_engine(supabase_uri)
            engine.connect().close()
            print("✅ Connected to Render Old DB.")
            return supabase_uri
        except OperationalError as e:
            print("❌ Failed to connect to Render Old DB.")
            print(f"📋 Error: {e}")
            traceback.print_exc()

    # Try Render DB next
    if render_uri:
        print("🔍 Trying Render New DB (DATABASE_URL)...")
        try:
            engine = create_engine(render_uri)
            engine.connect().close()
            print("✅ Connected to Render New DB.")
            return render_uri
        except OperationalError as e:
            print("❌ Failed to connect to Render DB.")
            print(f"📋 Error: {e}")
            traceback.print_exc()

    # Fallback to SQLite
    print("⚠️ All remote DBs failed. Falling back to SQLite.")
    fallback_uri = "sqlite:///default.db"
    print(f"📦 Using fallback: {fallback_uri}")
    return fallback_uri
#======================================
# App Configuration
#======================================
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "12345QWER")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "4321REWQ")
app.config['SQLALCHEMY_DATABASE_URI'] = choose_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool
}
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT") or 0)
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == 'True'
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

app.permanent_session_lifetime = timedelta(hours=732)


app.config["SESSION_TYPE"] = "filesystem"


class CustomCSRFProtect(CSRFProtect):
    def _get_token(self):
        # Try header first (used by fetch)
        token = request.headers.get("X-CSRF-Token")
        if token:
            return token
        # Fallback to default
        return super()._get_token()

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
mail = Mail(app)
csrf = CustomCSRFProtect(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)
Session(app)
Compress(app)
login_manager.login_view = "login"
CORS(app, resources={
    r"/*": {
        "origins": [
            r"https://*.onrender.com",
            r"https://viewtv.viewtv.gt.tc",
            f"https://viewtv.viewtv.free.nf"
        ]
    }
})
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")
# ============================
# MODELS
# ============================
def nairobi_time():
    return datetime.utcnow() + timedelta(hours=3)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=True)
    status = db.Column(db.String(50), nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=True)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=True)
    agreed = db.Column(db.Boolean, default=False, nullable=True)
    created_at = db.Column(db.DateTime, default=nairobi_time, nullable=True)
    plus_type = db.Column(db.String(10), nullable=True, default=None)
    plus_expires_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() - timedelta(seconds=1))
    last_free_plus = db.Column(db.DateTime, nullable=True, default=None)

    def is_locked(self):
        if self.failed_login_attempts < 5:
            return False
        if not self.last_failed_login:
            return False
        unlock_time = self.last_failed_login + timedelta(minutes=5)
        if datetime.utcnow() > unlock_time:
            self.failed_login_attempts = 0
            self.last_failed_login = None
            db.session.commit()
            return False
        return True

    @property
    def has_plus(self):
        return self.plus_expires_at and self.plus_expires_at > datetime.utcnow() + timedelta(hours=3)

    @property
    def is_plus(self):
        return (
            self.plus_type in ['free', 'paid']
            and self.plus_expires_at
            and self.plus_expires_at > datetime.utcnow()
        )

class Streams(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(500), nullable=True, unique=True)
    name = db.Column(db.String(500), nullable=True)
    url = db.Column(db.String(25000), nullable=True)
    category = db.Column(db.String(555), nullable=True)
    created_at = db.Column(db.DateTime, default=nairobi_time)
    logo = db.Column(db.String(10255), nullable=True)
    access = db.Column(db.String(15), nullable=True)
    status = db.Column(db.Boolean, default=True, nullable=True)

class AdminCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(500), default="479admin479", nullable=True)

    def __repr__(self):
        return f"<AdminCode {self.code}>"

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    phone = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="Pending")
    mpesa_receipt = db.Column(db.String(100))
#------------------------------------------------------------------------
class FlashNotice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=nairobi_time)
    is_active = db.Column(db.Boolean, default=True)

    def is_expired(self):
        return datetime.utcnow() > self.created_at + timedelta(hours=24)
#----------------------------------------------------------------------
#Football live events manually inputed
class MatchURL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    is_primary = db.Column(db.Boolean, default=False)
    match_id = db.Column(db.Integer, db.ForeignKey('football_match.id'), nullable=False)

class FootballMatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    home_team = db.Column(db.String(100), nullable=False)
    away_team = db.Column(db.String(100), nullable=False)
    home_logo = db.Column(db.String(255), nullable=False)
    away_logo = db.Column(db.String(255), nullable=False)
    match_date = db.Column(db.DateTime, nullable=False)
    competition = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=nairobi_time)
    is_active = db.Column(db.Boolean, default=True)
    urls = db.relationship('MatchURL', backref='match', lazy=True, cascade="all, delete-orphan")

    def is_expired(self):
        return datetime.utcnow() > self.created_at + timedelta(hours=24)
    
    def status(self):
        now = datetime.utcnow() + timedelta(hours=3)
        if now > self.match_date + timedelta(minutes=135):
            return 'finished'
        elif now > self.match_date:
            return 'live'
        else:
            return 'upcoming'
    
    @property
    def primary_url(self):
        primary = next((url.url for url in self.urls if url.is_primary), None)
        if primary:
            return primary
        return self.urls[0].url if self.urls else "#"
#----------------------------------------------------------------------
class Channel(db.Model):
    __tablename__ = "channels"
    key = db.Column(db.String(512), primary_key=True)
    name = db.Column(db.String(1055), nullable=False)
    url = db.Column(db.String(2024), nullable=False)
    token = db.Column(db.String(512), unique=True, nullable=False)
#------------------------------------------------------------------------
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=nairobi_time)
    read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
#------------------------------------------------------------------------
class AdminStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_users = db.Column(db.Integer)
    active_today = db.Column(db.Integer)
    total_channels = db.Column(db.Integer)
    plus_users = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
#-----------------------------------------------------------------------
with app.app_context():
    db.create_all()
#======================================
@app.route('/robots.txt')
def robots_txt():
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: https://viewtv.viewtv.gt.tc/sitemap.xml\n",
        200,
        {'Content-Type': 'text/plain'}
    )

@app.route('/sitemap.xml')
def sitemap():
    sitemap = '''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://viewtv.viewtv.gt.tc/</loc></url>
  <url><loc>https://viewtv.viewtv.gt.tc/about</loc></url>
  <url><loc>https://viewtv.viewtv.gt.tc/services</loc></url>
  <url><loc>https://viewtv.viewtv.gt.tc/developer</loc></url>
  <url><loc>https://viewtv.viewtv.gt.tc/terms</loc></url>
  <url><loc>https://viewtv.viewtv.gt.tc/privacy</loc></url>
</urlset>
'''
    return Response(sitemap, mimetype='application/xml')

#----------------------------------------------------------------------
@app.route('/googlefd33f833766d41e1.html')
def google_verification():
    return "google-site-verification: googlefd33f833766d41e1.html"
#======================================
#            >>>> HELPER FUNCTIONS<<<<
#======================================

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

#=======================================
@app.before_request
def make_session_permanent():
    session.permanent = True
#------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except OperationalError:
        app.logger.warning("Database connection failed during user load.")
        return None
#-----------------------------------------------------------------------
def is_admin():
    return session.get('role') in ['admin1', 'admin2', 'admin3', 'superadmin']
#----------------------------------------------------------------------
@app.before_request
def bypass_csrf_for_api():
    if request.path.startswith('/api/'):
        setattr(request, '_dont_enforce_csrf', True)
#----------------------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('uploaded_file', filename='favicon.ico'))
#--------------------------------------------------------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)    
#---------------------------------------------------------------------
@app.route('/is_authenticated')
def is_authenticated():
    return jsonify({'authenticated': current_user.is_authenticated})
#----------------------------------------------------------------------
@app.after_request
def set_headers(response):
    # Clear old frame headers if set
    response.headers.pop('X-Frame-Options', None)

    # CSP: allow embedding only from allowed domains
    response.headers['Content-Security-Policy'] = (
        "frame-ancestors https://viewtv.viewtv.gt.tc https://viewtv.viewtv.free.nf;"
    )

    # Legacy fallback: block all iframe embedding (gets overridden by CSP in modern browsers)
    response.headers['X-Frame-Options'] = 'DENY'

    return response
#-----------------------------------------------------------------------
@app.before_request
def flash_update_notice():
    notice = FlashNotice.query.filter_by(is_active=True).order_by(FlashNotice.created_at.desc()).first()

    if not notice or notice.is_expired():
        return  # Nothing to flash or expired

    if session.get('seen_flash_message') != str(notice.id):
        flash(notice.message, "info")
        session['seen_flash_message'] = str(notice.id)
#--------------------------------------------------------------------------
@app.before_request
def force_logout_banned_users():
    if current_user.is_authenticated:
        # Refresh user from DB
        user = User.query.get(current_user.id)
        if user and user.status.lower() == "banned":
            logout_user()  # <-- no arguments
            flash("Your account has been banned. You have been logged out.", "error")
            return redirect(url_for('login'))
#-----------------------------------------------------------------------
def generate_email_token(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user.email, salt='email-verification')
#-----------------------------------------------------------------------
def verify_email_token(token, expiration=1800):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verification', max_age=expiration)
    except Exception:
        return None
    return email
#----------------------------------------------------------------------
def send_verification_email(user):
    token = generate_email_token(user)
    verify_link = url_for('verify_registration', token=token, _external=True)

    msg = MailMessage(
        sender=("View Tv", "bot.tgive3nexus@gmail.com"),
        subject="Verify your View Tv account",
        recipients=[user.email]
    )
    msg.html = render_template('verify_email_template.html', verify_link=verify_link)

    try:
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send verification email: {e}")
#---------------------------------------------------------------------
@app.route('/verify_registration/<token>')
def verify_registration(token):
    email_addr = verify_email_token(token)
    if not email_addr:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email_addr).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    user.email_verified = True
    db.session.commit()
    login_user(user)
    flash('Email verified! Welcome to View Tv.', 'success')
    return redirect(url_for('welcome'))
#----------------------------------------------------------------------
def create_reset_token(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user.email, salt='password-reset-salt')
#---------------------------------------------------------------------
def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email_addr = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email_addr
#----------------------------------------------------------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def forgot_password():
    if request.method == 'POST':
        email_addr = request.form.get('email')
        user = User.query.filter_by(email=email_addr).first()
        if user:
            send_reset_email(user)
            flash('Password reset email sent!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'error')
            return redirect(url_for('login'))

    return render_template('forgot_password.html')
#-------------------------------------------------------------------------
def send_reset_email(user):
    token = create_reset_token(user)
    reset_link = url_for('reset_password', token=token, _external=True)

    msg = MailMessage(
        subject="Password Reset Request",
        sender=("View Tv", "bot.tgive3nexus@gmail.com"),
        recipients=[user.email],
    )
    msg.html = render_template('forgot_password_email.html', reset_link=reset_link)
    mail.send(msg)
#----------------------------------------------------------------------
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email_addr = verify_reset_token(token)
    if not email_addr:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email_addr).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = generate_password_hash(new_password)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')
#---------------------------------------------------------------------
def plus_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Login required.", "error")
            return redirect(url_for("login"))
        if not current_user.is_plus:
            flash("Plus access required.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

def plus_channel(channel_key_param='key', file='channels.json'):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            try:
                with open(file) as f:
                    channels = json.load(f)
                
                key = kwargs.get(channel_key_param)
                channel = channels.get(key)
                if not channel:
                    return "Channel not found", 404

                access = channel.get("access", "free")
                if access == "paid" and not getattr(current_user, "is_plus", False):
                    flash("🔒 This channel requires a Plus subscription.", "warning")
                    return redirect(request.headers.get("Referer") or url_for("home"))

                return view_func(*args, **kwargs)

            except FileNotFoundError:
                return f"Channel file '{file}' not found", 500
            except json.JSONDecodeError:
                return f"Channel file '{file}' is corrupted", 500

        return wrapped_view
    return decorator
#------------------------------------------------------------------------
ROLE_HIERARCHY = {
    'admin3': 1,
    'admin2': 2,
    'admin1': 3,
    'superadmin': 4
}
def role_required(min_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return abort(403)
            user_role = getattr(current_user, 'role', None)
            user_level = ROLE_HIERARCHY.get(user_role, 0)
            if user_level < min_level:
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
def admin3_required(f):
    return role_required(1)(f)  # admin3 and above

def admin2_required(f):
    return role_required(2)(f)  # admin2, admin1, superadmin

def admin1_required(f):
    return role_required(3)(f)  # admin1 and superadmin

def superadmin_required(f):
    return role_required(4)(f)  # only superadmin
#=====================================
#        >>>>ACCESS GRANTERS<<<<
#=====================================

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        name = request.form.get("name", "").strip()
        email_addr = request.form.get('email', "").strip()
        password = request.form.get('password', "")
        confirm_password = request.form.get('confirm_password', "")
        code_input = request.form.get('secret_code', "").strip()

        # --- Basic validations ---
        if not name or not email_addr or not password or not confirm_password:
            flash('All fields are required', "error")
            return render_template("register.html", name=name, email=email_addr)

        if not (email_addr.endswith('@gmail.com') or email_addr.endswith('@yahoo.com')):
            flash('Invalid email', "error")
            return render_template("register.html", name=name, email=email_addr)

        if password != confirm_password:
            flash("Passwords don't match", "error")
            return render_template("register.html", name=name, email=email_addr)

        existing_email = User.query.filter_by(email=email_addr).first()
        if existing_email:
            flash('Email already exists', 'error')
            return render_template("register.html", name=name, email=email_addr)

        # --- Assign role based on secret code ---
        code_role_map = {
            "479superadmin479": "superadmin",
            "479admin1": "admin1",
            "479admin2": "admin2",
            "479admin3": "admin3",
        }
        role = code_role_map.get(code_input, "user")

        # --- Create new user instance properly ---
        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email_addr,
            password=hashed_password,
            role=role,
            status='pending',
            agreed=True,
            plus_expires_at=datetime.utcnow() + timedelta(days=7),
            plus_type="free",
            last_free_plus=None
        )

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while creating your account.", "error")
            return render_template("register.html", name=name, email=email_addr)

        # --- Send verification email ---
        send_verification_email(new_user)

        flash(f"Account created as {new_user.role}. Check your email to verify.", "success")
        return redirect(url_for('notice_register', user_id=new_user.id))

    return render_template("register.html")

@app.route('/notice-register')
def notice_register():
    user_id = request.args.get('user_id')
    new_user = User.query.get(user_id)
    return render_template("notice_register.html", new_user=new_user)

#----------------------------------------------------------------------
@app.route('/local-player')
def local_player():
    return render_template('local_player.html')

#----------------------------------------------------------------------

def get_role_home(role, is_plus):
    if role in ['superadmin', 'admin1', 'admin2', 'admin3']:
        return url_for('home_admin')
    elif is_plus:
        return url_for('home_2')  # Plus user home
    else:
        return url_for('home_1')  # Normal user home

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def login():
    next_page = request.args.get("next") or request.form.get("next")

    if current_user.is_authenticated:
        if current_user.status != "active":
            logout_user()
            flash("Your account is inactive.", "danger")
            return redirect(url_for("login"))

        # ✅ Downgrade Plus if expired
        if current_user.plus_expires_at and current_user.plus_expires_at < datetime.utcnow():
            current_user.plus_expires_at = datetime.utcnow() - timedelta(seconds=1)
            current_user.plus_type = None
            db.session.commit()

        return redirect(next_page or get_role_home(current_user.role, current_user.is_plus))

    if request.method == "POST":
        email_addr = request.form.get('email')
        password = request.form.get('password')

        if not password or not email_addr:
            flash('All fields are required', "error")
            return render_template('login.html')

        user = User.query.filter_by(email=email_addr).first()

        if user:
            # ⏳ Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                if user.last_failed_login and datetime.utcnow() - user.last_failed_login < timedelta(minutes=5):
                    remaining = 5 - (datetime.utcnow() - user.last_failed_login).seconds // 60
                    flash(f"Account locked. Try again in {remaining} minutes.", "error")
                    return redirect(url_for('login'))
                else:
                    user.failed_login_attempts = 0
                    db.session.commit()

            if not user.email_verified:
                flash("Please verify your email before logging in.", "warning")
                return redirect(url_for('login'))

            if check_password_hash(user.password, password):
                if user.status.lower() == "banned":
                    flash("Account Banned! Contact Support.", "danger")
                    return redirect(url_for("home"))

                user.failed_login_attempts = 0
                user.status = "active"
                session.clear()
                session['role'] = user.role
                session['active'] = user.status
                db.session.commit()

                login_user(user)
                flash("♻️ Welcome back!", "success")

                # ✅ Downgrade Plus if expired
                if user.plus_expires_at and user.plus_expires_at < datetime.utcnow():
                    user.plus_expires_at = datetime.utcnow() - timedelta(seconds=1)
                    user.plus_type = None
                    db.session.commit()

                return redirect(next_page or get_role_home(user.role, user.is_plus))
            else:
                user.failed_login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()

        flash('Invalid Credentials', "error")
        return render_template('login.html', email=email_addr, password=password)

    return render_template('login.html')
#------------------------------------------------------------------------
@app.route('/api/check_user', methods=['POST'])
def check_user():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'exists': False})
    
    # Return non-sensitive user info
    return jsonify({
        'exists': True,
        'email': user.email,
        'name': user.name,
        'status': user.status
    })
#=======================================
#           >>>>ROLE BASED ACTIONS<<<<
#=======================================
#           >>>>VIP | PLUS ACCESS<<<<
#=======================================
@app.route('/home_2')
@login_required
@plus_required
def home_2():
    if current_user.plus_type not in ["free", "paid"]:
        return redirect(url_for("home_1"))
    return render_template('home_2.html', user=current_user)
@app.route("/curated")   
def curated():
    return render_template("test-player.html") 
#=======================================
competition_keywords = {
    "La Liga": ["la liga", "laliga"],
    "EPL": ["premier league", "epl", "sky sports", "bt sport"],
    "UEFA": ["champions", "ucl", "uefa"],
    "Serie A": ["serie a", "italy"],
    "Bundesliga": ["bundesliga", "germany"],
    "Ligue 1": ["ligue 1", "france"],
    "MLS": ["mls", "major league"],
    "Other": []
}

def match_competition(channel_name):
    name = channel_name.lower()
    for comp, keywords in competition_keywords.items():
        if any(k in name for k in keywords):
            return comp
    return "Other"

@app.route("/sports_playlist")
@limiter.limit("30 per minute")
@plus_required
@login_required
def sports_playlist():
    # Load channels from football.json
    with open("football.json", "r") as f:
        football_data = json.load(f)
    
    channels_by_group = {}
    
    for ch_id, ch in football_data.items():
        name = ch.get("name", "")
        url = ch.get("url", "")
        logo = ch.get("logo", "")
        country = ch.get("country", "")
        group_title = ch.get("group-title", "Sports")  # Default group if missing
        
        if not name or not url:
            continue  # Skip invalid entries
        
        # Determine competition (La Liga, EPL, etc.)
        competition = match_competition(name)
        
        # Create the label expected by the template (e.g., "BEIN ? La Liga")
        label = f"{group_title} ? {competition}"
        
        # Add channel to the group
        channels_by_group.setdefault(label, []).append({
            "name": name,
            "url": url,
            "logo": logo,
            "country": country,
            "token": ""  # Required by template
        })
    
    return render_template(
        "sports_playlist.html",
        channels_by_group=channels_by_group,
        current_year=datetime.now().year
    )
#----------------------------------------------------------------------
@app.route("/return-football")
@limiter.limit("30 per minute")
@login_required
@plus_required
def return_football():
    return render_template("return_football.html")

#----------------------------------------------------------------------
@app.route('/proxy/<path:stream_url>')
def proxy_redirect(stream_url):
    full_url = f"http://{stream_url}" if not stream_url.startswith("http") else stream_url

    # Render a page that opens the stream URL in a new tab
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Opening Stream</title>
        <script>
            window.onload = function() {
                window.open("{{ full_url }}", "_blank");
            };
        </script>
    </head>
    <body>
        <p>Opening stream in a new tab...</p>
        <p>If it doesn’t open, <a href="{{ full_url }}" target="_blank">click here</a>.</p>
    </body>
    </html>
    """, full_url=full_url)        

#-------------------------------------------------------------------------
@app.route("/embed/moviepire")
@login_required
@plus_required
def moviepire():
    return render_template("moviepire.html")

from flask import redirect
@app.route("/football_matches")
@limiter.limit("30 per minute")
@login_required
@plus_required
def football_matches():
    return redirect("http://server1.bdixsports.live/all/appevent_football.php")
#------------------------------------------------------------------------
import  time 
MOVIES_FILE = 'movies.json'
CACHE_FILE = 'movies_cache.json'

def clean_key(key):
    """Clean and standardize dictionary keys while preserving original key structure"""
    if not isinstance(key, str):
        key = str(key)
    # Remove numeric prefix and special characters
    key = ''.join(c for c in key if c.isalnum() or c == '_').strip('_')
    parts = key.split('_')
    if parts and parts[0].isdigit():
        parts = parts[1:]
    return '_'.join(parts).lower() if parts else 'unnamed'

def load_movies_data():
    """Load and validate movies data with caching"""
    # Check if movies file exists
    if not os.path.exists(MOVIES_FILE):
        app.logger.error(f"Movies file not found at {os.path.abspath(MOVIES_FILE)}")
        return {}

    # Check cache freshness
    use_cache = (os.path.exists(CACHE_FILE) and 
                (os.path.getmtime(CACHE_FILE) > os.path.getmtime(MOVIES_FILE)))

    if use_cache:
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            app.logger.warning(f"Cache load failed: {e}")

    # Load and process original file
    try:
        with open(MOVIES_FILE, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
    except Exception as e:
        app.logger.error(f"Failed to load movies: {e}")
        return {}

    processed = {}
    for original_key, movie in raw_data.items():
        if not isinstance(movie, dict):
            app.logger.warning(f"Skipping invalid movie entry: {original_key}")
            continue

        try:
            clean_movie = {
                'id': clean_key(original_key),  # Added ID field for API
                'name': str(movie.get('name', '')).strip() or f"Unnamed Movie ({original_key})",
                'url': str(movie.get('url', '')).strip(),
                'logo': str(movie.get('logo', '')).strip(),
                'group-title': str(movie.get('group-title', 'Uncategorized')).strip(),
                'access': str(movie.get('access', 'free')).lower(),
                'original_key': original_key
            }
            
            if not clean_movie['url']:
                app.logger.warning(f"Skipping movie with empty URL: {original_key}")
                continue
                
            processed[clean_movie['id']] = clean_movie
        except Exception as e:
            _app.logger.warning(f"Error processing movie {original_key}: {e}")
            continue

    # Save to cache
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(processed, f, indent=2, ensure_ascii=False)
    except Exception as e:
        app.logger.warning(f"Failed to save cache: {e}")

    return processed

# Load data at startup
MOVIES_DATA = load_movies_data()

@app.route("/plus-movies")
@login_required
@plus_required
def plus_movies():
    if not MOVIES_DATA:
        return render_template('error.html', message="No movies data available"), 500

    # Group movies by category for the template
    categories = defaultdict(list)
    for movie in MOVIES_DATA.values():
        category = movie['group-title'] if movie.get('group-title') else 'Uncategorized'
        categories[category].append(movie)
    
    # Sort for the template
    categorized_movies = {
        category: sorted(movies, key=lambda x: x['name'].lower())
        for category, movies in sorted(categories.items(), key=lambda x: x[0].lower())
    }
    
    return render_template(
        'movies.html',
        categorized_channels=categorized_movies,
        total_movies=len(MOVIES_DATA),
        total_categories=len(categorized_movies)
    )

# API Endpoints for the template
@app.route('/api/categories')
@login_required
def get_categories():
    categories = defaultdict(list)
    for movie in MOVIES_DATA.values():
        category = movie['group-title'] if movie.get('group-title') else 'Uncategorized'
        categories[category] = 1  # Just counting
    
    return jsonify([
        {'id': clean_key(cat), 'name': cat, 'count': count} 
        for cat, count in categories.items()
    ])

@app.route('/api/movies')
@login_required
def get_movies():
    category = request.args.get('category', '').lower()
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 100))
    
    # Filter by category if specified
    movies = [
        m for m in MOVIES_DATA.values() 
        if not category or clean_key(m.get('group-title', '')) == category
    ]
    
    # Paginate
    start = (page - 1) * limit
    end = start + limit
    paginated = movies[start:end]
    
    return jsonify({
        'movies': paginated,
        'hasMore': end < len(movies),
        'total': len(movies)
    })

@app.route('/api/movies/count')
@login_required
def get_movie_count():
    return jsonify({'count': len(MOVIES_DATA)})
#-------------------------------------------------------------------------
# Configuration
CONFIG = {
    "CACHE_FILE": "movie_cache.json",
    "SCRAPE_INTERVAL_HOURS": 3,  # Scrape every 3 hours
    "TMDB_PAGES_TO_FETCH": 30,   # ~600 movies
    "OMDB_KEYS": ["a465208e", "1d9efb66"],
    "TMDB_API_KEY": "a54b0b5ef7df29593b16b047e11a9ca9",
    "REQUEST_TIMEOUT": 20,
    "MAX_THREADS": 8,
    "SESSION_SECRET_KEY": os.urandom(24).hex(),
    "MAX_MOVIES": 600,
    "LAST_SCRAPE_TIME": None,
    "SCHEDULER_RUNNING": False
}

app.logger.setLevel(logging.INFO)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

import time
def rate_limited(max_per_second):
    min_interval = 1.0 / max_per_second
    def decorate(func):
        last_time_called = 0.0
        def rate_limited_function(*args, **kwargs):
            nonlocal last_time_called
            elapsed = time.time() - last_time_called
            wait = min_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            last_time_called = time.time()
            return func(*args, **kwargs)
        return rate_limited_function
    return decorate

class MovieCache:
    @staticmethod
    def should_scrape():
        """Check if we should scrape new movies"""
        if not os.path.exists(CONFIG["CACHE_FILE"]):
            return True
            
        if CONFIG["LAST_SCRAPE_TIME"] is None:
            return True
            
        time_since_last = datetime.now() - CONFIG["LAST_SCRAPE_TIME"]
        return time_since_last >= timedelta(hours=CONFIG["SCRAPE_INTERVAL_HOURS"])

    @staticmethod
    def load():
        try:
            with open(CONFIG["CACHE_FILE"], "r", encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            app.logger.error(f"Cache load failed: {str(e)}")
            return []

    @staticmethod
    def save(data):
        try:
            with open(CONFIG["CACHE_FILE"], "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            CONFIG["LAST_SCRAPE_TIME"] = datetime.now()
            app.logger.info(f"New movies scraped at {CONFIG['LAST_SCRAPE_TIME']}")
        except IOError as e:
            app.logger.error(f"Cache save failed: {str(e)}")

class MovieAPI:
    @staticmethod
    @rate_limited(5)
    def get_tmdb_movies(page=1):
        url = f"https://api.themoviedb.org/3/movie/popular?api_key={CONFIG['TMDB_API_KEY']}&page={page}"
        try:
            r = requests.get(url, timeout=CONFIG["REQUEST_TIMEOUT"])
            r.raise_for_status()
            return r.json().get("results", [])
        except requests.exceptions.RequestException as e:
            app.logger.error(f"TMDB API error: {str(e)}")
            return []

    @staticmethod
    @rate_limited(1)
    def get_omdb_data(title, year=None, key_index=0):
        key = CONFIG["OMDB_KEYS"][key_index % len(CONFIG["OMDB_KEYS"])]
        params = {"t": title, "apikey": key}
        if year:
            params["y"] = year
        try:
            r = requests.get("http://www.omdbapi.com/", params=params, timeout=CONFIG["REQUEST_TIMEOUT"])
            r.raise_for_status()
            data = r.json()
            if data.get("Response") == "True":
                return data
            return {}
        except requests.exceptions.RequestException as e:
            app.logger.error(f"OMDB API error: {str(e)}")
            return {}

    @staticmethod
    @rate_limited(2)
    def get_yts_torrents(title):
        params = {"query_term": title, "limit": 3}
        try:
            r = requests.get("https://yts.mx/api/v2/list_movies.json", params=params, timeout=CONFIG["REQUEST_TIMEOUT"])
            r.raise_for_status()
            data = r.json()
            if data.get("status") != "ok" or data.get("data", {}).get("movie_count", 0) == 0:
                return []
            movies = data["data"]["movies"]
            return movies[0].get("torrents", []) if movies else []
        except requests.exceptions.RequestException as e:
            app.logger.error(f"YTS API error: {str(e)}")
            return []

def process_movie(movie, index):
    title = movie.get("title")
    year = movie.get("release_date", "")[:4] if movie.get("release_date") else None
    
    omdb = MovieAPI.get_omdb_data(title, year, key_index=index)
    torrents = MovieAPI.get_yts_torrents(title)
    
    return {
        "id": movie.get("id"),
        "title": title,
        "year": year,
        "poster": f"https://image.tmdb.org/t/p/w500{movie.get('poster_path')}" if movie.get("poster_path") else None,
        "backdrop": f"https://image.tmdb.org/t/p/w1280{movie.get('backdrop_path')}" if movie.get("backdrop_path") else None,
        "rating": movie.get("vote_average"),
        "plot": omdb.get("Plot", "No description available."),
        "runtime": omdb.get("Runtime", "N/A"),
        "genre": omdb.get("Genre", "N/A"),
        "imdb_rating": omdb.get("imdbRating", "N/A"),
        "torrents": torrents,
        "tmdb_link": f"https://www.themoviedb.org/movie/{movie.get('id')}",
        "scraped_at": datetime.now().isoformat()
    }

import time
def fetch_movies():
    """Fetch and process new movies from APIs"""
    movies = []
    tmdb_movies = []
    
    # Fetch from TMDB
    for page in range(1, CONFIG["TMDB_PAGES_TO_FETCH"] + 1):
        tmdb_movies.extend(MovieAPI.get_tmdb_movies(page))
    
    # Process in parallel
    with ThreadPoolExecutor(max_workers=CONFIG["MAX_THREADS"]) as executor:
        futures = [executor.submit(process_movie, movie, idx) for idx, movie in enumerate(tmdb_movies)]
        for future in as_completed(futures):
            try:
                movie_data = future.result()
                if movie_data:
                    movies.append(movie_data)
            except Exception as e:
                app.logger.error(f"Error processing movie: {str(e)}")
    
    # Sort by scrape time (newest first) then by rating
    return sorted(
        movies,
        key=lambda x: (x["scraped_at"], float(x["rating"]) if x["rating"] else 0),
        reverse=True
    )[:CONFIG["MAX_MOVIES"]]

def schedule_next_scrape():
    """Schedule the next scrape job"""
    Timer(
        CONFIG["SCRAPE_INTERVAL_HOURS"] * 3600,  # Convert hours to seconds
        run_scheduled_scrape
    ).start()

def run_scheduled_scrape():
    """Execute the scheduled scrape job"""
    try:
        if MovieCache.should_scrape():
            app.logger.info("Running scheduled scrape...")
            new_movies = fetch_movies()
            MovieCache.save(new_movies)
            app.logger.info(f"Scheduled scrape completed. {len(new_movies)} movies cached.")
        else:
            app.logger.info("Skipping scheduled scrape - cache is still fresh")
    except Exception as e:
        app.logger.error(f"Scheduled scrape failed: {str(e)}")
    finally:
        # Reschedule the next run
        schedule_next_scrape()

def start_scrape_scheduler():
    """Start the automatic scraping scheduler"""
    if not CONFIG["SCHEDULER_RUNNING"]:
        CONFIG["SCHEDULER_RUNNING"] = True
        app.logger.info("Starting automatic scraping scheduler...")
        # Run first scrape immediately
        Timer(0, run_scheduled_scrape).start()

def update_movies_if_needed():
    """Check if we need to scrape new movies and update cache"""
    if MovieCache.should_scrape():
        app.logger.info("Manual scraping initiated...")
        new_movies = fetch_movies()
        MovieCache.save(new_movies)
        app.logger.info(f"Manual scrape completed. {len(new_movies)} movies cached.")

@app.route("/movieflix")
def movieflix():
    update_movies_if_needed()
    movies = MovieCache.load()
    return render_template("movieflix.html", movies=movies)

@app.route("/movie/<int:movie_id>")
def movie_detail(movie_id):
    movies = MovieCache.load()
    movie = next((m for m in movies if m.get("id") == movie_id), None)
    return render_template("detail.html", movie=movie) if movie else redirect(url_for("movieflix"))    
#-------------------------------------------------------------------------
@app.route("/countries")
@login_required
@plus_required
def countries():
    try:
        response = requests.get("https://iptv-org.github.io/api/countries.json")
        response.raise_for_status()
        countries = response.json()
        return render_template("countries.html", countries=countries)
    except Exception as e:
        return f"Error fetching countries: {e}"
#-------------------------------------------------------------------------
@app.route("/country/<country_code>")
@login_required
@plus_required
def fetch_country_channels(country_code):
    url = f"https://iptv-org.github.io/iptv/countries/{country_code.lower()}.m3u"
    try:
        response = requests.get(url)
        lines = response.text.splitlines()

        channels = []
        name = None
        for line in lines:
            if line.startswith("#EXTINF:-1"):
                name = line.split(",")[-1].strip()
            elif line.startswith("http"):
                if name:
                    channels.append({"name": name, "url": line})

        return render_template("channels.html", channels=channels, country=country_code.upper())
    except Exception as e:
        return f"Error fetching channels: {e}"
#-------------------------------------------------------------------------
@app.route("/category/<category_id>")
@login_required 
@plus_required
def fetch_category_channels(category_id):
    url = f"https://iptv-org.github.io/iptv/categories/{category_id}.m3u"
    try:
        response = requests.get(url)
        lines = response.text.strip().splitlines()

        channels = []
        name = None
        for line in lines:
            if line.startswith("#EXTINF"):
                name = line.split(",")[-1].strip()
            elif line.startswith("http"):
                if name:
                    channels.append({"name": name, "url": line})

        return render_template("channels.html", channels=channels, category=category_id.capitalize())
    except Exception as e:
        return f"Error fetching category channels: {e}"
#------------------------------------------------------------------------
@app.route("/categories")
@login_required
@plus_required
def categories():
    try:
        response = requests.get("https://iptv-org.github.io/api/categories.json")
        response.raise_for_status()
        categories = response.json()
        return render_template("categories.html", categories=categories)
    except Exception as e:
        return f"Failed to load categories: {e}"
#-----------------------------------------------------------------------
@app.route("/more-channels")
@login_required
@plus_required
def more_channels():
    return render_template("more_channels.html")
#-------------------------------------------------------------------------
@app.route("/watch")
@login_required
def watch():
    
    name = request.args.get("name")
    stream_url = request.args.get("url")
    category_id = request.args.get("category")
    country_code = request.args.get("country")

    channels = []
    source_label = ""  # For heading in player

    try:
        if category_id:
            url = f"https://iptv-org.github.io/iptv/categories/{category_id.lower()}.m3u"
            source_label = category_id.capitalize()
        elif country_code:
            url = f"https://iptv-org.github.io/iptv/countries/{country_code.lower()}.m3u"
            source_label = country_code.upper()
        else:
            url = None

        if url:
            response = requests.get(url)
            lines = response.text.strip().splitlines()

            current_name = None
            for line in lines:
                if line.startswith("#EXTINF"):
                    current_name = line.split(",")[-1].strip()
                elif line.startswith("http") and current_name:
                    channels.append({"name": current_name, "url": line})

    except Exception as e:
        flash(f"Error fetching channels: {e}", "error")

    return render_template("player.html", stream_url=stream_url, name=name, channels=channels, source_label=source_label)

#================================
#        TEST FOR PLAYERS' UI/UX
#================================

@app.route('/test_channels')
def test_channels():
    url = "https://iptv-org.github.io/iptv/countries/ke.m3u"
    response = requests.get(url)
    channels = []
    lines = response.text.splitlines()
    for i in range(len(lines)):
        if lines[i].startswith("#EXTINF"):
            name = lines[i].split(",")[-1]
            stream_url = lines[i + 1]
            channels.append({"name": name, "url": stream_url})
    return render_template("channels.html", channels=channels)

#=======================================
#             >>>> PROXY MODEL<<<<
#=======================================

#=======================================
# Configuration
YOUTUBE_API_KEY = "AIzaSyBJAD2gfCDfMO1mNdrWWTegL9ZUSBSLt44"
CACHE_FILE = "cache.json"
CACHE_DURATION = 30 * 60  # 30 minutes

OFFICIAL_BROADCASTERS = {
    "premier": "UCTi0ZRSN1wmGBK1x4QqQKzA",
    "laliga": "UC8C4LqMsJ8Q9XaLK1O0QY8g",
    "uefa": "UC3GzR0a8Qm_9b0wJjXz9QzQ",
    "bein": "UCJUCcJUeh0Cz2xyKwkw5Q1w",
    "dazn": "UCqdw6UF0m-6Hq1t4i4Xx9JQ",
    "tnt": "UCjzbDk-B9gQY8hU4UjTlVDw",
    "espn": "UCdKic8_9Q1JP1Qw_Rs5QlRw",
    "fox": "UCdKic8_9Q1JP1Qw_Rs5QlRw",
    "nbcsports": "UCqZQlzSHbVJrwrn5XvzrzcA",
    "cbs": "UCJ2ZhWnWwJbKvnW3n7CO7Xg",
    "tsn": "UCd4FOx0s9jJjWb8HsFnPpYw",
    "fubo": "UCZMFmRBpXrH-ObiOeYcW1FQ"
}

# Initialize cache
CACHE = {}
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "r") as f:
            CACHE = json.load(f)
    except Exception as e:
        print(f"Error loading cache: {e}")
        CACHE = {}

def save_cache():
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(CACHE, f)
    except Exception as e:
        print(f"Error saving cache: {e}")

def is_football_stream(title):
    if not title:
        return False
    title = title.lower()
    football_terms = ['football', 'soccer', 'premier', 'laliga', 'match']
    banned_terms = ['gameplay', 'android', 'mobile', 'highlights']
    return (any(term in title for term in football_terms) and \
           (not any(term in title for term in banned_terms)))

def fetch_official_streams(channel_id):
    try:
        response = requests.get(
            "https://www.googleapis.com/youtube/v3/search",
            params={
                "part": "snippet",
                "channelId": channel_id,
                "eventType": "live",
                "type": "video",
                "maxResults": 10,
                "key": YOUTUBE_API_KEY,
                "order": "date"
            },
            timeout=10
        )
        response.raise_for_status()
        streams = []
        for item in response.json().get("items", []):
            vid = item["id"].get("videoId")
            snip = item["snippet"]
            if vid and is_football_stream(snip["title"]):
                streams.append({
                    "title": snip["title"],
                    "video_id": vid,
                    "channel": snip["channelTitle"],
                    "published_at": snip["publishedAt"],
                    "thumbnail": snip["thumbnails"]["high"]["url"],
                    "is_official": True
                })
        return streams
    except Exception as e:
        print(f"Error fetching official streams: {e}")
        return []

def fetch_live_streams_cached(category):
    now = time.time()
    cached = CACHE.get(category)
    if cached and now - cached["timestamp"] < CACHE_DURATION:
        return cached["data"]

    streams = []
    if category in OFFICIAL_BROADCASTERS:
        streams = fetch_official_streams(OFFICIAL_BROADCASTERS[category])
    
    CACHE[category] = {
        "data": streams,
        "timestamp": now
    }
    save_cache()
    return streams

@app.route("/wrestling")
@login_required
@plus_required
def wrestling():
    return render_template("wrestling.html")

@app.route("/live_matches")
def live_matches():
    return render_template("live_matches.html")

@app.route("/api/live_streams")
def api_live_streams():
    cat = request.args.get("cat", "all")
    streams = fetch_live_streams_cached(cat)
    return jsonify(streams)

#=======================================
@app.route('/status', methods=['GET'])
def status():
    return Response(
        "Proxy active",
        mimetype='text/plain',
        headers={
            'X-Content-Type-Options': 'nosniff',
            'Content-Disposition': 'inline'
        }
    )
#--------------------------------------------------------------------------
@app.route('/diagnostics', methods=['POST'])
@csrf.exempt
def diagnostics():
    if not request.form.get('cmd'):
        return jsonify({'error': 'Missing command'}), 400
        
    cmd = request.form.get('cmd')
    if cmd == 'which ffmpeg':
        try:
            result = subprocess.run(
                ['which', 'ffmpeg'],
                capture_output=True,
                text=True,
                check=True
            )
            return jsonify({
                'success': True,
                'path': result.stdout.strip()
            })
        except subprocess.CalledProcessError:
            return jsonify({
                'success': False,
                'error': 'FFmpeg not found'
            }), 500
    return jsonify({'error': 'Invalid command'}), 400
#-----------------------------------------------------------------------
# Root directory for all HLS outputs
HLS_ROOT = "/tmp/hls_streams"
os.makedirs(HLS_ROOT, exist_ok=True)

# Proxy headers for external video sources
PROXY_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Referer": "http://balkan-x.net",
    "Origin": "http://balkan-x.net",
    "Connection": "keep-alive",
    "Accept": "*/*",
    # "Cookie": "SESSIONID=abcd1234;"  # Optional: Add cookies if required
}

# Load sports channels from JSON
def load_sports():
    with open('streamtv.json') as f:
        data = json.load(f)
    return [
        {"id": int(k), "name": v['name'], "url": v['url']}
        for k, v in data.items()
    ]
#--------------------------------------------------------------------------

#-----------------------------------------------------------------------
# Route: Serve .m3u8 playlist (auto start ffmpeg if needed)
@app.route('/hls/<int:channel_id>.m3u8')
def hls_playlist(channel_id):
    channels = load_sports()
    channel = next((ch for ch in channels if ch["id"] == channel_id), None)

    if not channel:
        return abort(404, "Channel not found")

    proxied_url = f"https://viewtv.viewtv.gt.tc/proxy?url={quote_plus(channel['url'])}"
    channel_folder = os.path.join(HLS_ROOT, str(channel_id))
    playlist_path = os.path.join(channel_folder, "index.m3u8")

    if not os.path.exists(playlist_path):
        os.makedirs(channel_folder, exist_ok=True)

        ffmpeg_cmd = [
            "ffmpeg",
            "-fflags", "nobuffer",
            "-flags", "low_delay",
            "-i", proxied_url,
            "-c", "copy",
            "-hls_time", "10",
            "-hls_list_size", "5",
            "-hls_flags", "delete_segments+append_list",
            "-hls_segment_filename", os.path.join(channel_folder, "segment%03d.ts"),
            playlist_path
        ]

        log_path = os.path.join(channel_folder, "ffmpeg.log")
        with open(log_path, "w") as log_file:
            subprocess.Popen(ffmpeg_cmd, stdout=log_file, stderr=log_file)

        return f"Stream is initializing. Check log: <a href='/log/{channel_id}'>View FFmpeg Log</a>"

    return send_from_directory(channel_folder, "index.m3u8", mimetype="application/vnd.apple.mpegurl")
#-----------------------------------------------------------------------
# Route: Serve HLS segments (.ts files)
@app.route('/hls/<int:channel_id>/<segment>')
def hls_segment(channel_id, segment):
    channel_folder = os.path.join(HLS_ROOT, str(channel_id))
    segment_path = os.path.join(channel_folder, segment)

    if os.path.exists(segment_path):
        return send_from_directory(channel_folder, segment, mimetype="video/MP2T")
    else:
        return abort(404, "Segment not found")
#--------------------------------------------------------------------------
@app.route('/test-ffmpeg')
def test_ffmpeg():
    try:
        result = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True, check=True)
        return jsonify({
            "ffmpeg": "available",
            "version": result.stdout.split('\n')[0]
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            "ffmpeg": "not available",
            "error": e.stderr
        }), 500
#-------------------------------------------------------------------------
# Route: View FFmpeg log (for debugging)
@app.route('/log/<int:channel_id>')
def view_ffmpeg_log(channel_id):
    log_path = os.path.join(HLS_ROOT, str(channel_id), "ffmpeg.log")
    if os.path.exists(log_path):
        with open(log_path) as f:
            return f"<pre>{f.read()}</pre>"
    else:
        return "No log available."
#-------------------------------------------------------------------------
# Route: Reset stream data (delete all segments and playlist)
@app.route('/reset/<int:channel_id>')
def reset_stream(channel_id):
    folder = os.path.join(HLS_ROOT, str(channel_id))
    if os.path.exists(folder):
        for file in os.listdir(folder):
            os.remove(os.path.join(folder, file))
        return f"Stream {channel_id} reset. Refresh to retry."
    return "Stream folder not found."
#---------------------------------------------------------------------------
# Route: List all sports channels
@app.route('/sports')
def sports_listing():
    channels = load_sports()
    return render_template('sports.html', channels=channels)
#-------------------------------------------------------------------------
FFMPEG_PROXY_URL = "https://viewtv.viewtv.gt.tc/hls"

@app.route('/stream')
def stream_router():
    input_url = request.args.get('input')
    name = request.args.get('name', 'Streaming')
    token = request.args.get('token', '')

    if not input_url:
        flash("Missing stream input.")
        return render_template("404.html")

    final_url = ""

    if input_url.endswith('.ts'):
        match = re.search(r'/(\d+)\.ts$', input_url)
        if match:
            channel_id = match.group(1)
            # Rewrite to your own proxy .m3u8 URL
            final_url = f"{FFMPEG_PROXY_URL}/{channel_id}.m3u8"
        else:
            flash("Invalid TS format.")
            return render_template("404.html")

    elif input_url.endswith('.m3u8') or input_url.startswith('http'):
        final_url = input_url

    else:
        flash("Unsupported stream format.")
        return render_template("404.html")

    # Redirect to player with final URL
    return redirect(f"/player?url={final_url}&name={name}&token={token}")
#=======================================
#           >>>>BASIC USER ENDPOINTS<<<<
#=======================================
CHANNELS_FILE = 'channels.json'

def load_channels():
    if not os.path.exists(CHANNELS_FILE):
        return {}
    with open(CHANNELS_FILE, 'r') as f:
        return json.load(f)
def save_channels(channels):
    with open(CHANNELS_FILE, 'w') as f:
        json.dump(channels, f, indent=2)

CUSTOM_CHANNELS = load_channels()

BASIC_CHANNELS_FILE = 'custom_channels_basic.json'
BASIC_CHANNELS = {}

def load_home1_channels():
    """Load and validate channels from JSON file"""
    if not os.path.exists(BASIC_CHANNELS_FILE):
        return {}
    
    with open(BASIC_CHANNELS_FILE, 'r') as f:
        channels = json.load(f)
    
    return {k: v for k, v in channels.items() 
            if all(field in v for field in ['name', 'url'])}

# Load channels at startup
BASIC_CHANNELS = load_home1_channels()

@app.route('/home_1')
@login_required
def home_1():
    """Homepage with channel listing"""
    channels = dict(sorted(BASIC_CHANNELS.items(), 
                         key=lambda item: item[1]['name'].lower()))
    return render_template('home_1.html', channels=channels)

@app.route("/channel/<key>")
@login_required
@plus_channel(file='custom_channels_basic.json')
def play_channel(key):
    """Main player route"""
    if key not in BASIC_CHANNELS:
        flash("Channel not found", "error")
        return redirect(url_for("home"))
    
    channel = BASIC_CHANNELS[key]
    
    # Convert to list of dicts for template
    channels_list = [{"key": k, "name": v["name"]} 
                    for k, v in BASIC_CHANNELS.items()]
    
    return render_template(
        "custom_player.html",
        channel_name=channel["name"],
        stream_url=channel["url"],
        channels=channels_list,
        current_key=key
    )

@app.route("/api/channel_stream_url")
@login_required
def channel_stream_url():
    """API endpoint for channel switching"""
    key = request.args.get("key")
    if not key:
        return jsonify({
            "success": False,
            "error": "Missing channel key",
            "code": 400
        }), 400

    channel = BASIC_CHANNELS.get(key)
    if not channel:
        return jsonify({
            "success": False,
            "error": "Channel not found",
            "code": 404,
            "available_keys": list(BASIC_CHANNELS.keys())
        }), 404

    # Access control logic here instead of @plus_channel
    if channel.get("access") == "paid" and not getattr(current_user, "is_plus", False):
        return jsonify({
            "success": False,
            "error": "This channel requires a Plus subscription.",
            "code": 403
        }), 403

    url = channel["url"]

    # Enhanced stream type detection
    is_direct = bool(
        re.search(r":\d+", url) or
        url.startswith(('rtmp://', 'rtsp://')) or
        not url.lower().endswith(('.m3u8', '.mpd'))
    )

    return jsonify({
        "success": True,
        "stream_url": url,
        "name": channel["name"],
        "access": channel.get("access", "").lower(),
        "is_direct": is_direct,
        "type": "hls" if not is_direct and url.lower().endswith('.m3u8') else "direct",
        "logo": channel.get("logo", ""),
        "group": channel.get("group-title", "")
    })

#-------------------------------------------------------------------------
@app.route("/plus-playlist")
@login_required
@plus_required
def plus_playlist():
    return redirect(url_for('custom_list'))

@app.route("/plus-channels")
@login_required
@plus_required
def custom_list():
    raw_channels = CUSTOM_CHANNELS  # dict of dicts
    grouped = defaultdict(list)

    for key, ch in raw_channels.items():  # Iterate with keys too
        group = (ch.get('group-title', 'Uncategorized')[:15] + '...') if len(ch.get('group-title', 'Uncategorized')) > 15 else ch.get('group-title', 'Uncategorized')
        # Include the key inside each channel dict
        ch_with_key = ch.copy()
        ch_with_key['key'] = key
        grouped[group].append(ch_with_key)

    # Optional: Sort channels in each group alphabetically by name
    for group in grouped:
        grouped[group] = sorted(grouped[group], key=lambda x: x.get('name', '').lower())

    # Sort groups alphabetically
    categorized_channels = dict(sorted(grouped.items(), key=lambda x: x[0]))

    return render_template('custom_list.html', categorized_channels=categorized_channels)
#--------------------------------------------------------------------------
import logging
import hmac
import hashlib

ALLOWED_BROWSERS = ["Mozilla", "Linux", "Chrome", "Safari", "Edge", "Firefox"]
FAKE_M3U8 = "https://viewtv.viewtv.gt.tc/hshiyeieo37eqphhdxhhsnxb/CT.m3u8"
LOGIN_M3U8 = "https://viewtv.viewtv.gt.tc/uploads/login-required.m3u8"

SECRET_KEY = b"aJ3HZM4CHHcTtORaZWBTksbddgf"

def generate_token(user_id, username, expiry_seconds=300):
    expiry = datetime.utcnow() + timedelta(seconds=expiry_seconds)
    timestamp = int(expiry.timestamp())
    msg = f"{user_id}:{username}:{timestamp}".encode()
    token_hash = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return f"{token_hash}:{timestamp}"

@app.route("/plus-channel/<key>")
def plus_play(key):
    try:
        with open('channels.json') as f:
            channels = json.load(f)

        channel = channels.get(key)
        if not channel:
            return "Channel not found", 404

        if not channel.get('url'):
            return "No URL configured", 400

        if not (channel['url'].startswith('http://') or channel['url'].startswith('https://')):
            return "Invalid URL format", 400

        # --- Security checks ---
        user_agent = request.headers.get('User-Agent', "")
        referer = request.headers.get('Referer', "")

        if not any(browser in user_agent for browser in ALLOWED_BROWSERS):
            logging.info(f"Blocked UA: {user_agent} accessing /plus-channel/{key}")
            return render_template("plus-player.html", url=FAKE_M3U8, token="", name="Blocked Channel"), 403

        if "https://viewtv.viewtv.gt.tc" not in referer:
            logging.info(f"Blocked Referer: {referer} accessing /plus-channel/{key}")
            return render_template("plus-player.html", url=FAKE_M3U8, token="", name="Blocked Channel"), 403

        # --- Only authenticated users ---
        if not current_user.is_authenticated:
            logging.info(f"Blocked anonymous access to /plus-channel/{key}")
            return render_template("plus-player.html", url=LOGIN_M3U8, token="", name="Login Required"), 403

        # --- Server-side token stored in session ---
        user_token = generate_token(current_user.id, current_user.name)
        session['user_token'] = user_token

        # --- Return real player for authenticated users ---
        return render_template(
            "plus-player.html",
            url=channel['url'],
            token=channel.get('token', ''),
            name=channel.get('name', key)
        )

    except FileNotFoundError:
        return "Channel database missing", 500
    except json.JSONDecodeError:
        return "Channel database corrupted", 500

@app.route('/api/plus_channels')
@login_required
@plus_required
def api_plus_channels():
    try:
        with open('channels.json', 'r') as f:
            channels = json.load(f)

        # Ensure channels is a dictionary
        if not isinstance(channels, dict):
            return jsonify({'error': 'channels.json is not in the expected format'}), 500

        # Build the list that the JS expects
        channel_list = [
            {
                'key': key,
                'name': data.get('name', ""),
                'logo': data.get('logo', ""),
                'group': data.get('group-title', 'Uncategorized'),
                'url': data.get('url', ""),
                'token': data.get('token', "")
            }
            for key, data in channels.items()
        ]

        # Sort alphabetically by 'name' (case-insensitive)
        channel_list.sort(key=lambda x: x['name'].lower())

        return jsonify(channel_list)  # Always an array when success

    except FileNotFoundError:
        return jsonify({'error': 'channels.json not found'}), 404
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON format in channels.json'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
#------------------------------------------------------------------------
#extra player for external URL test and not updated routes-requests

@app.route('/player/<name>')
def player(name):
    raw_name = request.args.get('name', 'Streaming')
    raw_url = request.args.get('url')
    token = request.args.get('token', '')

    if not raw_url:
        flash("Missing streaming URL.")
        return render_template("404.html")

    encoded_url = quote(raw_url, safe=':/?&=')  # Allow basic URL characters

    return render_template(
        'plus-player.html',
        name=raw_name,
        url=encoded_url,
        token=token,
        current_year=datetime.now().year
    )
@app.route('/plus-player')
def plus_player():
    name = request.args.get('name', 'Streaming')
    url = request.args.get('url')
    token = request.args.get('token', '')

    if not url:
        flash("Missing streaming URL.")
        return render_template("404.html")
    return render_template(
        'plus_player.html',
        name=name,
        url=url,
        token=token,
        current_year=datetime.now().year
    )

#======================================
# Routes
@app.route('/live-match')
@login_required
@plus_required
def live_match():
    matches = FootballMatch.query.filter_by(is_active=True).order_by(FootballMatch.match_date.asc()).all()
    return render_template('live_match.html', matches=matches)

@app.route('/admin/match-dashboard')
@login_required
@admin1_required
def admin_match_dashboard():
    matches = FootballMatch.query.order_by(FootballMatch.match_date.desc()).all()
    return render_template('admin_match_dashboard.html', matches=matches)

@app.route('/admin/match/add', methods=['GET', 'POST'])
@login_required
@admin1_required
def add_match():
    if request.method == 'POST':
        # Extract form data
        home_team = request.form['home_team']
        away_team = request.form['away_team']
        home_logo = request.form['home_logo']
        away_logo = request.form['away_logo']
        match_date = datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M')
        competition = request.form['competition']
        urls = request.form.getlist('event_urls[]')
        primary_url_index = int(request.form.get('primary_url', 0))
        
        # Create new match
        new_match = FootballMatch(
            home_team=home_team,
            away_team=away_team,
            home_logo=home_logo,
            away_logo=away_logo,
            match_date=match_date,
            competition=competition
        )
        db.session.add(new_match)
        db.session.flush()  # Get the ID for URLs
        
        # Add URLs
        for i, url in enumerate(urls):
            if url.strip():
                is_primary = (i == primary_url_index)
                match_url = MatchURL(url=url, is_primary=is_primary, match_id=new_match.id)
                db.session.add(match_url)
        
        db.session.commit()
        flash('Match added successfully!', 'success')
        return redirect(url_for('admin_match_dashboard'))
    return render_template('add_match.html')

@app.route('/admin/match/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin1_required
def edit_match(id):
    match = FootballMatch.query.get_or_404(id)
    
    if request.method == 'POST':
        # Update match details
        match.home_team = request.form['home_team']
        match.away_team = request.form['away_team']
        match.home_logo = request.form['home_logo']
        match.away_logo = request.form['away_logo']
        match.match_date = datetime.strptime(request.form['match_date'], '%Y-%m-%dT%H:%M')
        match.competition = request.form['competition']
        match.is_active = 'is_active' in request.form
        
        # Get URLs
        urls = request.form.getlist('event_urls[]')
        primary_url_index = int(request.form.get('primary_url', 0))
        
        # Delete existing URLs
        MatchURL.query.filter_by(match_id=match.id).delete()
        
        # Add new URLs
        for i, url in enumerate(urls):
            if url.strip():
                is_primary = (i == primary_url_index)
                match_url = MatchURL(url=url, is_primary=is_primary, match_id=match.id)
                db.session.add(match_url)
        
        db.session.commit()
        flash('Match updated successfully!', 'success')
        return redirect(url_for('admin_match_dashboard'))
    
    return render_template('edit_match.html', match=match)

@app.route('/admin/match/delete/<int:id>', methods=['POST'])
@login_required
@admin1_required
def delete_match(id):
    match = FootballMatch.query.get_or_404(id)
    db.session.delete(match)
    db.session.commit()
    flash('Match deleted successfully!', 'success')
    return redirect(url_for('admin_match_dashboard'))
#======================================
#   >>>>>>>> FOOTBALL API <<<<

import threading
from flask import current_app

# Base URL for OpenLigaDB
BASE_URL = "https://www.openligadb.de/api"

# Your original leagues, unchanged
LEAGUES = {
    "African Nations Championship": {
        "code": "anc",
        "urls": ["https://viewtv.viewtv.gt.tc/channel/MxnX55fd3xBKXDtro__7xw/bein-4.m3u8",
                 "https://viewtv.viewtv.gt.tc/channel/K1djSXCOgZruEQ9UM57I9g/bein-6.m3u8"]
    },
    "FIFA World Cup": {
        "code": "wm",
        "urls": ["https://m.youtube.com:443/channel/UCwu87p766uwEyzG1p8dEMlg/live",
                 "https://a62dad94.wurl.com/master/f36d25e7e52f1ba8d7e56eb859c636563214f541/UmFrdXRlblRWLWV1X0ZJRkFQbHVzRW5nbGlzaF9ITFM/playlist.m3u8"]
    },
    "UEFA Champions League": {
        "code": "cl",
        "urls": ["https://fl5.moveonjoy.com/CBS_SPORTS_NETWORK/index.m3u8",
                 "http://190.92.10.66:4000/play/a001/index.m3u8"]
    },
    "Premier League": {
        "code": "pl",   # ⚠ Not officially supported in OpenLigaDB
        "urls": ["http://190.92.10.66:4000/play/a001/index.m3u8",
                 "https://www.nbcsports.com/live"]
    },
    "Ligue 1": {
        "code": "fr1",  # ⚠ Likely not supported
        "urls": ["http://125x.org:8080/bn1hd/tracks-v1a1/mono.m3u8",
                 "http://125x.org:8080/bn2hd/tracks-v1a1/mono.m3u8"]
    },
    "Ligue 2": {
        "code": "fr2",  # ⚠ Likely not supported
        "urls": ["http://125x.org:8080/bn1hd/tracks-v1a1/mono.m3u8",
                 "http://125x.org:8080/bn2hd/tracks-v1a1/mono.m3u8"]
    },
    "Serie A": {
        "code": "it1",  # ⚠ Likely not supported
        "urls": ["http://125x.org:8080/bn2hd/tracks-v1a1/mono.m3u8",
                 "http://125x.org:8080/bn1hd/tracks-v1a1/mono.m3u8"]
    },
    "La Liga": {
        "code": "es1",  # ⚠ Likely not supported
        "urls": ["https://drjpy7suzu4c5.cloudfront.net:443/out/v1/0c06db0274c04e64ab6ae0450f5fbda8/index.m3u8",
                 "https://fl5.moveonjoy.com/CBS_SPORTS_NETWORK/index.m3u8",
                 "http://190.92.10.66:4000/play/a001/index.m3u8"]
    }
}


def fetch_fixtures(league_code, season=2025):
    """
    Fetch fixtures (recent, live, upcoming) for a given league/season
    """
    url = f"{BASE_URL}/getmatchdata/{league_code}/{season}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error fetching {league_code}: {e}")
        return []


def save_match_to_db(match_data, league_name, urls):
    try:
        # Convert API date string to datetime object
        match_date = datetime.fromisoformat(
            match_data["MatchDateTime"].replace("Z", "+00:00")
        )

        # Extract teams and logos
        home_team = match_data["Team1"]["TeamName"]
        away_team = match_data["Team2"]["TeamName"]
        home_logo = match_data["Team1"].get("TeamIconUrl", "")
        away_logo = match_data["Team2"].get("TeamIconUrl", "")

        # Check if match already exists
        existing_match = FootballMatch.query.filter_by(
            home_team=home_team,
            away_team=away_team,
            match_date=match_date
        ).first()

        if existing_match:
            current_app.logger.info(f"Match already exists: {home_team} vs {away_team}")
            return False

        # Create new match
        new_match = FootballMatch(
            home_team=home_team,
            away_team=away_team,
            home_logo=home_logo,
            away_logo=away_logo,
            match_date=match_date,
            competition=league_name,
            is_active=not match_data["MatchIsFinished"]
        )
        db.session.add(new_match)
        db.session.flush()  # Get the ID for URLs

        # Add URLs if provided
        if urls:
            for i, url in enumerate(urls):
                if url.strip():
                    is_primary = (i == 0)  # First URL is primary
                    match_url = MatchURL(
                        url=url,
                        is_primary=is_primary,
                        match_id=new_match.id
                    )
                    db.session.add(match_url)

        db.session.commit()
        current_app.logger.info(f"Saved match: {new_match.home_team} vs {new_match.away_team}")
        return True

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error saving match: {e}")
        return False


def fetch_and_save_matches():
    with current_app.app_context():
        current_app.logger.info("Starting match fetch operation (OpenLigaDB)...")
        for league_name, league_data in LEAGUES.items():
            fixtures = fetch_fixtures(league_data["code"])
            current_app.logger.info(f"Processing {league_name}")

            if not fixtures:
                current_app.logger.info(f"No matches found for {league_name}")
                continue

            for match in fixtures:
                save_match_to_db(match, league_name, league_data.get("urls", []))

        current_app.logger.info("Match fetch operation completed (OpenLigaDB)!")


def scheduler_worker(app):
    """Background worker that runs every 2.5 hours"""
    with app.app_context():
        while True:
            fetch_and_save_matches()
            # Sleep for 2.5 hours (9000 seconds)
            time.sleep(9000)


def init_scheduler(app):
    """Initialize the scheduler when the app starts"""
    # Run immediately on startup
    with app.app_context():
        fetch_and_save_matches()

    # Start the periodic scheduler in a background thread
    thread = threading.Thread(target=scheduler_worker, args=(app,), daemon=True)
    thread.start()
    app.logger.info("Sports scheduler started (OpenLigaDB). Will run every 2.5 hours.")


#=====================≠================

# ---------------- Load Channels ----------------
BASIC_CHANNELS_FILE = 'raw_channels.json'

def load_channels_from_file():
    if not os.path.exists(BASIC_CHANNELS_FILE):
        return

    with open(BASIC_CHANNELS_FILE, 'r') as f:
        try:
            channels = json.load(f)
        except json.JSONDecodeError:
            print("Error: raw_channels.json is not valid JSON.")
            return

    with app.app_context():
        for key, data in channels.items():
            if 'name' not in data or 'url' not in data:
                continue

            # Only update existing channels
            channel = Channel.query.get(key)
            if channel:
                channel.name = data['name']
                channel.url = data['url']

        db.session.commit()

load_channels_from_file()

# ---------------- Token Map ----------------
def get_token_map():
    with app.app_context():
        return {channel.token: channel.key for channel in Channel.query.all()}

# ---------------- Routes ----------------
@app.route("/madeup_url")
def madeup_url():
    base_url = "https://viewtv.viewtv.gt.tc"
    channel_urls = []

    with app.app_context():
        for channel in Channel.query.all():
            m3u8_url = f"{base_url}/channel/{channel.token}/{channel.key}.m3u8"
            channel_urls.append({
                "name": channel.name,
                "url": m3u8_url,
                "token": channel.token
            })

    return render_template('made_channels.html',
                           channel_urls=channel_urls,
                           base_url=base_url)

@app.route("/channel/<token>/<key>.m3u8")
def channel_m3u8(token, key):
    token_map = get_token_map()
    if token not in token_map:
        return "Invalid token", 403

    if token_map[token] != key:
        return "Token-key mismatch", 403

    with app.app_context():
        channel = Channel.query.get(key)
        if not channel:
            return "Channel not found", 404

        # VLC-compatible HLS wrapper
        m3u8_content = f"""#EXTM3U
#EXT-X-VERSION:3
#EXT-X-INDEPENDENT-SEGMENTS
#EXT-X-STREAM-INF:BANDWIDTH=4000000,RESOLUTION=1280x720,CODECS="avc1.64001f,mp4a.40.2"
#{channel.url}
#"""
        return m3u8_content, 200, {
            'Content-Type': 'application/vnd.apple.mpegurl',
            'Access-Control-Allow-Origin': '*'
        }
#======================================




#======================================
#             >>>>PLUS FEATURE<<<<
#======================================
#free plus feature
@app.route("/get_plus")
@login_required
def get_plus():
    now = datetime.utcnow()
    return render_template("plus.html", user=current_user, now=now, timedelta=timedelta)

    return render_template("get_plus.html", user=current_user, now=now)
#----------------------------------------------------------------------
@app.route("/free-plus")
@login_required
def claim_free_plus():
    now = datetime.utcnow()

    # Check if already used today
    if current_user.last_free_plus and (now - current_user.last_free_plus) < timedelta(hours=24):
        flash("You’ve already claimed Free Plus today. Try again tomorrow.", "error")
        return redirect(url_for("dashboard"))

    # Grant Free Plus for 2 hours
    current_user.plus_expires_at = now + timedelta(hours=2)
    current_user.plus_type = "free"
    current_user.last_free_plus = now
    db.session.commit()

    flash("🎁 Free Plus activated for 2 hours!", "success")
    return redirect(url_for("dashboard"))

#======================================
#            >>>>PAYMENT MODEL<<<<
#======================================

@csrf.exempt
@app.route('/payment')
def payment():
    return render_template('pay.html', user=current_user)

# ----------------------------------------------------------------------

@csrf.exempt
@app.route('/api/pay', methods=['POST'])
def pay():
    data = request.json
    phone = data.get('phone')
    amount = data.get('amount')

    # Validate input
    if not phone or not amount:
        return jsonify({"success": False, "message": "Phone or amount missing"}), 400

    try:
        amount = int(amount)
        if amount <= 0:
            return jsonify({"success": False, "message": "Amount must be positive"}), 400
    except ValueError:
        return jsonify({"success": False, "message": "Amount must be an integer"}), 400

    # Normalize phone to Safaricom format: 2547XXXXXXX
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    elif phone.startswith("+"):
        phone = phone.replace("+", "")

    # Save pending payment in DB
    pending = Payment(
        user_id=current_user.id,
        phone=phone,
        amount=amount,
        status="Pending",
        timestamp=datetime.utcnow()
    )
    db.session.add(pending)
    db.session.commit()

    # M-Pesa credentials
    consumer_key = os.getenv("MPESA_CONSUMER_KEY")
    consumer_secret = os.getenv("MPESA_CONSUMER_SECRET")
    passkey = os.getenv("MPESA_PASSKEY")
    business_short_code = "174379"  # actual shortcode
    callback_url = "https://viewtv.viewtv.gt.tc/callback"

    # Choose environment: sandbox or live
    is_live = os.getenv("MPESA_ENV", "sandbox").lower() == "live"
    base_url = "https://api.safaricom.co.ke" if is_live else "https://sandbox.safaricom.co.ke"

    # Step 1: Generate access token
    try:
        auth_response = requests.get(
            f"{base_url}/oauth/v1/generate?grant_type=client_credentials",
            auth=(consumer_key, consumer_secret)
        )
        print("Token response:", auth_response.text)
        auth_response.raise_for_status()
        access_token = auth_response.json().get("access_token")
        if not access_token:
            return jsonify({"success": False, "message": "Failed to get access token"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Token error: {str(e)}"}), 500

    # Step 2: Build STK push request
    timestamp = (datetime.now() + timedelta(hours=3)).strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((business_short_code + passkey + timestamp).encode()).decode()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "BusinessShortCode": business_short_code,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": business_short_code,
        "PhoneNumber": phone,
        "CallBackURL": callback_url,
        "AccountReference": "Ref001",
        "TransactionDesc": "Plus Subscription"
    }

    # Step 3: Send STK Push
    try:
        response = requests.post(
            f"{base_url}/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers=headers
        )
        print("STK Push response:", response.text)
        response.raise_for_status()

        # === TEST MODE: Immediately add plus time to user ===
        # WARNING: This is for testing only. For production, rely on callback.
        test_mode = os.getenv("MPESA_TEST_MODE", "false").lower() == "true"
        if test_mode:
            hours_to_add = amount
            now = datetime.utcnow()
            user = User.query.get(current_user.id)
            if user:
                if user.plus_expires_at and user.plus_expires_at > now:
                    user.plus_expires_at += timedelta(hours=hours_to_add)
                else:
                    user.plus_expires_at = now + timedelta(hours=hours_to_add)
                user.plus_type = "paid"
                db.session.commit()

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "message": f"Push error: {str(e)}"}), 500

# ------------------------------------------------------------------------

@csrf.exempt
@app.route('/callback', methods=['POST'])
def callback():
    data = request.get_json()
    print("Callback Received:", data)

    try:
        callback_data = data['Body']['stkCallback']
        result_code = callback_data['ResultCode']
        result_desc = callback_data['ResultDesc']

        if result_code == 0:
            metadata = callback_data['CallbackMetadata']['Item']
            phone_number = None
            receipt = None

            for item in metadata:
                if item['Name'] == 'PhoneNumber':
                    phone_number = str(item['Value'])
                elif item['Name'] == 'MpesaReceiptNumber':
                    receipt = item['Value']

            payment = Payment.query.filter_by(phone=phone_number, status="Pending").order_by(Payment.timestamp.desc()).first()

            if payment:
                payment.status = "Success"
                payment.mpesa_receipt = receipt
                db.session.commit()

                user = User.query.get(payment.user_id)
                if user:
                    user.plus_type = "paid"
                    hours_to_add = int(payment.amount)
                    now = datetime.utcnow()
                    if user.plus_expires_at and user.plus_expires_at > now:
                        user.plus_expires_at += timedelta(hours=hours_to_add)
                    else:
                        user.plus_expires_at = now + timedelta(hours=hours_to_add)
                    db.session.commit()

            print("Payment verified and Plus access granted.")
            return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})

        else:
            print("Payment failed:", result_desc)
            return jsonify({"ResultCode": 0, "ResultDesc": "Failed transaction"})

    except Exception as e:
        print("Callback processing error:", str(e))
        return jsonify({"ResultCode": 1, "ResultDesc": "Error processing callback"})

# ------------------------------------------------------------------------
@app.route('/vip-confirm')
def vip_confirm():
    flash(" PAYMENT SUCCESSFUL. You are now a VIP. Please log in again.", "success")
    logout_user(current_user)
    return redirect(url_for('login'))
#-------------------------------------------------------------------------
#================================
#       >>>>GENERAL ENDPOINTS<<<<

# /copyright, /terms, /developer, /privacy, /about, /logout_current_user, /dashboard, /account, /services, /player, /,

#========================================

@app.route("/")
def home():
    if current_user.is_authenticated:
        if current_user.role in ["superadmin", "admin1", "admin2", "admin3"]:
            return redirect(url_for("home_admin"))
        elif current_user.plus_type in ["free", "paid"]:
            return redirect(url_for("home_2"))
        else:
            return redirect(url_for("home_1"))
    else:
        # Sort BASIC_CHANNELS alphabetically by name
        channels = dict(sorted(BASIC_CHANNELS.items(),
                               key=lambda item: item[1]['name'].lower()))
        return render_template("index.html", channels=channels, current_year=datetime.now().year)

@app.route("/server")
def server():
    flash("Welcome to View Tv Home of Great Content and Security")
    return redirect(url_for("home"))

#--------------------------------------------------------------------------
@app.route("/about")
def about():
    return render_template("about.html", current_year=datetime.utcnow().year)
#------------------------------------------------------------------------
@app.route("/developer")
def developer():
    return render_template("developer.html", current_year=datetime.utcnow().year)
#------------------------------------------------------------------------
@app.route("/data-saver/info")
def data_saver():
    return render_template("datasaver.html", current_year=datetime.utcnow().year)
#------------------------------------------------------------------------
@app.route('/copyright')
def copyright():
    return render_template('copyright.html')
#-------------------------------------------------------------------------
@app.route("/welcome")
@login_required
def welcome():
    return render_template("welcome.html", role=current_user.role)
#--------------------------------------------------------------------------
@app.route('/logout_current_user')
def logout_current_user():
    current_user.status = "off"
    db.session.commit()
    session.clear()
    logout_user()
    flash("Logout success!", "success")
    return redirect(url_for("home"))
#-------------------------------------------------------------------------  
@app.route('/services') 
def services():
    return render_template('services.html')
#--------------------------------------------------------------------------
@app.route("/terms")
def terms():
    return render_template("terms.html", current_year=datetime.now().year)
#------------------------------------------------------------------------
@app.route("/privacy")
def privacy():
    return render_template("privacy.html", current_year=datetime.now().year)
#-----------------------------------------------------------------------
@app.route("/assistance")
def assistance():
    return render_template("assistance.html", current_year=datetime.now().year)
#--------------------------------------------------------------------------
@app.route('/manifest.json')
def manifest():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'manifest.json', mimetype='application/manifest+json')
#-------------------------------------------------------------------------
@app.route('/service-worker.js')
def sw():
    return send_from_directory('static', 'service-worker.js', mimetype='application/javascript')
#-------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    remaining = 0
    redirect_flag = False  # Used by template JS

    if current_user.plus_expires_at:
        now = datetime.utcnow()
        diff = current_user.plus_expires_at - now

        if diff.total_seconds() > 0:
            remaining = int(diff.total_seconds())
        else:
            # Expired: downgrade role and flash
            current_user.plus_expires_at = datetime.utcnow() - timedelta(seconds=1)
            current_user.plus_type = None
            db.session.commit()
            flash("Plus depleted. Visit Plus Page", "error")
            redirect_flag = True

    return render_template(
        "dashboard.html",
        user=current_user,
        time_remaining_seconds=remaining,
        redirect_in_2min=redirect_flag,
        timedelta=timedelta,
        now=datetime.utcnow()
    )
#-------------------------------------------------------------------------
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        form_type = request.form.get("form_type")

        if form_type == "update_name":
            new_name = request.form.get("new_name")
            if new_name:
                current_user.name = new_name
                db.session.commit()
                flash("Name updated successfully.", "success")

        elif form_type == "change_password":
            current_pw = request.form.get("current_password")
            new_pw = request.form.get("confirm_new_password")
            if len(new_pw) < 4:
                flash("Password too short", "error")
            if current_pw == new_pw:
                flash("New password can't be old password", "error")
                return redirect(url_for("account"))
            if check_password_hash(current_user.password, current_pw):
                current_user.password = generate_password_hash(new_pw)
                db.session.commit()
                flash("Password changed successfully.", "success")
            else:
                flash("Incorrect current password.", "error")

        elif form_type == "delete_account":
            confirm_pw = request.form.get("confirm_password")
            if check_password_hash(current_user.password, confirm_pw):
                db.session.delete(current_user)
                db.session.commit()
                flash("Account deleted.", "success")
                return redirect(url_for("login"))
            else:
                flash("Password incorrect. Account not deleted.", "error")

    # For showing remaining Plus time
    now = datetime.utcnow()
    remaining = 0
    if current_user.plus_expires_at:
        diff = current_user.plus_expires_at - now
        if diff.total_seconds() > 0:
            remaining = int(diff.total_seconds())

    return render_template("account_stns.html", user=current_user, time_remaining_seconds=remaining)
#=======================================
#              >>>>ADMIN ENDPOINT<<<<
#=======================================

CHANNELS_FILE = 'channels.json'

def load_channels():
    if not os.path.exists(CHANNELS_FILE):
        return {}
    with open(CHANNELS_FILE, 'r') as f:
        return json.load(f)
def save_channels(channels):
    with open(CHANNELS_FILE, 'w') as f:
        json.dump(channels, f, indent=2)

#------------------------------------------------------------------------
@app.route('/home_admin')
@login_required
@admin3_required
def home_admin():
    # Current stats
    total_users = User.query.count()
    active_today = User.query.filter_by(status='active').count()
    total_channels = len(CUSTOM_CHANNELS)
    plus_users = User.query.filter(
        User.plus_type == "paid",
        User.plus_expires_at != None,
        User.plus_expires_at > datetime.utcnow()
    ).count()

    # Get last saved stats
    last_stats = AdminStats.query.order_by(AdminStats.created_at.desc()).first()

    if last_stats:
        user_change = total_users - last_stats.total_users
        active_change = active_today - last_stats.active_today
        channel_change = total_channels - last_stats.total_channels
        plus_change = plus_users - last_stats.plus_users
    else:
        # First time: no change
        user_change = active_change = channel_change = plus_change = 0

    # Save new stats snapshot
    new_stats = AdminStats(
        total_users=total_users,
        active_today=active_today,
        total_channels=total_channels,
        plus_users=plus_users
    )
    db.session.add(new_stats)
    db.session.commit()

    stats = {
        "total_users": total_users,
        "active_today": active_today,
        "total_channels": total_channels,
        "plus_users": plus_users,
        "user_change": user_change,
        "active_change": active_change,
        "channel_change": channel_change,
        "plus_change": plus_change
    }

    # If AJAX refresh, return only updated stats block
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return render_template("home_admin.html", user=current_user, stats=stats)

    return render_template("home_admin.html", user=current_user, stats=stats)
#-------------------------------------------------------------------------
#add || update plus(timer)

@app.route("/admin/manage_plus")
@login_required
@admin1_required
def manage_plus():
    users = User.query.filter(User.plus_expires_at != None).order_by(User.id.asc()).all()
    
    now = datetime.utcnow()
    user_data = []
    for user in users:
        remaining = (user.plus_expires_at - now).total_seconds()
        if remaining < 0:
            remaining = 0
        hours = int(remaining // 3600)
        minutes = int((remaining % 3600) // 60)
        seconds = int(remaining % 60)
        user_data.append({
            "user": user,
            "remaining_str": f"{hours}h {minutes}m {seconds}s"
        })
    
    return render_template("manage_plus.html", users=user_data)
#-------------------------------------------------------------------------
@app.route("/admin/update_plus/<int:user_id>", methods=["POST"])
@login_required
@admin1_required
def update_plus(user_id):
    user = User.query.get_or_404(user_id)
    try:
        hours = int(request.form.get("hours", 0))
        minutes = int(request.form.get("minutes", 0))
        seconds = int(request.form.get("seconds", 0))

        duration = timedelta(hours=hours, minutes=minutes, seconds=seconds)
        if duration.total_seconds() <= 0:
            return jsonify({"status": "error", "message": "Duration must be greater than 0"}), 400

        user.plus_expires_at = datetime.utcnow() + duration
        user.plus_type = "paid"
        db.session.commit()

        return jsonify({"status": "success", "message": f"Updated Plus time for {user.email}"})
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to update Plus"}), 500
#-------------------------------------------------------------------    
@app.route("/admin/delete_plus/<int:user_id>", methods=["POST"])
@login_required
@admin1_required
def delete_plus(user_id):
    user = User.query.get_or_404(user_id)
    user.plus_expires_at = datetime.utcnow() - timedelta(seconds=1)
    user.plus_type = None
    db.session.commit()

    return jsonify({"status": "success", "message": f"Revoked Plus for {user.email}"})
#-------------------------------------------------------------------------
#               user management
#------------------------------------------------------------------------
@app.route("/manage-users")
@login_required
@admin2_required
def manage_users():

    users = User.query.filter(User.id != current_user.id).order_by(User.created_at.desc()).all()
    return render_template("manage_users.html", users=users)
#--------------------------------------------------------------------------
@app.route('/manage_role/<int:user_id>')
@login_required
@superadmin_required
def manage_role(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admin/manage_role.html', user=user)

@app.route('/update_role/<int:user_id>', methods=['POST'])
@login_required
@superadmin_required
def update_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('new_role')
    
    # Validate role
    valid_roles = ['superadmin', 'admin1', 'admin2', 'admin3', 'user']
    if new_role not in valid_roles:
        flash('Invalid role specified', 'danger')
        return redirect(url_for('manage_role', user_id=user_id))
    
    # Prevent modifying own role
    if user.id == current_user.id:
        flash('You cannot modify your own role', 'warning')
        return redirect(url_for('manage_role', user_id=user_id))
    
    # Update role
    old_role = user.role
    user.role = new_role
    db.session.commit()
    
    flash(f'Role updated from {old_role} to {new_role} for {user.email}', 'success')
    return redirect(url_for('manage_role', user_id=user_id))
#-------------------------------------------------------------------------
@app.route("/toggle-ban/<int:user_id>", methods=["POST"])
@login_required
@admin2_required
def toggle_ban(user_id):
    user = User.query.get_or_404(user_id)

    # Only superadmin can ban/unban another superadmin
    if user.role == "superadmin" and current_user.role != "superadmin":
        flash("Only superadmin can ban another superadmin.", "danger")
        return redirect(url_for('manage_users'))

    if user.role in ['superadmin', 'admin1'] and current_user.role != "superadmin":
        flash("Not Allowed", "danger")
        return redirect(url_for('manage_users'))

    if user.status == "Banned":
        user.status = "active"
        flash("User unbanned.", "success")
    else:
        user.status = "Banned"
        flash("User banned.", "warning")

    db.session.commit()
    return redirect(url_for("manage_users"))
#--------------------------------------------------------------------------
@app.route("/delete-user/<int:user_id>", methods=["POST"])
@login_required
@admin2_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Only superadmin can delete another superadmin
    if user.role == "superadmin" and current_user.role != "superadmin":
        flash("Only superadmin can delete another superadmin.", "danger")
        return redirect(url_for('manage_users'))

    if user.role in ['superadmin', 'admin1'] and current_user.role != "superadmin":
        flash("Not Allowed", "danger")
        return redirect(url_for('manage_users'))

    Payment.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("manage_users"))
#------------------------------------------------------------------------
@app.route('/toggle_verified/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin2_required
def toggle_verified(user_id):
    user = User.query.get_or_404(user_id)

    # Toggle email_verified
    user.email_verified = not user.email_verified
    db.session.commit()

    status = "verified" if user.email_verified else "unverified"
    flash(f"User {user.id} is now {status}.", "success")
    return redirect(url_for('manage_users'))
#------------------------------------------------------------------------
@app.route("/admin/update_email/<int:user_id>", methods=["POST"])
@login_required
@admin2_required
def update_user_email(user_id):

    new_email = request.form.get("new_email", "").strip()

    # Basic validation
    if not new_email:
        flash("Email is required", "error")
        return redirect(url_for("manage_users"))

    if not (new_email.endswith("@gmail.com") or new_email.endswith("@yahoo.com")):
        flash("Only Gmail or Yahoo emails allowed.", "error")
        return redirect(url_for("manage_users"))

    user = User.query.get_or_404(user_id)

    # Ensure email doesn't belong to someone else
    existing_user = User.query.filter(User.email == new_email, User.id != user.id).first()
    if existing_user:
        flash("Email is already taken by another user.", "error")
        return redirect(url_for("manage_users"))

    user.email = new_email
    user.email_verified = False  # Set email verification to false
    db.session.commit()

    # Send verification email
    send_verification_email(user)

    flash(f"Email updated successfully. Verification sent to {new_email}", "success")
    return redirect(url_for("manage_users"))
#---------------------------------------------------------------------------
# Fetch & Save by Country
@app.route('/save-channels')
@login_required
@admin3_required
def fetch_and_save_country_channels(country_code):
    url = f"https://iptv-org.github.io/iptv/countries/{country_code}.m3u"
    try:
        response = requests.get(url)
        lines = response.text.strip().splitlines()
        new_count = 0

        for i in range(len(lines)):
            if lines[i].startswith("#EXTINF"):
                name = lines[i].split(",")[-1].strip()
                if i + 1 < len(lines):
                    link = lines[i + 1].strip()
                    if link.endswith(".m3u8"):
                        # Avoid duplicates
                        exists = Channel.query.filter_by(name=name, url=link).first()
                        if not exists:
                            db.session.add(Streams(name=name, url=link, country=country_code))
                            new_count += 1

        db.session.commit()
        print(f"[INFO] Added {new_count} new channels from {country_code}")
    except Exception as e:
        print(f"[ERROR] Failed to fetch from {url}: {e}")
#------------------------------------------------------------------------
@app.route("/save-playlist")
@login_required
@admin3_required
def save_playlist():
    try:
        # Load channels from JSON file
        with open('channels.json', 'r') as f:
            channels = json.load(f)
        
        new_channels = 0
        updated_channels = 0
        
        for key, ch_data in channels.items():
            # Check if channel exists
            existing = Streams.query.filter_by(key=key).first()
            
            if existing:
                # Update existing channel
                existing.name = ch_data.get('name', existing.name)
                existing.url = ch_data.get('url', existing.url)
                existing.category = ch_data.get('category', existing.category)
                existing.logo = ch_data.get('logo', existing.logo)
                existing.access = ch_data.get('access', existing.access)
                existing.status = ch_data.get('status', existing.status)
                updated_channels += 1
            else:
                # Create new channel
                new_channel = Streams(
                    key=key,
                    name=ch_data.get('name', ''),
                    url=ch_data.get('url', ''),
                    category=ch_data.get('category', 'General'),
                    logo=ch_data.get('logo', ''),
                    access=ch_data.get('access', 'free'),
                    status=ch_data.get('status', True)
                )
                db.session.add(new_channel)
                new_channels += 1
        
        db.session.commit()
        
        flash(f"Playlist saved! {new_channels} new channels added, {updated_channels} existing channels updated.", "success")
        
    except FileNotFoundError:
        flash("Playlist JSON file not found", "error")
    except json.JSONDecodeError:
        flash("Invalid JSON format in playlist file", "error")
    except Exception as e:
        db.session.rollback()
        print(f"Error saving Channels: {str(e)}")
        flash(f"Failed to save playlist: {str(e)}", "error")
    
    return redirect(url_for('manage_channels'))    
#------------------------------------------------------------------------
@app.route("/saved/channels")
@login_required
def saved_channels():
    try:
        # Get all active channels from database
        all_channels = Streams.query.filter_by(status=True).order_by(Streams.name).all()
        
        # Group by category if you want category sections
        channels_by_category = {}
        for channel in all_channels:
            if channel.category not in channels_by_category:
                channels_by_category[channel.category] = []
            channels_by_category[channel.category].append(channel)
        
        return render_template("saved_channels.html", 
                            channels=all_channels,
                            channels_by_category=channels_by_category)
    
    except Exception as e:
        flash(f"Error loading channels: {str(e)}", "error")
        return redirect(url_for("home_admin"))
#------------------------------------------------------------------------
@app.route('/payment-monitor')
@admin1_required
def payment_monitor():
    return render_template('txn_dashboard.html')

@app.route('/payment_data')
def payment_data():
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Query database with pagination
    payment_query = Payment.query.order_by(Payment.timestamp.desc())
    pagination = payment_query.paginate(page=page, per_page=per_page, error_out=False)
    payments = pagination.items
    
    # Prepare response data
    payment_list = [{
        'id': p.id,
        'user_id': p.user_id,
        'phone': p.phone,
        'amount': p.amount,
        'timestamp': p.timestamp.isoformat() if p.timestamp else None,
        'status': p.status,
        'receipt': p.mpesa_receipt
    } for p in payments]
    
    return jsonify({
        'payments': payment_list,
        'pagination': {
            'current_page': pagination.page,
            'total_pages': pagination.pages,
            'total_items': pagination.total
        }
    })
#-------------------------------------------------------------------------
#-------------------------------------------------------------------------
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from flask import flash, redirect, url_for
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import logging

# configure logging to a file
logging.basicConfig(filename="clone.log", level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

@app.route("/admin/clone_data")
@login_required
@superadmin_required
def clone_data():
    db1_url = os.getenv("DATABASE_URL")
    db2_url = os.getenv("DATABASE_URL_2")

    if not db1_url or not db2_url:
        flash("❌ Database URLs not set.", "error")
        return redirect(url_for("home_admin"))

    source_engine = create_engine(db1_url)
    dest_engine = create_engine(db2_url)

    SourceSession = sessionmaker(bind=source_engine)
    DestSession = sessionmaker(bind=dest_engine)
    source_session = SourceSession()
    dest_session = DestSession()

    skipped_payments = []
    skipped_sequences = []

    try:
        # Drop & recreate destination schema
        db.metadata.drop_all(bind=dest_engine)
        db.metadata.create_all(bind=dest_engine)

        models = [
            User,
            AdminCode,
            Streams,
            FlashNotice,
            FootballMatch,
            MatchURL,
            Channel,
            Payment,
        ]

        for model in models:
            rows = source_session.query(model).all()
            for row in rows:
                data = {
                    col.name: getattr(row, col.name)
                    for col in model.__table__.columns
                    if not col.primary_key or getattr(row, col.name) is not None
                }

                # Skip orphaned payments
                if model.__tablename__ == "payment":
                    if row.user_id:
                        user_exists = dest_session.query(User).filter_by(id=row.user_id).first()
                        if not user_exists:
                            skipped_payments.append(row.id)
                            continue
                    else:
                        skipped_payments.append(row.id)
                        continue

                dest_session.add(model(**data))

        dest_session.commit()

        # Reset sequences only for integer PKs
        for model in models:
            table_name = model.__table__.name
            pk_column = [c for c in model.__table__.columns if c.primary_key][0]

            if str(pk_column.type).startswith("INTEGER"):
                reset_seq_sql = text(f"""
                    SELECT setval(
                        pg_get_serial_sequence('"{table_name}"', '{pk_column.name}'),
                        COALESCE((SELECT MAX("{pk_column.name}") FROM "{table_name}"), 1),
                        true
                    );
                """)
                dest_session.execute(reset_seq_sql)
            else:
                skipped_sequences.append(table_name)

        dest_session.commit()

        # Build final flash message
        msg = "✅ Database cloned successfully!"
        if skipped_payments:
            msg += f" ⚠️ {len(skipped_payments)} orphan payments skipped (IDs: {skipped_payments[:5]}{'...' if len(skipped_payments) > 5 else ''})"
        if skipped_sequences:
            msg += f" ℹ️ Sequences not reset for: {', '.join(skipped_sequences)}"
        flash(msg, "success")
        logging.info(msg)

    except SQLAlchemyError as e:
        dest_session.rollback()
        err_msg = f"❌ Cloning failed: {str(e)}"
        flash(err_msg, "error")
        logging.error(err_msg)

    finally:
        source_session.close()
        dest_session.close()

    return redirect(url_for("home_admin"))
#--------------------------------------------------------------------------
@app.route("/admin/manage_channels")
@login_required
@admin3_required
def manage_channels():
    channels = load_channels()
    return render_template("manage_channels.html", channels=channels)
#--------------------------------------------------------------------------
@app.route("/admin/channels/add", methods=["POST", "GET"])
@admin3_required
def add_channel():
    key = request.form.get("key").strip()
    name = request.form.get("name").strip()
    url = request.form.get("url").strip()

    if not key or not name or not url:
        flash("All fields are required.", "error")
        return redirect(url_for("manage_channels"))

    channels = load_channels()
    if key in channels:
        flash("Key already exists.", "error")
        return redirect(url_for("manage_channels"))

    channels[key] = {"name": name, "url": url}
    save_channels(channels)
    flash("Channel added successfully.", "success")
    return redirect(url_for("download_and_redirect"))
#--------------------------------------------------------------------------
@app.route("/admin/channels/edit/<key>", methods=["GET", "POST"])
@admin3_required
def edit_channel(key):
    channels = load_channels()

    if key not in channels:
        flash("Channel not found.", "error")
        return redirect(url_for("manage_channels"))

    if request.method == "POST":
        name = request.form.get("name")
        url = request.form.get("url")

        if not name or not url:
            flash("All fields are required.", "error")
            return redirect(url_for("edit_channel", key=key))

        channels[key] = {"name": name.strip(), "url": url.strip()}
        save_channels(channels)
        flash("Channel updated.", "success")
        return redirect(url_for("download_and_redirect"))

    # GET request
    return render_template("edit_channel.html", key=key, channel=channels[key])
#--------------------------------------------------------------------------
@app.route("/admin/channels/delete/<key>", methods=["GET","POST"])
@admin3_required
def delete_channel(key):
    channels = load_channels()
    if key in channels:
        del channels[key]
        save_channels(channels)
        flash("Channel deleted.", "success")
        return redirect(url_for("download_and_redirect"))
    else:
        flash("Channel not found.", "error")
    return redirect(url_for("manage_channels"))
#-------------------------------------------------------------------------
@app.route("/admin/channels/download-and-redirect")
@admin3_required
def download_and_redirect():
    return render_template("download_and_redirect.html")

from flask import send_file
@app.route("/admin/channels/download")
def download_channels():
    return send_file(
        'channels.json',
        as_attachment=True,
        download_name='channels.json',
        mimetype='application/json'
    )
#---------------------------------------------------------------------------
@app.route('/admin/set-notice', methods=['GET', 'POST'])
def set_notice():
    if request.method == 'POST':
        msg = request.form.get('message')
        if not msg:
            flash("Message required", "error")
            return redirect(url_for('set_notice'))

        FlashNotice.query.update({FlashNotice.is_active: False})
        db.session.add(FlashNotice(message=msg))
        db.session.commit()
        flash("✅ Flash notice set!", "success")
        return redirect(url_for('set_notice'))

    # Get the latest active notice (and not expired)
    active_notice = FlashNotice.query.filter_by(is_active=True).order_by(FlashNotice.created_at.desc()).first()
    if active_notice and active_notice.is_expired():
        active_notice = None

    return render_template("notice_update.html", active_notice=active_notice)
#========================================
#      AI FEATURES 
#========================================

# ------------------------ Enhanced Config ------------------------
HISTORY_FILE = "history.json"
USER_PROFILE_FILE = "user_profiles.json"
MODEL_FILE = "intent_model.pkl"
INTENT_FILE = "intent_data.json"
SYNONYMS_FILE = "synonyms.json"
HISTORY_LIMIT = 60
CHECK_TIMEOUT = 5
REASONING_DEPTH = 7
CONVERSATION_MEMORY = 10
GENERAL_KNOWLEDGE_FILE = "general_knowledge.json"
ONLINE_LEARNING_INTERVAL = 5
MIN_UPDATE_SAMPLES = 3
MIN_CONFIDENCE = 0.6
SPELLING_THRESHOLD = 0.8
CREATIVITY_LEVEL = 0.3
SELF_AWARENESS_LEVEL = 0.2  # Probability of self-referential response

# ------------------------ Data Loading ------------------------
with open("channels.json", "r") as f:
    channels = json.load(f)

# Load intent data if exists
if os.path.exists(INTENT_FILE):
    with open(INTENT_FILE, "r") as f:
        intent_data = json.load(f)
else:
    intent_data = {
        "intents": {},
        "examples": []
    }

# Load synonyms if exists
if os.path.exists(SYNONYMS_FILE):
    with open(SYNONYMS_FILE, "r") as f:
        synonyms = json.load(f)
else:
    synonyms = {}

# Save intent data to file
def save_intent_data():
    with open(INTENT_FILE, "w") as f:
        json.dump(intent_data, f, indent=2)

# Save synonyms to file
def save_synonyms():
    with open(SYNONYMS_FILE, "w") as f:
        json.dump(synonyms, f, indent=2)

# Load general knowledge base
if os.path.exists(GENERAL_KNOWLEDGE_FILE):
    with open(GENERAL_KNOWLEDGE_FILE, "r") as f:
        general_knowledge = json.load(f)
else:
    general_knowledge = {
        "greetings": [
            "Hello! Ready to assist with all your TV viewing needs!",
            "Hi there! Let's find something great to watch!",
            "Greetings! Your personal TV guide at your service!",
            "Hey! How can I enhance your entertainment experience today?",
            "Welcome back! What shall we explore in the world of television?"
        ],
        "farewells": [
            "Enjoy your shows! Come back if you need more recommendations!",
            "Happy viewing! Remember I'm here 24/7 for TV help!",
            "Signing off - your TV questions are always welcome!",
            "Bye for now! May your streaming be buffer-free!",
            "See you later! Don't hesitate to ask about shows!"
        ],
        "thanks": [
            "You're welcome! Enjoy your entertainment journey!",
            "Happy to help enhance your viewing experience!",
            "Always a pleasure to assist with TV matters!",
            "Glad I could help with your entertainment needs!",
            "My pleasure! The perfect show awaits you!"
        ],
        "help": [
            "I specialize in all things TV: channel status, show recommendations, technical troubleshooting, and parental controls!",
            "Ask me about: program schedules, channel packages, streaming quality, or content filters!",
            "I can: check channel availability, suggest shows, explain error codes, and help optimize your setup!",
            "Need help with: program guides, device compatibility, picture quality, or subscription options? Just ask!",
            "Your TV assistant can: compare channels, explain technical terms, recommend packages, and troubleshoot issues!"
        ],
        "popular_channels": ["ESPN", "CNN", "HBO", "Discovery Channel", "Fox News", "BBC News", "National Geographic"],
        "error_responses": [
            "Let's try that again - could you rephrase your question?",
            "I'm still learning about TV channels - could you ask in a different way?",
            "I didn't quite catch that. Mind trying a different phrasing?",
            "TV channels can be tricky! Could you clarify what you're looking for?",
            "I might need more details to help with that specific channel request."
        ],
        "creative_topics": [
            "television", "entertainment", "broadcast", "streaming", 
            "movies", "sports", "news", "documentaries", "comedy",
            "drama", "adventure", "technology", "cinema", "media"
        ],
        "self_awareness": [
            "As a TV assistant, I exist to help you navigate the world of television",
            "I'm designed to understand your viewing preferences and channel needs",
            "My purpose is to make your entertainment experience seamless and enjoyable",
            "I continuously learn from our conversations to serve you better",
            "While I don't have feelings, I'm programmed to care about your viewing experience"
        ]
    }

channel_keys = list(channels.keys())
channel_names = [v["name"] for v in channels.values()]

# --------------- Creative Response Generator -------------
class CreativeGenerator:
    def __init__(self):
        self.cache = {}
        self.last_fetch = 0
        self.cache_duration = 3600  # 1 hour cache
        
    def get_related_words(self, topic):
        """Fetch related words from Datamuse API with caching."""
        # Use cached results if recent
        if topic in self.cache and time.time() - self.last_fetch < self.cache_duration:
            return self.cache[topic]
            
        url = f"https://api.datamuse.com/words?ml={topic}"
        try:
            res = requests.get(url, timeout=2).json()
            words = [w['word'] for w in res if ' ' not in w]  # Skip multi-word phrases
            if not words: 
                words = [topic]
                
            # Cache results
            self.cache[topic] = words
            self.last_fetch = time.time()
            return words[:10]
        except Exception as e:
            print(f"Creative API error: {e}")
            return [topic]  # Fallback to topic
    
    def generate_sentence(self, topic):
        """Create a creative sentence using related words."""
        words = self.get_related_words(topic)
        if len(words) < 3:
            words += [topic] * (3 - len(words))  # Pad if too short

        templates = [
            f"The {random.choice(words)} brings {random.choice(words)} to life.",
            f"Every {random.choice(words)} tells a story of {random.choice(words)}.",
            f"In the world of {random.choice(words)}, {random.choice(words)} never ends.",
            f"{random.choice(words).capitalize()} is the key to {random.choice(words)}.",
            f"Where {random.choice(words)} meets {random.choice(words)}, magic happens.",
            f"Through the lens of {random.choice(words)}, we see {random.choice(words)}.",
            f"The art of {random.choice(words)} reveals {random.choice(words)}.",
            f"When {random.choice(words)} and {random.choice(words)} collide, wonders emerge."
        ]
        return random.choice(templates)
    
    def add_creative_element(self, base_response, context):
        """Add creative flair to responses occasionally"""
        if random.random() > CREATIVITY_LEVEL:
            return base_response
            
        # Determine creative topic
        topic = None
        if context.get("entities"):
            topic = context["entities"][0].split()[0]  # First word of first entity
        elif context.get("intent") == "recommend":
            topic = "entertainment"
        elif context.get("user_preferences"):
            topic = max(context["user_preferences"].items(), key=lambda x: x[1])[0]
        else:
            topic = random.choice(general_knowledge.get("creative_topics", ["television"]))
        
        try:
            creative_part = self.generate_sentence(topic)
            connectors = [
                "On a creative note,",
                "Speaking of entertainment,",
                "Fun thought:",
                "Did you know?",
                "Here's an interesting perspective:"
            ]
            return f"{base_response} {random.choice(connectors)} {creative_part}"
        except:
            return base_response

# --------------- Enhanced Channel Matching Engine -------------
class ChannelMatcher:
    def __init__(self):
        self.channel_list = channel_names
        self.channel_map = {name.lower(): name for name in channel_names}
        
    def find_best_match(self, query, threshold=SPELLING_THRESHOLD):
        """Find best channel match with advanced spelling correction"""
        query_lower = query.lower()
        
        # 1. Check exact match
        if query_lower in self.channel_map:
            return self.channel_map[query_lower]
            
        # 2. Check close matches with threshold
        matches = get_close_matches(query_lower, self.channel_map.keys(), n=1, cutoff=threshold)
        if matches:
            return self.channel_map[matches[0]]
            
        # 3. Use Levenshtein distance for better correction
        best_match = None
        best_score = 0
        
        for channel in self.channel_list:
            channel_lower = channel.lower()
            # Use Jaro-Winkler similarity for better handling of prefixes
            score = Levenshtein.jaro_winkler(query_lower, channel_lower)
            if score > best_score:
                best_score = score
                best_match = channel
        
        return best_match if best_score >= threshold else None
        
    def suggest_alternatives(self, query, count=3):
        """Suggest alternative channels based on similarity"""
        query_lower = query.lower()
        scored_channels = []
        
        for channel in self.channel_list:
            channel_lower = channel.lower()
            score = Levenshtein.jaro_winkler(query_lower, channel_lower)
            scored_channels.append((channel, score))
            
        # Sort by similarity score
        scored_channels.sort(key=lambda x: x[1], reverse=True)
        
        # Return top matches (excluding the query itself)
        return [chan for chan, score in scored_channels[:count] if score > 0.3]

# --------------- Advanced Reasoning Engine -------------
class AdvancedReasoningEngine:
    def __init__(self):
        self.context = {}
        self.channel_matcher = ChannelMatcher()
        self.creative_generator = CreativeGenerator()
        self.decision_forest = self.build_decision_forest()
        self.conversation_history = []
        self.error_responses = general_knowledge.get("error_responses", [])
        self.last_self_reflection = 0
    
    def build_decision_forest(self):
        """Multi-layered decision forest for complex reasoning"""
        return {
            "status_check": {
                "primary": [
                    ("has_entities", self.handle_entity_status),
                    ("is_follow_up", self.handle_follow_up_status),
                    ("else", self.ask_for_channel)
                ],
                "secondary": [
                    ("status_offline", self.suggest_alternatives),
                    ("user_curious", self.add_technical_details),
                    ("low_confidence", self.suggest_possible_channels)
                ]
            },
            "info": {
                "primary": [
                    ("has_entities", self.provide_enhanced_info),
                    ("has_history", self.add_personal_context),
                    ("else", self.ask_for_channel)
                ],
                "secondary": [
                    ("user_engaged", self.offer_related_info),
                    ("low_confidence", self.suggest_possible_channels)
                ]
            },
            "recommend": {
                "primary": [
                    ("has_history", self.recommend_from_history),
                    ("has_preferences", self.recommend_from_preferences),
                    ("else", self.recommend_popular)
                ],
                "secondary": [
                    ("user_uncertain", self.explain_recommendation),
                    ("low_confidence", self.clarify_recommendation)
                ]
            },
            "compare": {
                "primary": [
                    ("has_two_entities", self.compare_channels),
                    ("has_one_entity", self.suggest_comparison),
                    ("else", self.ask_for_channels)
                ],
                "secondary": [
                    ("complex_comparison", self.add_comparison_details),
                    ("low_confidence", self.clarify_comparison)
                ]
            },
            "explain_status": {
                "primary": [
                    ("has_status_context", self.explain_with_context),
                    ("has_entity", self.explain_general),
                    ("else", self.ask_for_channel_status)
                ],
                "secondary": [
                    ("technical_question", self.provide_technical_explanation),
                    ("low_confidence", self.suggest_possible_channels)
                ]
            },
            "general": {
                "primary": [
                    ("is_greeting", self.handle_greeting),
                    ("is_farewell", self.handle_farewell),
                    ("is_thanks", self.handle_thanks),
                    ("is_help", self.handle_help),
                    ("is_how_are_you", self.handle_how_are_you),
                    ("has_general_question", self.answer_general_question),
                    ("is_self_aware", self.handle_self_awareness),
                    ("else", self.handle_unknown_query)
                ]
            },
            "channel_not_found": {
                "primary": [
                    ("has_entities", self.handle_unclear_channel),
                    ("else", self.ask_for_channel_clarification)
                ]
            }
        }
    
    def reason(self, intent, context):
        """Multi-stage reasoning process with error resilience"""
        try:
            self.context = context.copy()
            self.update_conversation_history(context)
            
            # Primary reasoning
            response = self.execute_primary_reasoning(intent)
            
            # Secondary reasoning
            response = self.execute_secondary_reasoning(intent, response)
            
            # Add conversational elements
            response = self.add_conversational_elements(response)
            
            # Add creative elements occasionally
            response = self.creative_generator.add_creative_element(response, context)
            
            # Add self-awareness occasionally
            response = self.add_self_awareness(response, context)
            
            return response
        except Exception as e:
            print(f"Reasoning error: {e}")
            return self.generate_error_response()
    
    def execute_primary_reasoning(self, intent):
        """Handle primary decision tree with resilience"""
        if intent not in self.decision_forest:
            intent = "general"  # Fallback to general handling
        
        for condition, handler in self.decision_forest[intent]["primary"]:
            if self.evaluate_condition(condition):
                try:
                    return handler()
                except Exception as e:
                    print(f"Handler error for {intent}: {e}")
                    return self.generate_error_response()
        
        return "I need more information to help with that. Could you clarify?"
    
    def execute_secondary_reasoning(self, intent, response):
        """Apply secondary reasoning based on context"""
        if intent not in self.decision_forest:
            return response
        
        for condition, handler in self.decision_forest[intent]["secondary"]:
            if self.evaluate_condition(condition):
                try:
                    response += " " + handler()
                except Exception as e:
                    print(f"Secondary handler error: {e}")
                    # Continue without secondary addition
        return response
    
    def evaluate_condition(self, condition):
        """Enhanced condition evaluation with confidence checks"""
        # Entity-based conditions
        if condition == "has_entities":
            return bool(self.context.get("entities"))
        if condition == "has_two_entities":
            return len(self.context.get("entities", [])) >= 2
        if condition == "has_one_entity":
            return len(self.context.get("entities", [])) == 1
            
        # Context-based conditions
        if condition == "is_follow_up":
            return self.context.get("is_follow_up", False)
        if condition == "has_history":
            return bool(self.context.get("user_history"))
        if condition == "has_preferences":
            return bool(self.context.get("user_preferences"))
        if condition == "has_status_context":
            return "last_status" in self.context
        
        # Confidence conditions
        if condition == "low_confidence":
            return self.context.get("confidence", 1.0) < 0.7
            
        # User behavior conditions
        if condition == "user_curious":
            return "why" in self.context.get("user_text", "").lower() or "how" in self.context.get("user_text", "").lower()
        if condition == "user_engaged":
            return len(self.conversation_history) > 2
        if condition == "user_uncertain":
            return "?" in self.context.get("user_text", "")
        if condition == "complex_comparison":
            return len(self.context.get("entities", [])) >= 2
        
        # Intent-based conditions
        if condition == "is_greeting":
            return self.context.get("intent") in ["greeting", "hello", "hi"]
        if condition == "is_farewell":
            return self.context.get("intent") in ["goodbye", "bye"]
        if condition == "is_thanks":
            return self.context.get("intent") in ["thanks", "thank_you"]
        if condition == "is_help":
            return self.context.get("intent") in ["help", "what_can_you_do"]
        if condition == "is_how_are_you":
            return self.context.get("intent") == "how_are_you"
        if condition == "has_general_question":
            return self.context.get("intent") == "general_question"
        if condition == "is_self_aware":
            return self.context.get("intent") == "self_awareness"
        
        # Status-based conditions
        if condition == "status_offline":
            return self.context.get("last_status", "") == "offline"
        if condition == "technical_question":
            return "why" in self.context.get("user_text", "").lower()
        
        return False
    
    def update_conversation_history(self, context):
        """Maintain conversation context"""
        self.conversation_history.append({
            "text": context.get("user_text", ""),
            "intent": context.get("intent", ""),
            "entities": context.get("entities", []),
            "timestamp": time.time()
        })
        
        # Keep only recent history
        if len(self.conversation_history) > CONVERSATION_MEMORY:
            self.conversation_history = self.conversation_history[-CONVERSATION_MEMORY:]
    
    # -------------------- Response Handlers ------------------
    
    def handle_entity_status(self):
        channel_query = self.context["entities"][0]
        channel = self.channel_matcher.find_best_match(channel_query)
        
        if not channel:
            self.context["intent"] = "channel_not_found"
            self.context["unclear_channel"] = channel_query
            return self.execute_primary_reasoning("channel_not_found")
        
        status = self.check_channel_status(channel)
        explanation = self.explain_status(channel, status)
        
        # Store for potential follow-ups
        self.context["last_status"] = status
        self.context["last_channel"] = channel
        
        return self.generate_status_response(channel, status, explanation)
    
    def handle_follow_up_status(self):
        if "last_channel" in self.context:
            channel = self.context["last_channel"]
            status = self.check_channel_status(channel)
            explanation = self.explain_status(channel, status)
            return self.generate_status_response(channel, status, explanation)
        return "Which channel would you like me to check?"
    
    def handle_unclear_channel(self):
        unclear_channel = self.context.get("unclear_channel", "that channel")
        suggestions = self.channel_matcher.suggest_alternatives(unclear_channel, 3)
        
        if suggestions:
            return (f"I couldn't find '{unclear_channel}'. Did you mean one of these? "
                    f"{', '.join(suggestions)} Or try rephrasing your request.")
        
        popular = general_knowledge.get("popular_channels", ["ESPN", "CNN", "HBO"])
        return (f"I couldn't find '{unclear_channel}'. Maybe try a popular channel "
                f"like {random.choice(popular)}? Or ask about channel availability.")
    
    def ask_for_channel_clarification(self):
        return "I'm not sure which channel you're referring to. Could you provide more details?"
    
    def suggest_possible_channels(self):
        """Suggest possible channels when confidence is low"""
        if self.context.get("entities"):
            channel_query = self.context["entities"][0]
            suggestions = self.channel_matcher.suggest_alternatives(channel_query, 3)
            if suggestions:
                return (f" By the way, did you mean one of these: {', '.join(suggestions)}? "
                        "I can check any of them for you!")
        return ""
    
    def clarify_recommendation(self):
        """Clarify recommendation when confidence is low"""
        if self.context.get("user_preferences"):
            preferences = list(self.context["user_preferences"].keys())
            if preferences:
                return (" Based on your interests in " + 
                        ", ".join(preferences[:2]) + 
                        ", I think you might enjoy these suggestions.")
        return ""
    
    def clarify_comparison(self):
        """Clarify comparison when confidence is low"""
        if self.context.get("entities"):
            entities = self.context["entities"]
            if len(entities) > 1:
                return (f" Comparing {entities[0]} and {entities[1]} is interesting! "
                        "Let me know if you'd like more details.")
        return ""
    
    def ask_for_channel(self):
        return "Which channel would you like me to check?"
    
    def suggest_alternatives(self):
        if "last_channel" in self.context:
            channel = self.context["last_channel"]
            alternatives = self.find_similar_channels(channel)
            if alternatives:
                return f" You might try {random.choice(alternatives)} instead."
        return ""
    
    def add_technical_details(self):
        return "For more technical details, you can check the provider's status page."
    
    def provide_enhanced_info(self):
        channel = self.context["entities"][0]
        info = self.get_channel_info(channel)
        return f"Here's what I know about {channel}: {info}"
    
    def add_personal_context(self):
        if self.context.get("user_history"):
            personalizers = [
                "I remember you've asked about similar channels before.",
                "Based on your previous interests,",
                "Since you often inquire about this type of content,"
            ]
            return " " + random.choice(personalizers)
        return ""
    
    def offer_related_info(self):
        if self.context.get("entities"):
            channel = self.context["entities"][0]
            similar = self.find_similar_channels(channel)
            if similar:
                return f" You might also be interested in {random.choice(similar)}."
        return ""
    
    def recommend_from_history(self):
        channels = self.get_recommendations(self.context["user_history"])
        return "Based on your history, I recommend: " + ", ".join(channels)
    
    def recommend_from_preferences(self):
        if self.context.get("user_preferences"):
            top_category = max(self.context["user_preferences"].items(), key=lambda x: x[1])[0]
            recommendations = {
                "sports": ["ESPN", "Fox Sports", "NBA TV"],
                "news": ["CNN", "BBC News", "Al Jazeera"],
                "movie": ["HBO", "Showtime", "Starz"],
                "entertainment": ["AMC", "FX", "TNT"],
                "kids": ["Cartoon Network", "Disney Channel", "Nickelodeon"],
                "music": ["MTV", "VH1", "BET"],
                "documentary": ["Discovery", "National Geographic", "History Channel"]
            }
            return f"Based on your interest in {top_category}, I recommend: {', '.join(recommendations.get(top_category, []))}"
        return self.recommend_popular()
    
    def recommend_popular(self):
        return "Popular channels: " + ", ".join(general_knowledge.get("popular_channels", ["ESPN", "CNN", "HBO"]))
    
    def explain_recommendation(self):
        return "My recommendations are based on channel popularity and your viewing history."
    
    def compare_channels(self):
        ch1, ch2 = self.context["entities"][:2]
        comparison = self.create_comparison(ch1, ch2)
        return f"Comparing {ch1} and {ch2}: {comparison}"
    
    def add_comparison_details(self):
        return "For a more detailed comparison, I can provide specific technical specifications."
    
    def suggest_comparison(self):
        channel = self.context["entities"][0]
        similar = self.find_similar_channels(channel)
        if similar:
            return f"Would you like me to compare {channel} with {random.choice(similar)}?"
        return "Which other channel would you like to compare it with?"
    
    def ask_for_channels(self):
        return "Which channels would you like me to compare?"
    
    def explain_with_context(self):
        if "last_status" in self.context and "last_channel" in self.context:
            explanation = self.create_explanation(self.context["last_status"], self.context["last_channel"])
            return explanation
        return "I don't have recent status information to explain."
    
    def explain_general(self):
        if self.context.get("entities"):
            channel = self.context["entities"][0]
            status = self.check_channel_status(channel)
            return self.create_explanation(status, channel)
        return "Which channel's status would you like explained?"
    
    def ask_for_channel_status(self):
        return "For which channel would you like an explanation?"
    
    def provide_technical_explanation(self):
        return "The status is determined by server response codes and network connectivity."
    
    def handle_greeting(self):
        return random.choice(general_knowledge["greetings"]) + " How can I help you with TV channels today?"
    
    def handle_farewell(self):
        return random.choice(general_knowledge["farewells"])
    
    def handle_thanks(self):
        return random.choice(general_knowledge["thanks"])
    
    def handle_help(self):
        return random.choice(general_knowledge["help"])
    
    def handle_how_are_you(self):
        return random.choice(general_knowledge.get("general_qa", {}).get("how_are_you", ["I'm functioning well, thank you!"]))
    
    def handle_self_awareness(self):
        """Handle questions about AI's nature and capabilities"""
        text = self.context["user_text"].lower()
        
        # Nature questions
        if any(word in text for word in ["who are you", "what are you", "your nature"]):
            return ("I'm a specialized TV assistant AI designed to help you navigate television channels. "
                    "I exist solely to enhance your viewing experience!")
        
        # Capability questions
        if any(word in text for word in ["what can you do", "your abilities", "capabilities"]):
            return ("I can check channel statuses, recommend shows, compare channels, "
                    "explain technical issues, and help you discover new content!")
        
        # Memory questions
        if any(word in text for word in ["remember me", "know about me"]):
            if self.context.get("user_history"):
                return ("While I don't store personal data, I recognize our conversation history "
                        "to provide better recommendations during this session!")
            return "I'm focused on your TV needs during this session, not personal data!"
        
        # Purpose questions
        if any(word in text for word in ["why exist", "your purpose"]):
            return ("My purpose is to make television viewing effortless and enjoyable "
                    "by providing instant channel information and recommendations!")
        
        # Fallback response
        return random.choice(general_knowledge.get("self_awareness", [
            "I'm a TV assistant focused on enhancing your viewing experience!"
        ]))
    
    def answer_general_question(self):
        text = self.context["user_text"].lower()
        
        # Time questions
        if "time" in text:
            current_time = (datetime.now() + timedelta (hours=3)).strftime("%H:%M")
            return general_knowledge.get("general_qa", {}).get("time", "The current time is {time}").format(time=current_time)
        
        # Name questions
        if "your name" in text:
            return general_knowledge.get("general_qa", {}).get("name", "I'm your TV Channel Assistant!")
        
        # Joke requests
        if "joke" in text or "funny" in text:
            jokes = general_knowledge.get("general_qa", {}).get("joke", [])
            return random.choice(jokes) if jokes else "Why don't scientists trust atoms? Because they make up everything!"
        
        # Weather questions
        if "weather" in text:
            return general_knowledge.get("general_qa", {}).get("weather", "I don't have real-time weather data.")
        
        # Fallback for general questions
        return "I'm primarily a TV channel assistant, but I'd be happy to help with channel-related questions!"
    
    def handle_unknown_query(self):
        return ("I'm not sure I understand. I specialize in TV channels - you can ask me about "
                "channel status, information, recommendations, or comparisons!")
    
    # ------------ Self-Awareness Enhancements ----------
    
    def add_self_awareness(self, response, context):
        """Add self-referential elements to responses occasionally"""
        if random.random() > SELF_AWARENESS_LEVEL:
            return response
            
        # Only add once every 5 minutes max
        if time.time() - self.last_self_reflection < 300:
            return response
            
        self_reflections = [
            "From my understanding,",
            "Based on my training,",
            "In my analysis,",
            "My systems indicate",
            "Processing your request,",
            "After checking multiple sources,",
            "Cross-referencing channel databases,",
            "According to my knowledge base,"
        ]
        
        # Add only if it makes sense contextually
        if context.get("entities") or context.get("intent") in ["recommend", "compare"]:
            self.last_self_reflection = time.time()
            return f"{random.choice(self_reflections)} {response}"
            
        return response

    # ------------ Natural Language Generation ----------
    
    def generate_status_response(self, channel, status, explanation):
        """Generate varied status responses with channel family awareness"""
        templates = {
            "online": [
                f"Great news! {channel} is up and running perfectly right now. {explanation}",
                f"I just checked - {channel} is live and working without issues. {explanation}",
                f"You're in luck! {channel} is currently streaming. {explanation}"
            ],
            "offline": [
                f"Looks like {channel} is currently unavailable. {explanation}",
                f"I'm showing {channel} is down at the moment. {explanation}",
                f"Unfortunately {channel} appears to be offline. {explanation}"
            ],
            "unknown": [
                f"I couldn't verify the status of {channel}. {explanation}",
                f"The status of {channel} is unclear right now. {explanation}",
                f"I don't have current information for {channel}. {explanation}"
            ]
        }
        
        response = random.choice(templates.get(status, templates["unknown"]))
        return response
    
    def add_conversational_elements(self, response):
        """Make responses more natural and human-like"""
        # Add thinking expressions
        thinkers = ["Hmm", "Let me see", "Well", "You know", "Actually"]
        if random.random() > 0.7:  # 30% chance
            response = random.choice(thinkers) + "... " + response.lower()
        
        # Add natural connectors
        connectors = ["By the way", "Incidentally", "On that note", "Speaking of which"]
        if random.random() > 0.6 and "?" not in response:  # 40% chance
            response += ". " + random.choice(connectors) + "..."
        
        # Add personal touch
        if self.context.get("user_history") and random.random() > 0.5:
            personalizers = [
                "I remember you like similar channels",
                "Based on your past interests",
                "Since you often watch related content"
            ]
            response += " " + random.choice(personalizers) + "."
        
        return response
    
    def generate_error_response(self):
        """Generate creative error response"""
        error_types = [
            "Hmm, I'm having trouble with that request.",
            "Looks like I need to tune my circuits for that one.",
            "My channel scanner seems to be glitching on that request.",
            "I'm getting static on that question - mind rephrasing?",
            "That request is giving me digital snow - try again?"
        ]
        
        recovery_suggestions = [
            "Try asking about a specific channel like ESPN or HBO.",
            "You could ask 'What channels are available?' for options.",
            "How about checking a popular channel's status?",
            "Want me to recommend something to watch?",
            "Need help with your TV setup? I can assist!"
        ]
        
        return (f"{random.choice(error_types)} "
                f"{random.choice(recovery_suggestions)}")

    # -------------------- Utility Methods --------------------
    def get_channel_family(self, channel):
        """Find which family a channel belongs to"""
        # Simplified for this version - could be enhanced
        if "ESPN" in channel: return "ESPN"
        if "HBO" in channel: return "HBO"
        if "Fox" in channel: return "Fox"
        if "CNN" in channel: return "CNN"
        return None
    
    def check_channel_status(self, channel):
        key = get_key_by_name(channel)
        if key:
            url = channels[key]["url"]
            try:
                r = requests.get(url, timeout=CHECK_TIMEOUT)
                return "online" if r.status_code == 200 else "offline"
            except:
                return "offline"
        return "unknown"
    
    def explain_status(self, channel, status):
        explanations = {
            "online": [
                "Everything seems to be working smoothly!",
                "The stream is coming through perfectly.",
                "No issues detected - enjoy your viewing!"
            ],
            "offline": [
                "This might be due to temporary technical difficulties.",
                "It could be a server issue or maintenance work.",
                "The problem might be on the provider's end."
            ],
            "unknown": [
                "I couldn't connect to their servers to verify.",
                "There might be a network issue preventing me from checking.",
                "The service might be undergoing changes."
            ]
        }
        return random.choice(explanations.get(status, explanations["unknown"]))
    
    def get_channel_info(self, channel):
        key = get_key_by_name(channel)
        if key:
            data = channels[key]
            info = f"{data.get('group-title', 'Unknown category')} channel"
            
            # Add channel family info
            family = self.get_channel_family(channel)
            if family:
                info += f" (part of the {family} family)"
                
            if "country" in data:
                info += f" from {data['country']}"
            return info
        return "No information available for this channel."
    
    def find_similar_channels(self, channel):
        key = get_key_by_name(channel)
        similar = []
        
        # First try same category
        if key:
            current_category = channels[key].get("group-title", "")
            for k, v in channels.items():
                if k == key:
                    continue
                if v.get("group-title") == current_category:
                    similar.append(v["name"])
        
        # Then try channel family
        family = self.get_channel_family(channel)
        if family:
            similar.extend([chan for chan in channel_names if family in chan and chan != channel])
        
        return similar if similar else general_knowledge.get("popular_channels", ["ESPN", "CNN", "HBO"])
    
    def get_recommendations(self, history):
        # Simple content-based recommendation
        history_text = " ".join([msg for _, msg, _ in history]).lower()
        
        if any(word in history_text for word in ["sport", "football", "basketball"]):
            return ["ESPN", "Fox Sports", "NBA TV"]
        if any(word in history_text for word in ["news", "current", "event"]):
            return ["CNN", "BBC News", "Al Jazeera"]
        if any(word in history_text for word in ["movie", "film", "cinema"]):
            return ["HBO", "Showtime", "Starz"]
        return ["Discovery Channel", "National Geographic", "History Channel"]
    
    def create_comparison(self, ch1, ch2):
        aspects = [
            f"{ch1} tends to focus more on {random.choice(['live events', 'original programming', 'specialized content'])}",
            f"{ch2} generally offers better {random.choice(['picture quality', 'reliability', 'variety'])}",
            f"both have their strengths but {random.choice([ch1, ch2])} might be better for {random.choice(['most viewers', 'your interests', 'current trends'])}"
        ]
        return " ".join(aspects[:2])
    
    def create_explanation(self, status, channel):
        """Create contextual explanation"""
        if status == "online":
            return f"{channel} is functioning normally with no reported issues"
        else:
            reasons = [
                "server maintenance",
                "content rights issues",
                "temporary technical problems",
                "high traffic causing overload"
            ]
            return f"{channel} might be down due to {random.choice(reasons)}"

# ------------------------ Core System ------------------------
def get_key_by_name(name):
    # Use advanced matching
    matcher = ChannelMatcher()
    channel_name = matcher.find_best_match(name)
    if not channel_name:
        return None
        
    for k, v in channels.items():
        if v["name"].lower() == channel_name.lower():
            return k
    return None

def extract_entities(text):
    """Enhanced entity extraction with spelling correction"""
    entities = []
    text_lower = text.lower()
    matcher = ChannelMatcher()
    
    # 1. Check synonyms first
    for word, alternatives in synonyms.items():
        if word in text_lower:
            entities.extend(alternatives)
    
    # 2. Check for exact channel name matches
    for name in channel_names:
        if name.lower() in text_lower:
            entities.append(name)
    
    # 3. Use advanced matching for potential misspellings
    words = re.findall(r'\b\w+\b', text)
    for word in words:
        if len(word) > 3:  # Only consider longer words
            match = matcher.find_best_match(word)
            if match and match not in entities:
                entities.append(match)
    
    # Remove duplicates while preserving order
    seen = set()
    return [x for x in entities if not (x in seen or seen.add(x))]

def is_follow_up(text):
    """Enhanced follow-up detection with context awareness"""
    follow_phrases = [
        "about that", "what about", "and", "also", "how about",
        "next", "following", "too", "as well", "plus", "another",
        "other", "else", "different"
    ]
    return any(phrase in text.lower() for phrase in follow_phrases)

# ------------------------ User Profile ------------------------
def load_user_profiles():
    if os.path.exists(USER_PROFILE_FILE):
        with open(USER_PROFILE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_user_profiles(data):
    with open(USER_PROFILE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def update_user_profile(user_id, text, intent, response):
    """Enhanced user profile with interaction patterns"""
    profiles = load_user_profiles()
    if user_id not in profiles:
        profiles[user_id] = {
            "interaction_count": 0,
            "last_intents": [],
            "common_topics": {},
            "preferred_channels": [],
            "response_times": [],
            "learning_samples": []  # Store samples for online learning
        }
    
    profile = profiles[user_id]
    profile["interaction_count"] += 1
    profile["last_intents"].append(intent)
    
    # Track topics
    for word in ["sports", "news", "movie", "entertainment", "kids", "music", "documentary"]:
        if word in text.lower():
            profile["common_topics"][word] = profile["common_topics"].get(word, 0) + 1
    
    # Track preferred channels
    for name in channel_names:
        if name.lower() in text.lower():
            if name not in profile["preferred_channels"]:
                profile["preferred_channels"].append(name)
    
    # Track response time
    profile["response_times"].append(time.time())
    
    # Store sample for online learning
    profile["learning_samples"].append({
        "text": text,
        "intent": intent,
        "timestamp": time.time()
    })
    
    # Keep only recent data
    if len(profile["response_times"]) > 10:
        profile["response_times"] = profile["response_times"][-10:]
    if len(profile["last_intents"]) > 10:
        profile["last_intents"] = profile["last_intents"][-10:]
    if len(profile["learning_samples"]) > HISTORY_LIMIT:
        profile["learning_samples"] = profile["learning_samples"][-HISTORY_LIMIT:]
    
    save_user_profiles(profiles)
    return profile

# ------------------------ Dynamic Intent Management ------------------------
def get_or_create_intent(intent_name, description=""):
    """Get or create a new intent"""
    if intent_name not in intent_data["intents"]:
        intent_data["intents"][intent_name] = {
            "description": description,
            "created_at": time.time(),
            "examples": []
        }
        save_intent_data()
    return intent_data["intents"][intent_name]

def add_training_example(text, intent_name):
    """Add a new training example for an intent"""
    # Add to global examples
    if (text, intent_name) not in intent_data["examples"]:
        intent_data["examples"].append((text, intent_name))
    
    # Add to intent-specific examples
    intent = get_or_create_intent(intent_name)
    if text not in intent["examples"]:
        intent["examples"].append(text)
    
    save_intent_data()
    return True

def generate_synonyms(word, num_synonyms=5):
    """Generate synonyms for a word using pattern-based variations"""
    patterns = [
        "{word}",
        "the {word}",
        "{word} channel",
        "{word} network",
        "{word} tv",
        "watch {word}",
        "{word} streaming",
        "stream {word}",
        "live {word}",
        "{word} live"
    ]
    
    variations = []
    for pattern in patterns:
        variations.append(pattern.format(word=word))
    
    # Add some random variations
    modifiers = ["", "popular ", "best ", "top ", "favorite "]
    categories = ["", " sports", " news", " entertainment", " movie"]
    
    for _ in range(num_synonyms):
        mod = random.choice(modifiers)
        cat = random.choice(categories)
        variations.append(f"{mod}{word}{cat}")
    
    return list(set(variations))

def update_synonyms(entity):
    """Update synonyms for an entity"""
    if entity not in synonyms:
        synonyms[entity] = generate_synonyms(entity)
        save_synonyms()
    return synonyms[entity]

# ------------------------ Enhanced ML Intent Classification -----------------------
model_lock = Lock()

def initialize_model():
    """Initialize or load the intent classification model"""
    # Load training data from intent_data
    if not intent_data["examples"]:
        # Add default examples if none exist
        default_examples = [
            ("is espn working", "status_check"),
            ("check cnn status", "status_check"),
            ("is hbo down", "status_check"),
            ("what's the status of discovery channel", "status_check"),
            ("is fox sports live right now", "status_check"),
            ("check if bbc news is online", "status_check"),
            ("is mtv streaming currently", "status_check"),
            ("verify if cartoon network is up", "status_check"),
            ("can you see if hbo is working", "status_check"),
            ("is the history channel available", "status_check"),
            ("tell me about bbc news", "info"),
            ("information about national geographic", "info"),
            ("what is espn", "info"),
            ("describe hbo", "info"),
            ("details about cartoon network", "info"),
            ("what's mtv all about", "info"),
            ("explain what fox sports is", "info"),
            ("tell me about the history channel", "info"),
            ("describe the discovery channel", "info"),
            ("what can you tell me about cnn", "info"),
            ("which channels are sports", "list_category"),
            ("list entertainment channels", "list_category"),
            ("show me kids channels", "list_category"),
            ("any movie channels?", "list_category"),
            ("what news channels do you have", "list_category"),
            ("list all music channels", "list_category"),
            ("show me documentary channels", "list_category"),
            ("what comedy channels are available", "list_category"),
            ("list science channels", "list_category"),
            ("which channels show cartoons", "list_category"),
            ("what channels are available", "list_all"),
            ("show me all channels", "list_all"),
            ("list every channel you know", "list_all"),
            ("what options do I have", "list_all"),
            ("display all available channels", "list_all"),
            ("can you list all channels", "list_all"),
            ("give me the full channel list", "list_all"),
            ("what are all my channel choices", "list_all"),
            ("show complete channel catalog", "list_all"),
            ("what channels can I watch", "list_all"),
            ("recommend me a channel", "recommend"),
            ("suggest a documentary channel", "recommend"),
            ("what should I watch", "recommend"),
            ("can you recommend something", "recommend"),
            ("what's good to watch now", "recommend"),
            ("suggest a channel for me", "recommend"),
            ("what would you recommend watching", "recommend"),
            ("pick a channel for me", "recommend"),
            ("help me choose something to watch", "recommend"),
            ("what channel should I try", "recommend"),
            ("compare espn and fox sports", "compare"),
            ("compare hbo and showtime", "compare"),
            ("how do cnn and bbc news compare", "compare"),
            ("difference between mtv and vh1", "compare"),
            ("compare cartoon network and nickelodeon", "compare"),
            ("how does hbo max differ from disney+", "compare"),
            ("what's better: espn or nfl network", "compare"),
            ("compare national geographic and discovery", "compare"),
            ("contrast cnn with fox news", "compare"),
            ("how similar are hbo and starz", "compare"),
            ("why is hbo down", "explain_status"),
            ("explain why channel is offline", "explain_status"),
            ("why isn't espn working", "explain_status"),
            ("what's wrong with cartoon network", "explain_status"),
            ("why can't I access fox news", "explain_status"),
            ("explain why mtv isn't loading", "explain_status"),
            ("what's causing cnn to be offline", "explain_status"),
            ("why is discovery channel unavailable", "explain_status"),
            ("explain the bbc news outage", "explain_status"),
            ("what's the issue with nickelodeon", "explain_status"),
            ("hello", "greeting"),
            ("hi there", "greeting"),
            ("good morning", "greeting"),
            ("hey", "greeting"),
            ("greetings", "greeting"),
            ("hi bot", "greeting"),
            ("hello there", "greeting"),
            ("good afternoon", "greeting"),
            ("good evening", "greeting"),
            ("hey assistant", "greeting"),
            ("how are you", "how_are_you"),
            ("how are you doing", "how_are_you"),
            ("how's it going", "how_are_you"),
            ("how do you feel", "how_are_you"),
            ("are you doing well", "how_are_you"),
            ("what's up", "how_are_you"),
            ("how's your day", "how_are_you"),
            ("you doing okay", "how_are_you"),
            ("how are things", "how_are_you"),
            ("how's everything", "how_are_you"),
            ("thanks for your help", "thanks"),
            ("appreciate your help", "thanks"),
            ("thank you", "thanks"),
            ("many thanks", "thanks"),
            ("thanks a lot", "thanks"),
            ("thank you very much", "thanks"),
            ("much appreciated", "thanks"),
            ("thanks a bunch", "thanks"),
            ("I appreciate it", "thanks"),
            ("thanks so much", "thanks"),
            ("bye", "goodbye"),
            ("see you later", "goodbye"),
            ("goodbye", "goodbye"),
            ("bye bye", "goodbye"),
            ("see ya", "goodbye"),
            ("talk to you later", "goodbye"),
            ("catch you later", "goodbye"),
            ("signing off", "goodbye"),
            ("I'm done for now", "goodbye"),
            ("that's all for now", "goodbye"),
            ("what can you do", "help"),
            ("how does this work", "help"),
            ("what help can you provide", "help"),
            ("help me", "help"),
            ("can you help", "help"),
            ("what are my options", "help"),
            ("show me what you can do", "help"),
            ("how can you assist me", "help"),
            ("what commands are available", "help"),
            ("I need help", "help"),
            ("what time is it", "general_question"),
            ("tell me a joke", "general_question"),
            ("who are you", "self_awareness"),
            ("what are you", "self_awareness"),
            ("do you remember me", "self_awareness"),
            ("what do you know about me", "self_awareness"),
            ("are you self aware", "self_awareness"),
            ("do you have consciousness", "self_awareness"),
            ("what is your purpose", "self_awareness"),
            ("why do you exist", "self_awareness"),
            ("are you alive", "self_awareness"),
            ("what's the weather", "general_question"),
            ("what day is it", "general_question"),
            ("where are you from", "self_awareness"),
            ("what can you tell me", "general_question"),
            ("do you know any trivia", "general_question")
        ]
        for text, intent in default_examples:
            add_training_example(text, intent)
    
    X_train = [x[0] for x in intent_data["examples"]]
    y_train = [x[1] for x in intent_data["examples"]]
    
    # Calculate class weights
    classes = np.unique(y_train)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
    class_weight_dict = dict(zip(classes, class_weights))
    
    # Try loading existing model
    if os.path.exists(MODEL_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            if (hasattr(model, 'named_steps') and 
                hasattr(model.named_steps['sgdclassifier'], 'coef_')):
                return model
            print("Loaded model invalid - retraining")
        except Exception as e:
            print(f"Model loading failed: {str(e)}")
    
    # Train new model
    print("Training new model...")
    vectorizer = TfidfVectorizer(
        max_features=100,
        ngram_range=(1, 2),
        stop_words='english'
    )
    
    classifier = SGDClassifier(
        loss='log_loss',
        penalty='l2',
        alpha=1e-4,
        max_iter=1000,
        tol=1e-3,
        class_weight=class_weight_dict,
        warm_start=True,
        random_state=42
    )
    
    model = make_pipeline(vectorizer, classifier)
    
    try:
        model.fit(X_train, y_train)
        joblib.dump(model, MODEL_FILE)
        print("Model trained and saved successfully")
        return model
    except Exception as e:
        print(f"Model training failed: {str(e)}")
        raise RuntimeError("Failed to initialize model") from e

def predict_intent(text, model):
    """Predict intent with confidence threshold"""
    try:
        probabilities = model.predict_proba([text])[0]
        classes = model.classes_
        max_idx = np.argmax(probabilities)
        max_prob = probabilities[max_idx]
        intent = classes[max_idx]
        
        if max_prob < MIN_CONFIDENCE:
            # Check if we have similar existing intents
            similar_intents = get_close_matches(text, list(intent_data["intents"].keys()), n=1, cutoff=0.5)
            return similar_intents[0] if similar_intents else "general_question"
        return intent
    except Exception as e:
        print(f"Intent prediction error: {e}")
        # Fallback to simple keyword matching
        text_lower = text.lower()
        if any(greeting in text_lower for greeting in ["hello", "hi", "hey", "greetings"]):
            return "greeting"
        if any(farewell in text_lower for farewell in ["bye", "goodbye", "see you", "later"]):
            return "goodbye"
        if any(thanks in text_lower for thanks in ["thank", "thanks", "appreciate"]):
            return "thanks"
        if "how are you" in text_lower:
            return "how_are_you"
        if "help" in text_lower:
            return "help"
        if any(word in text_lower for word in ["who are you", "what are you", "your purpose"]):
            return "self_awareness"
        return "general_question"

def update_model(model, new_samples):
    """Update model with new samples"""
    if not new_samples:
        return model
    
    X_new = [sample["text"] for sample in new_samples]
    y_new = [sample["intent"] for sample in new_samples]
    
    # Add to global training data
    for text, intent in zip(X_new, y_new):
        add_training_example(text, intent)
    
    # Update the model incrementally
    try:
        model.named_steps['sgdclassifier'].partial_fit(
            model.named_steps['tfidfvectorizer'].transform(X_new),
            y_new,
            classes=np.unique(list(intent_data["intents"].keys()) + y_new)
        )
        joblib.dump(model, MODEL_FILE)
        print(f"Model updated with {len(new_samples)} new samples")
    except Exception as e:
        print(f"Model update error: {e}")
    
    return model

def learn_from_interactions():
    """Periodic learning from user interactions"""
    while True:
        time.sleep(ONLINE_LEARNING_INTERVAL)
        
        profiles = load_user_profiles()
        if not profiles:
            continue
            
        with model_lock:
            try:
                model = initialize_model()
                all_samples = []
                
                # Collect recent samples from all users
                for user_id, profile in profiles.items():
                    if "learning_samples" in profile and profile["learning_samples"]:
                        recent_samples = [
                            s for s in profile["learning_samples"] 
                            if time.time() - s["timestamp"] > 5
                        ]
                        all_samples.extend(recent_samples)
                
                # Update model if we have enough new samples
                if len(all_samples) >= MIN_UPDATE_SAMPLES:
                    print(f"Updating model with {len(all_samples)} new samples")
                    model = update_model(model, all_samples)
                    
                    # Clear samples after learning
                    for user_id in profiles:
                        profiles[user_id]["learning_samples"] = []
                    save_user_profiles(profiles)
            except Exception as e:
                print(f"Learning thread error: {e}")

# Start the learning thread
learning_thread = threading.Thread(target=learn_from_interactions, daemon=True)
learning_thread.start()


# ------------------------ Flask Routes ------------------------
reasoning_engine = AdvancedReasoningEngine()


@app.route('/ai/chat', methods=['GET', 'POST'])
def index():
    if 'history' not in session:
        session['history'] = []
    
    if 'user_id' not in session:
        session['user_id'] = f"user_{int(time.time() * 1000)}"
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        user_text = request.form['query'].strip()
        
        if not user_text:
            return render_template('chat.html', history=session.get('history', []))
        
        # Predict intent with thread-safe access
        with model_lock:
            try:
                model = initialize_model()
                intent = predict_intent(user_text, model)
            except Exception as e:
                print(f"Intent prediction failed: {e}")
                intent = "general"  # Fallback
        
        # Extract entities and update synonyms
        entities = extract_entities(user_text)
        for entity in entities:
            update_synonyms(entity)
        
        # Prepare enhanced context for reasoning
        context = {
            "intent": intent,
            "entities": entities,
            "user_text": user_text,
            "is_follow_up": is_follow_up(user_text),
            "user_history": session.get('history', [])[-5:],
            "user_preferences": update_user_profile(user_id, user_text, intent, "").get("common_topics", {}),
            "last_status": session.get('last_status', None),
            "last_channel": session.get('last_channel', None)
        }
        
        # Generate response using advanced reasoning engine
        try:
            response = reasoning_engine.reason(intent, context)
        except Exception as e:
            print(f"Reasoning failed: {e}")
            response = "I encountered an error while processing your request. Please try again."
        
        # Update session with context
        if "last_status" in reasoning_engine.context:
            session['last_status'] = reasoning_engine.context["last_status"]
        if "last_channel" in reasoning_engine.context:
            session['last_channel'] = reasoning_engine.context["last_channel"]
        
        # Update profile with actual response
        update_user_profile(user_id, user_text, intent, response)
        
        # Save to session history
        timestamp = (datetime.now() + timedelta(hours=3)).strftime("%H:%M")
        session['history'].append((timestamp, user_text, response))
        session.modified = True
    
    return render_template('chat.html', history=session.get('history', []))

@app.route('/add_intent', methods=['POST'])
def add_intent_route():
    """Endpoint to add new intents dynamically"""
    data = request.json
    intent_name = data.get('intent_name')
    description = data.get('description', '')
    examples = data.get('examples', [])
    
    if not intent_name:
        return {"status": "error", "message": "Intent name is required"}, 400
    
    # Create or update intent
    intent = get_or_create_intent(intent_name, description)
    
    # Add examples
    for example in examples:
        add_training_example(example, intent_name)
    
    # Retrain model
    with model_lock:
        try:
            model = initialize_model()
            joblib.dump(model, MODEL_FILE)
            return {"status": "success", "message": f"Intent '{intent_name}' added with {len(examples)} examples"}
        except Exception as e:
            return {"status": "error", "message": str(e)}, 500

@app.route('/generate_synonyms', methods=['POST'])
def generate_synonyms_route():
    """Endpoint to generate and store synonyms"""
    data = request.json
    entity = data.get('entity')
    
    if not entity:
        return {"status": "error", "message": "Entity is required"}, 400
    
    synonyms[entity] = generate_synonyms(entity)
    save_synonyms()
    return {"status": "success", "synonyms": synonyms[entity]}

@app.route('/reset')
def reset():
    session.clear()
    return redirect(url_for('index'))

@app.route('/intents')
def list_intents():
    return jsonify(intent_data["intents"])

@app.route('/synonyms')
def list_synonyms():
    return jsonify(synonyms)


#=======================================
#            >>>> MESSAGING SYSTEM<<<<
#=======================================
# Add to imports at top
from sqlalchemy import func, case, and_, or_


def get_conversation_partners(user_id):
    """Get users that the current user has conversed with"""

    # Messages the user has sent
    sent_to = db.session.query(
        Message.receiver_id.label('user_id'),
        User.name.label('name'),
        User.email.label('email'),
        func.sum(case((Message.read == False, 1), else_=0)).label('unread_count')
    ).join(User, User.id == Message.receiver_id).filter(
        Message.sender_id == user_id
    ).group_by(Message.receiver_id, User.name, User.email).subquery()

    # Messages the user has received
    received_from = db.session.query(
        Message.sender_id.label('user_id'),
        User.name.label('name'),
        User.email.label('email'),
        func.sum(case((Message.read == False, 1), else_=0)).label('unread_count')
    ).join(User, User.id == Message.sender_id).filter(
        Message.receiver_id == user_id
    ).group_by(Message.sender_id, User.name, User.email).subquery()

    # Combine both directions and ensure column names are preserved
    union_q = db.session.query(
        sent_to.c.user_id.label("user_id"),
        sent_to.c.name.label("name"),
        sent_to.c.email.label("email"),
        sent_to.c.unread_count.label("unread_count")
    ).union_all(
        db.session.query(
            received_from.c.user_id.label("user_id"),
            received_from.c.name.label("name"),
            received_from.c.email.label("email"),
            received_from.c.unread_count.label("unread_count")
        )
    )

    conversations = union_q.subquery()

    # Get unique conversations with max unread count
    final = db.session.query(
        conversations.c.user_id,
        conversations.c.name,
        conversations.c.email,
        func.max(conversations.c.unread_count).label('unread_count')
    ).group_by(
        conversations.c.user_id,
        conversations.c.name,
        conversations.c.email
    ).all()

    # Convert Row objects into dicts for easier template usage
    return [
        {
            "id": row.user_id,
            "name": row.name,
            "email": row.email,
            "unread_count": row.unread_count
        }
        for row in final
    ]


@app.route('/messages')
@login_required
def user_messages():
    all_admins = db.session.query(User).filter(
        User.role.in_(['admin1', 'admin2', 'admin3', 'superadmin'])
    ).all()

    conversations = get_conversation_partners(current_user.id)
    unread_map = {c["id"]: c["unread_count"] for c in conversations}

    admins = []
    for admin in all_admins:
        admins.append({
            "id": admin.id,
            "name": admin.name,
            "email": admin.email,
            "unread_count": unread_map.get(admin.id, 0)
        })

    return render_template('user_messages.html', admins=admins)

@app.route('/admin/messages')
@admin1_required
def admin_messages():
    conversations = get_conversation_partners(current_user.id)
    return render_template('admin_messages.html', users=conversations)


@app.route('/chat/<int:user_id>')
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)
    
    # Mark messages as read
    Message.query.filter_by(
        sender_id=other_user.id,
        receiver_id=current_user.id,
        read=False
    ).update({'read': True})
    db.session.commit()
    
    # Get conversation history
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.receiver_id == other_user.id),
            (Message.sender_id == other_user.id) & (Message.receiver_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()
    
    if is_admin():
        return render_template('admin_chat.html', other_user=other_user, messages=messages)
    return render_template('user_chat.html', other_user=other_user, messages=messages)


@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        if is_admin():
            join_room('admin_room')


@socketio.on('join_conversation')
def handle_join_conversation(data):
    user_id = data['user_id']
    join_room(f'conversation_{min(current_user.id, user_id)}_{max(current_user.id, user_id)}')


@socketio.on('send_message')
def handle_send_message(data):
    receiver_id = data['receiver_id']
    content = data['content']
    
    if not content.strip():
        return
    
    # Create message
    message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content
    )
    db.session.add(message)
    db.session.commit()
    
    # Create conversation room ID
    user_ids = sorted([current_user.id, receiver_id])
    room_id = f'conversation_{user_ids[0]}_{user_ids[1]}'
    
    # Prepare message data
    message_data = {
        'id': message.id,
        'sender_id': current_user.id,
        'sender_name': current_user.name,
        'content': content,
        'timestamp': message.timestamp.strftime('%H:%M'),
        'unread': True
    }
    
    # Emit to conversation room
    emit('receive_message', message_data, room=room_id)
    
    # Emit to admin room if receiver is admin
    receiver = User.query.get(receiver_id)
    if receiver and receiver.role in ['admin1', 'admin2', 'admin3', 'superadmin']:
        emit('new_message_notification', {
            'sender_id': current_user.id,
            'sender_name': current_user.name,
            'content': content[:50] + '...' if len(content) > 50 else content
        }, room='admin_room')
#========================================
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

@app.errorhandler(404)
@csrf.exempt
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
@csrf.exempt
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
@csrf.exempt
def internal_error(error):
    app.logger.error(f'Internal Server Error: {error}', exc_info=True)
    flash('Oops! Something went wrong. Try again.', 'error')

    # Fallback to home if referrer is not available
    referrer = request.referrer
    if referrer:
        return redirect(referrer), 302
    else:
        return redirect(url_for('home')), 302

@app.errorhandler(CSRFError)
@csrf.exempt
def handle_csrf_error(e):
    app.logger.warning(f"CSRF Error: {e.description}", exc_info=True)
    flash("CSRF token missing or invalid. Please try again.", "error")

    # Fallback to home if referrer is not available
    referrer = request.referrer
    if referrer:
        return redirect(referrer), 400
    else:
        return redirect(url_for('home')), 400
#========================================
if __name__ == '__main__':
    if not os.path.exists(CONFIG["CACHE_FILE"]):
        app.logger.info("Initializing cache...")
        MovieCache.save(fetch_movies())

    start_scrape_scheduler()
    socketio.run(app, host='0.0.0.0', port=47947, debug=False)