#====================================
#                     >>>>MAIN APP <<<<
#====================================
# Standard Library Imports
import os
import base64
import json
import random
import re
import subprocess
from datetime import datetime, timedelta, time
from functools import wraps
from typing import Dict, List, Optional, Union
from urllib.parse import quote_plus

# Third-Party Imports
import requests
from dotenv import load_dotenv
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, Response, send_file, send_from_directory, session,
                   stream_with_context, url_for)
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                        login_user, logout_user)
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from requests.auth import HTTPBasicAuth
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

# ============================
# CONFIGURATION & INIT
# ============================

app = Flask(__name__)
load_dotenv()

#======================================
# choose db Helper
#======================================
import traceback

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

# App Configuration
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "12345QWER")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "4321REWQ")
app.config['SQLALCHEMY_DATABASE_URI'] = choose_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 15,          # Max connections (adjust for DB tier)
    'max_overflow': 5,        # Temporary extra connections if pool is full
    'pool_recycle': 300,      # Recycle connections after 5 mins (avoid timeouts)
    'pool_pre_ping': True     # Test connections before reuse
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

now_utc = datetime.utcnow()
# Nairobi is UTC+3
now_eat = now_utc + timedelta(hours=3)
# Calculate next midnight in EAT
next_midnight_eat = datetime.combine(now_eat.date() + timedelta(days=1), time.min)
# Get seconds until that midnight (back in UTC)
seconds_until_midnight = (next_midnight_eat - now_eat).total_seconds()
# Apply session expiration
app.permanent_session_lifetime = timedelta(seconds=seconds_until_midnight)

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
mail = Mail(app)
csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)
login_manager.login_view = "login"
CORS(app, resources={r"/*": {"origins": "https://viewtv-p2s3.onrender.com"}})

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
            and self.plus_expires_at > datetime.utcnow() + timedelta(hours=3)
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
with app.app_context():
    db.create_all()
#======================================
@app.route('/robots.txt')
def robots_txt():
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: https://viewtv-p2s3.onrender.com/sitemap.xml\n",
        200,
        {'Content-Type': 'text/plain'}
    )

@app.route('/sitemap.xml')
def sitemap():
    sitemap = '''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://viewtv-p2s3.onrender.com/</loc></url>
  <url><loc>https://viewtv-p2s3.onrender.com/about</loc></url>
  <url><loc>https://viewtv-p2s3.onrender.com/services</loc></url>
  <url><loc>https://viewtv-p2s3.onrender.com/developer</loc></url>
  <url><loc>https://viewtv-p2s3.onrender.com/terms</loc></url>
  <url><loc>https://viewtv-p2s3.onrender.com/privacy</loc></url>
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
    return session.get('role') == 'admin'
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
        "frame-ancestors https://viewtv-p2s3.onrender.com https://viewstream-1.onrender.com;"
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
def auto_logout_user():
    if current_user.is_authenticated:
        user = User.query.filter_by(id=current_user.id).first()
        if user and user.status != current_user.status:
            logout_user(user)
            flash("Status changed. Please log in again.", "error")
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

    msg = Message(
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

    msg = Message(
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
            return redirect(url_for("get_plus"))
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
        name = request.form["name"]
        email_addr = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        code_input = request.form.get('secret_code')

        if not name or not password or not confirm_password or not email_addr:
            flash('All fields are required', "error")
            return render_template("register.html")

        if not (email_addr.endswith('@gmail.com') or email_addr.endswith('@yahoo.com')):
            flash('Invalid email', "error")
            return render_template('register.html',
                                   name=name, email=email_addr,
                                   password=password, confirm_password=confirm_password)

        existing_email = User.query.filter_by(email=email_addr).first()
        if existing_email:
            flash('Email already exists', 'error')
            return render_template('register.html',
                                   email=email_addr, name=name,
                                   password=password, confirm_password=confirm_password)

        if password != confirm_password:
            flash("Passwords don't match", "error")
            return render_template('register.html',
                                   name=name, email=email_addr,
                                   password=password, confirm_password=confirm_password)

        # ✅ Hardcoded secret codes mapped to roles
        code_role_map = {
            "479superadmin479": "superadmin",
            "479admin1": "admin1",
            "479admin2": "admin2",
            "479admin3": "admin3",
        }

        # ✅ Assign role based on code input (or fallback to 'user')
        role = code_role_map.get(code_input, "user")

        status = 'active'
        hashed_password = generate_password_hash(password)

        new_user = User(
            name=name,
            email=email_addr,
            password=hashed_password,
            role=role,
            status=status,
            agreed=True,
            plus_expires_at=datetime.utcnow() - timedelta(seconds=1),
            plus_type=None,
            last_free_plus=None
        )

        db.session.add(new_user)
        db.session.commit()

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
# Exclusive sport Logic

import sports  # from sports.py file

# Keyword mappings for competitions
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

# List of sports dictionaries in your sports.py
SPORTS_GROUPS = [
    "DAZN", "BEIN", "FUTBOL", "SPORT", "ALL_SPORTS", "FOX_SPORTS", "EUROSPORT",
    "ACTION_SPORT", "ADVENTURE_SPORTS", "AFRICA_SPORT", "ANTENA_SPORT", "AUTO_SPORT_MOTOR",
    "CBS_SPORTS", "CNAR", "ELEVEN_SPORTS", "E_SPORT", "EXTREME_SPORTS", "FIFA", "FAST_SPORTS",
    "FL_SPORT", "FUBO_SPORTS", "KTV", "LAX", "M4", "MNB", "MORE_THAN_SPORTS", "NBA", "NBC",
    "NFL", "OMAN", "PLUTO", "PTV", "RAI", "RED_BULL", "SEO", "SMG", "SONY", "SPIEGEL",
    "T_SPORT", "PORT", "ATG", "TIGO", "TR", "TV_3", "TVR", "TVS", "UNBEATEN", "US_TODAY",
    "VIJU", "FREESPORTS", "X_SPORTS"
]

def match_competition(channel_name):
    name = channel_name.lower()
    for comp, keywords in competition_keywords.items():
        if any(k in name for k in keywords):
            return comp
    return "Other"

def get_grouped_channels():
    grouped = {}

    for group_name in SPORTS_GROUPS:
        group_dict = getattr(sports, group_name, None)
        if not isinstance(group_dict, dict):
            continue

        for ch in group_dict.values():
            name = ch.get("name", "").strip()
            url = ch.get("url", "").strip()
            logo = ch.get("tvg-logo", "").strip()
            country = ch.get("tvg-country", "").strip()

            if not name or not url:
                continue  # skip incomplete entries

            competition = match_competition(name)
            label = f"{group_name} ? {competition}"

            grouped.setdefault(label, []).append({
                "name": name,
                "url": url,
                "logo": logo,
                "country": country
            })

    return grouped
#----------------------------------------------------------------------
@app.route("/return-football")
@limiter.limit("30 per minute")
@login_required
@plus_required
def return_football():
    return render_template("return_football.html")

@app.route("/sports_playlist")
@limiter.limit("30 per minute")
@plus_required
@login_required
def sports_playlist():
    channels_by_group = get_grouped_channels()
    return render_template(
        "sports_playlist.html",
        channels_by_group=channels_by_group,
        current_year=datetime.now().year
    )
#----------------------------------------------------------------------
from flask import render_template_string

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
import json
import time
from collections import defaultdict

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
import logging
from datetime import datetime, timedelta
from threading import Timer
from concurrent.futures import ThreadPoolExecutor, as_completed

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
import json
import subprocess
from flask import jsonify               
from flask import Flask, request, Response, abort, render_template, send_from_directory, stream_with_context
import requests
import re
from urllib.parse import quote_plus
#=======================================
import time

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

    proxied_url = f"https://viewtv-p2s3.onrender.com/proxy?url={quote_plus(channel['url'])}"
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
FFMPEG_PROXY_URL = "https://viewtv-p2s3.onrender.com/hls"

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
import json
import random

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

from collections import defaultdict

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
@app.route("/plus-channel/<key>")
def plus_play(key):
    try:
        with open('channels.json') as f:
            channels = json.load(f)

        channel = channels.get(key)  # Use key exactly as received
        if not channel:
            return "Channel not found", 404
            
        if not channel.get('url'):
            return "No URL configured", 400
            
        # Validate URL format
        if not (channel['url'].startswith('http://') or channel['url'].startswith('https://')):
            return "Invalid URL format", 400
            
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
#------------------------------------------------------------------------
#extra player for external URL test and not updated routes-requests
from urllib.parse import quote

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
#=====================≠================

import secrets

# Configuration
BASIC_CHANNELS_FILE = 'raw_channels.json'
TOKENS_FILE = 'channel_tokens.json'
CHANNELS = {}
TOKEN_MAP = {}

def load_or_create_tokens():
    """Load tokens from file or generate new ones"""
    tokens = {}
    
    if os.path.exists(TOKENS_FILE):
        try:
            with open(TOKENS_FILE, 'r') as f:
                tokens = json.load(f)
        except:
            pass  # If file is corrupt, we'll regenerate tokens
            
    return tokens

def load_channels():
    """Load channels and attach persistent tokens"""
    if not os.path.exists(BASIC_CHANNELS_FILE):
        return {}
    
    with open(BASIC_CHANNELS_FILE, 'r') as f:
        channels = json.load(f)
    
    valid_channels = {}
    tokens = load_or_create_tokens()
    new_tokens = False
    
    for key, data in channels.items():
        if not all(field in data for field in ['name', 'url']):
            continue
            
        # Generate new token if none exists
        if key not in tokens:
            tokens[key] = secrets.token_urlsafe(16)
            new_tokens = True
            
        # Attach token to channel data
        data['token'] = tokens[key]
        valid_channels[key] = data
    
    # Save new tokens if generated
    if new_tokens:
        with open(TOKENS_FILE, 'w') as f:
            json.dump(tokens, f)
    
    return valid_channels

# Initialize channels and tokens
CHANNELS = load_channels()
TOKEN_MAP = {data['token']: key for key, data in CHANNELS.items()}

# Custom endpoint for channel URLs
@app.route("/madeup_url")
def madeup_url():
    base_url = "https://viewtv-p2s3.onrender.com"
    channel_urls = []
    
    for key, channel in CHANNELS.items():
        m3u8_url = f"{base_url}/channel/{channel['token']}/{key}.m3u8"
        channel_urls.append({
            "name": channel["name"],
            "url": m3u8_url,
            "token": channel['token']
        })
    
    return render_template('made_channels.html', 
                         channel_urls=channel_urls,
                         base_url=base_url)


@app.route("/channel/<token>/<key>.m3u8")
def channel_m3u8(token, key):
    if token not in TOKEN_MAP:
        return "Invalid token", 403
    
    if TOKEN_MAP[token] != key:
        return "Token-key mismatch", 403

    channel = CHANNELS.get(key)
    if not channel:
        return "Channel not found", 404

    # VLC-compatible HLS wrapper
    m3u8_content = f"""#EXTM3U
#EXT-X-VERSION:3
#EXT-X-INDEPENDENT-SEGMENTS
#EXT-X-STREAM-INF:BANDWIDTH=4000000,RESOLUTION=1280x720,CODECS="avc1.64001f,mp4a.40.2"
{channel['url']}
"""
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

@app.route('/payment')
def payment():
    return render_template('pay.html', user=current_user)

# ----------------------------------------------------------------------

@app.route('/api/pay', methods=['POST'])
def pay():
    data = request.json
    phone = data.get('phone')
    amount = int(data.get('amount'))

    if not phone or not amount:
        return jsonify({"success": False, "message": "Phone or amount missing"}), 400

    # Convert phone to Safaricom format: 2547XXXXXXX
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    elif phone.startswith("+"):
        phone = phone.replace("+", "")

    # Save pending payment
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
    business_short_code = "174379"  # Your actual shortcode
    callback_url = "https://viewtv.onrender.com/callback"

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
        "TransactionDesc": "VIP Subscription"
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
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": f"Push error: {str(e)}"}), 500

# ------------------------------------------------------------------------
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
import random

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
    return render_template("welcome.html")
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
@app.route('/home_admin')
@login_required 
@admin3_required
def home_admin():
    # Get statistics from database
    total_users = User.query.count()
    
    # Count users marked as 'active'
    active_today = User.query.filter_by(status='active').count()
    
    # Total channels
    total_channels = len(CUSTOM_CHANNELS)
    
    # Plus subscribers
    plus_users = User.query.filter(
        User.plus_type == "paid",
        User.plus_expires_at != None,
        User.plus_expires_at > datetime.utcnow()
    ).count()
    
    return render_template(
        'home_admin.html',
        user=current_user,
        stats={
            'total_users': total_users,
            'active_today': active_today,
            'total_channels': total_channels,
            'plus_users': plus_users
        }
    )
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
# user management

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
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError

@app.route("/admin/clone_data")
@login_required
@superadmin_required
def clone_data():
    db1_url = os.getenv("DATABASE_URL")
    db2_url = os.getenv("DATABASE_URL_2")

    if not db1_url or not db2_url:
        flash("Database URLs not set in environment file.", "error")
        return redirect(url_for("home_admin"))

    source_engine = create_engine(db1_url)
    dest_engine = create_engine(db2_url)

    SourceSession = sessionmaker(bind=source_engine)
    DestSession = sessionmaker(bind=dest_engine)
    source_session = SourceSession()
    dest_session = DestSession()

    try:
        # Drop all tables in destination DB
        db.metadata.drop_all(bind=dest_engine)

        # Recreate tables
        db.metadata.create_all(bind=dest_engine)

        # Now clone data
        for model in [User]:  # add your models here
            rows = source_session.query(model).all()
            for row in rows:
                clone = model(**{col.name: getattr(row, col.name) for col in model.__table__.columns})
                dest_session.add(clone)
        dest_session.commit()
        flash("Cloning completed successfully.", "success")

    except Exception as e:
        dest_session.rollback()
        flash(f"Cloning failed: {e}", "error")

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

    start_scrape_scheduler()  # ✅ Schedule the automatic scraping
    app.run(host='0.0.0.0', port=47947, debug=False)