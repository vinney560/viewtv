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
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

# ============================
# CONFIGURATION & INIT
# ============================

app = Flask(__name__)
load_dotenv()


def choose_db_uri():
    render_uri = os.getenv('DATABASE_URL_3')        # Render DB (primary)
    supabase_uri = os.getenv('DATABASE_URL')    # Supabase DB (secondary)

    if render_uri:
        try:
            engine = create_engine(render_uri)
            engine.connect().close()
            print("✅ Connected to Render DB (DATABASE_URL)")
            return render_uri
        except OperationalError:
            print("⚠️ Failed to connect to Render DB. Trying Supabase DB...")

    if supabase_uri:
        try:
            engine = create_engine(supabase_uri)
            engine.connect().close()
            print("✅ Connected to Supabase DB (DATABASE_URL_3)")
            return supabase_uri
        except OperationalError:
            print("⚠️ Failed to connect to Supabase DB.")

    print("❌ All remote DBs failed. Falling back to SQLite.")
    return "sqlite:///default.db"

# App Configuration
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "12345QWER")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "4321REWQ")
app.config['SQLALCHEMY_DATABASE_URI'] = choose_db_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False

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
        return self.plus_expires_at and self.plus_expires_at > datetime.utcnow()

    @property
    def is_plus(self):
        return (
            self.plus_type in ['free', 'paid']
            and self.plus_expires_at
            and self.plus_expires_at > datetime.utcnow()
        )

class Streams(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(25), nullable=True, unique=True)
    name = db.Column(db.String(255), nullable=True)
    url = db.Column(db.String(2500), nullable=True)
    category = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=nairobi_time)
    logo = db.Column(db.String(1255), nullable=True)
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

#-----------------------------------------------------------------------
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
def verify_email_token(token, expiration=300):
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
#------------------------------------------------------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'superadmin']:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

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
            flash('Email Already exist', 'error')
            return render_template('register.html', email=email_addr, name=name, password=password, confirm_password=confirm_password)
            
        if password != confirm_password:
            flash("Passwords don't match", "error")
            return render_template('register.html',
                                   name=name, email=email_addr,
                                   password=password, confirm_password=confirm_password)

        secret_code = AdminCode.query.first()
        if not secret_code:
            new_code = AdminCode(code="479admin479")
            db.session.add(new_code)
            db.session.commit()
            secret_code = AdminCode.query.first()

        if secret_code and code_input == secret_code.code:
            role = 'admin'
        else:
            role = 'user'

        status = 'active'
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, password=hashed_password,
                        email=email_addr, role=role,
                        status=status, agreed=True, plus_expires_at=datetime.utcnow() - timedelta(seconds=1), plus_type=None, last_free_plus=None)
        db.session.add(new_user)
        db.session.commit()

        send_verification_email(new_user)
        flash(f"Account created as {role}. Check your email to verify.", "success")

        return redirect(url_for('home'))

    return render_template("register.html")

#----------------------------------------------------------------------

@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated and current_user.status == "active":
        if current_user.role == 'admin':
            return redirect(url_for('home_admin'))
        if current_user.is_plus:
            return redirect(url_for('home_2'))
        return redirect(url_for('home_1'))

    if request.method == "POST":
        email_addr = request.form['email']
        password = request.form['password']

        if not password or not email_addr:
            flash('All fields are required', "error")
            return render_template('login.html')

        user = User.query.filter_by(email=email_addr).first()

        if user:
            # Auto-unlock after 5 minutes
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
                user.failed_login_attempts = 0  # Reset on success
                db.session.commit()
                session.clear()

                session['role'] = user.role
                session['active'] = user.status
                login_user(user)
                flash("♻️ Welcome back!", "success")

                if user.role == 'admin':
                    return redirect(url_for('home_admin'))
                if user.is_plus:
                    return redirect(url_for('home_2'))
                return redirect(url_for('home_1'))
            else:
                # Increase failed attempt count
                user.failed_login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()

        flash('Invalid Credentials', "error")
        return render_template('login.html', email=email, password=password)

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
    return render_template('home_2.html', user=current_user)
#-----------------------------------------------------------------------
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
@app.route("/sports_playlist")
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
        group = ch.get('group-title', 'Uncategorized')
        # Include the key inside each channel dict
        ch_with_key = ch.copy()
        ch_with_key['key'] = key
        grouped[group].append(ch_with_key)

    # Optional: Sort channels in each group alphabetically by name
    for group in grouped:
        grouped[group] = sorted(grouped[group], key=lambda x: x.get('name', '').lower())

    # Sort groups alphabetically
    categorized_channels = dict(sorted(grouped.items(), key=lambda x: x[0].lower()))

    return render_template('custom_list.html', categorized_channels=categorized_channels)
#-------------------------------------------------------------------------
import json
import os
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
        current_app.logger.error(f"Movies file not found at {os.path.abspath(MOVIES_FILE)}")
        return {}

    # Check cache freshness
    use_cache = (os.path.exists(CACHE_FILE) and 
                (os.path.getmtime(CACHE_FILE) > os.path.getmtime(MOVIES_FILE)))

    if use_cache:
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            current_app.logger.warning(f"Cache load failed: {e}")

    # Load and process original file
    try:
        with open(MOVIES_FILE, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
    except Exception as e:
        current_app.logger.error(f"Failed to load movies: {e}")
        return {}

    processed = {}
    for original_key, movie in raw_data.items():
        if not isinstance(movie, dict):
            current_app.logger.warning(f"Skipping invalid movie entry: {original_key}")
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
                current_app.logger.warning(f"Skipping movie with empty URL: {original_key}")
                continue
                
            processed[clean_movie['id']] = clean_movie
        except Exception as e:
            current_app.logger.warning(f"Error processing movie {original_key}: {e}")
            continue

    # Save to cache
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(processed, f, indent=2, ensure_ascii=False)
    except Exception as e:
        current_app.logger.warning(f"Failed to save cache: {e}")

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
import os
from urllib.parse import quote_plus
#=======================================
from flask import Blueprint

YOUTUBE_API_KEY = "AIzaSyBJAD2gfCDfMO1mNdrWWTegL9ZUSBSLt44"

@app.route("/live_matches")
def live_matches():
    url = "https://www.googleapis.com/youtube/v3/search"
    params = {
        "part": "snippet",
        "type": "video",
        "eventType": "live",
        "q": "football match",  # You can change to "live sports" etc.
        "maxResults": 10,
        "key": YOUTUBE_API_KEY
    }

    try:
        response = requests.get(url, params=params)
        data = response.json()
        live_streams = []

        for item in data.get("items", []):
            live_streams.append({
                "title": item["snippet"]["title"],
                "video_id": item["id"]["videoId"],
                "channel": item["snippet"]["channelTitle"],
                "published_at": item["snippet"]["publishedAt"]
            })

        return render_template("live_matches.html", streams=live_streams)

    except Exception as e:
        return f"Failed to fetch live data: {str(e)}", 500
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
# Proxy route to stream remote content
@app.route('/proxy')
def proxy():
    remote_url = request.args.get('url')
    if not remote_url:
        return abort(400, "Missing 'url' parameter")

    try:
        remote_resp = requests.get(remote_url, headers=PROXY_HEADERS, stream=True, timeout=10)
        remote_resp.raise_for_status()
    except requests.RequestException as e:
        return abort(502, f"Upstream error: {e}")

    return Response(
        stream_with_context(remote_resp.iter_content(chunk_size=8192)),
        content_type=remote_resp.headers.get('Content-Type', 'application/octet-stream'),
        status=remote_resp.status_code
    )

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

CHANNELS_FILE = 'channels.json'

def load_channels():
    if not os.path.exists(CHANNELS_FILE):
        return {}
    with open(CHANNELS_FILE, 'r') as f:
        return json.load(f)

def save_channels(channels):
    with open(CHANNELS_FILE, 'w') as f:
        json.dump(channels, f, indent=2)

# Expose as alias
CUSTOM_CHANNELS = load_channels()

import random

# 17 channels from CUSTOM_CHANNELS
selected_keys = [
    "afro-beats", "bollywood", "citizen-tv", "disney-jr", "ebru-tv", "emmanual-tv",
    "figth-network", "fifa-a", "inooro-tv", "kameme-tv", "k24-tv", "kass-tv", "kbc",
    "ktn", "kyeni-tv", "lolwe-tv", "movie-box", "nick-jr-east", "ntv-kenya",
    "ramogi-tv", "racing-com", "sporty", "tom-and-jerry"
]

RANDOMIZED_CHANNELS = {
    key: CUSTOM_CHANNELS[key]
    for key in selected_keys
    if key in CUSTOM_CHANNELS
}

@app.route('/home_1')
@login_required
def home_1():
    return render_template('home_1.html', user=current_user, channels=RANDOMIZED_CHANNELS)

#======================================
#               >>>>PLAYERS AVAILABLE<<<<
#======================================
#  For home_1 - basic users and home_2 - Plus          access users

@app.route("/channel/<key>")
@login_required
def play_channel(key):
    channel = RANDOMIZED_CHANNELS.get(key)
    if not channel:
        abort(404)

    channels = [
        {"key": k, "name": v["name"], "url": v["url"]}
        for k, v in RANDOMIZED_CHANNELS.items()
    ]

    return render_template(
        "custom_player.html",
        channel_name=channel["name"],
        stream_url=channel["url"],
        channels=channels,       # Now a list of dicts with name, url, key
        current_key=key 
    )
#-------------------------------------------------------------------------
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

@app.route('/player')
def player():
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
#------------------------------------------------------------------------
@app.route("/api/channel_stream_url")
@login_required
def channel_stream_url():
    key = request.args.get("key")
    channel = RANDOMIZED_CHANNELS.get(key)
    if not channel:
        return jsonify({"error": "Channel not found"}), 404
    return jsonify({
        "stream_url": channel["url"],
        "name": channel["name"]
    })

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
    all_channels = list(CUSTOM_CHANNELS.items())
    random_channels = dict(random.sample(all_channels, min(15, len(all_channels))))
    return render_template('index.html', channels=random_channels, current_year=datetime.now().year) 
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
            new_pw = request.form.get("new_password")
            if len(new_pw) < 4:
                flash("Password too short", "error")
            if current_pw != new_pw:
                flash("Password don't match", "error")
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
@admin_required
def home_admin():
    # Get statistics from database
    total_users = User.query.count()
    
    # Count users marked as 'active'
    active_today = User.query.filter_by(status='active').count()
    
    # Total channels from CUSTOM_CHANNELS dictionary
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
@admin_required
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
@admin_required
def update_plus(user_id):
    user = User.query.get_or_404(user_id)

    try:
        hours = int(request.form.get("hours", 0))
        minutes = int(request.form.get("minutes", 0))
        seconds = int(request.form.get("seconds", 0))

        duration = timedelta(hours=hours, minutes=minutes, seconds=seconds)
        if duration.total_seconds() <= 0:
            flash("Duration must be greater than 0", "error")
            return redirect(url_for("manage_plus"))

        user.plus_expires_at = datetime.utcnow() + duration
        user.plus_type = user.plus_type or "paid"
        db.session.commit()

        flash(f"Updated Plus time for {user.email}", "success")
    except Exception as e:
        flash("Failed to update Plus", "error")

    return redirect(url_for("manage_plus"))
#-------------------------------------------------------------------    
@app.route("/admin/delete_plus/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_plus(user_id):
    user = User.query.get_or_404(user_id)
    user.plus_expires_at = datetime.utcnow() - timedelta(seconds=1)
    user.plus_type = None
    db.session.commit()

    flash(f"Revoked Plus for {user.email}", "success")
    return redirect(url_for("manage_plus"))
#-------------------------------------------------------------------------
# user management

@app.route("/manage-users")
@login_required
@admin_required
def manage_users():

    users = User.query.filter(User.id != current_user.id).order_by(User.created_at.desc()).all()
    return render_template("manage_users.html", users=users)
#--------------------------------------------------------------------------
@app.route("/toggle-admin/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def toggle_admin(user_id):

    user = User.query.get_or_404(user_id)
    user.role = "user" if user.role == "admin" else "admin"
    db.session.commit()
    flash(f"User role changed to '{user.role}'.", "success")
    return redirect(url_for("manage_users"))
#-------------------------------------------------------------------------
@app.route("/toggle-ban/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def toggle_ban(user_id):

    user = User.query.get_or_404(user_id)
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
@admin_required
def delete_user(user_id):

    user = User.query.get_or_404(user_id)
    # Delete associated payments (if any)
    Payment.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("manage_users"))
#------------------------------------------------------------------------
@app.route("/admin/update_email/<int:user_id>", methods=["POST"])
@login_required
@admin_required
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
@admin_required
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
@admin_required
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
        current_app.logger.error(f"Error saving playlist: {str(e)}")
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
def clone_data():
    db1_url = os.getenv("DATABASE_URL")
    db2_url = os.getenv("DATABASE_URL_3")

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
@admin_required
def manage_channels():
    channels = load_channels()
    return render_template("manage_channels.html", channels=channels)
#--------------------------------------------------------------------------
@app.route("/admin/channels/add", methods=["POST", "GET"])
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

    try:
        return redirect(request.referrer), 400
    except Exception:
        return redirect(url_for('home')), 400

#========================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=47947, debug=False)