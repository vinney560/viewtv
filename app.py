from flask import Flask, session, abort, render_template, request, flash, url_for, redirect, jsonify, send_from_directory
from flask_login import login_user, logout_user as flask_logout_user, LoginManager, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect, CSRFError
from functools import wraps
import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, Index, text, create_engine
from sqlalchemy.exc import OperationalError, IntegrityError
from sqlalchemy.orm import joinedload
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from datetime import datetime, timedelta   # Added for nairobi_time
import requests
import base64
from requests.auth import HTTPBasicAuth 

load_dotenv()

#================================

app = Flask(__name__)

# Secure and fallback-safe config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "12345QWER")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "4321REWQ")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///default.db")
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Persistent session lifetime
app.permanent_session_lifetime = timedelta(days=7)

app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT")) if os.getenv("MAIL_PORT") else None
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == 'True'
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
CORS(app)
csrf = CSRFProtect()
csrf.init_app(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

mail = Mail(app)

#================================

def nairobi_time():
    return datetime.utcnow() + timedelta(hours=3)  # Converts GMT to Kenyan Local Time

#-------------------------------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)  # full name for reference in emailing
    email = db.Column(db.String(255), unique=True, nullable=False)  # For day-to-day communication & Notice
    password = db.Column(db.String(255), nullable=False)  # Increased length to hold hash
    role = db.Column(db.String(50), default='user', nullable=True)  # plus, user, admin.
    status = db.Column(db.String(50), nullable=True)  # Active, Paid, Deactivated, Blacklisted, Locked
    failed_login_attempts = db.Column(db.Integer, nullable=True, default=0)  # 5 wrong password-locks account
    email_verified = db.Column(db.Boolean, nullable=True, default=False)  # Confirms if email is valid & owned by User
    agreed = db.Column(db.Boolean, nullable=True, default=False)  # Agreement to Terms & Conditions of the Services
    created_at = db.Column(db.DateTime, default=nairobi_time, nullable=True)
    plus_expires_at = db.Column(db.DateTime, nullable=True)
    plus_type = db.Column(db.String(10), nullable=True)  # 'free' or 'paid'
    last_free_plus = db.Column(db.DateTime, nullable=True)
    last_failed_login = db.Column(db.DateTime, nullable=True)

    def is_locked(self):
        if self.failed_login_attempts < 5:
            return False
        if not self.last_failed_login:
            return False
        unlock_time = self.last_failed_login + timedelta(minutes=5)
        if datetime.utcnow() > unlock_time:
            # Reset if the time has passed
            self.failed_login_attempts = 0
            self.last_failed_login = None
            db.session.commit()
            return False
        return True    

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Tv = db.Column(db.String(1255), nullable=True)
    Tv_url = db.Column(db.String(1000), nullable=True)
    country = db.Column(db.String(1255), nullable=True)
    created_at = db.Column(db.DateTime, default=nairobi_time)
    
class AdminCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(500), default="479admin479", nullable=True)

    def __repr__(self):
        return f"<AdminCode {self.code}>"

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Assuming 'user' table
    phone = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="Pending")  # "Pending", "Success", "Failed"
    mpesa_receipt = db.Column(db.String(100))  # Optional: store M-Pesa receipt
    
#=====================================    

with app.app_context():
    db.drop_all()
    # Recreate all tables from models
    db.create_all()

#======================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
#-------------------------------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'superadmin']:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function
#-------------------------------------------------
def is_admin():
    return session.get('role') == 'admin'
#-------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('uploaded_file', filename='favicon.ico'))
#-------------------------------------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)    
#-------------------------------------------------
@app.route('/is_authenticated')
def is_authenticated():
    return jsonify({'authenticated': current_user.is_authenticated})
#-------------------------------------------------
@app.before_request
def make_session_permanent():
    session.permanent = True
#-------------------------------------------------
@app.before_request
def auto_logout_user():
    if current_user.is_authenticated:
        user = User.query.filter_by(id=current_user.id).first()
        if user and user.role != current_user.role:
            logout_current_user()
            flash("Role has changed. Please log in again.", "error")
            return redirect(url_for('login'))
#-------------------------------------------------
def generate_email_token(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user.email, salt='email-verification')
#-------------------------------------------------
def verify_email_token(token, expiration=300):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verification', max_age=expiration)
    except Exception:
        return None
    return email
#-------------------------------------------------
def send_verification_email(user):
    token = generate_email_token(user)
    verify_link = url_for('verify_registration', token=token, _external=True)

    msg = Message(
        subject="Verify your T-Give Nexus account",
        recipients=[user.email]
    )
    msg.html = render_template('verify_email_template.html', verify_link=verify_link)

    try:
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send verification email: {e}")
#-------------------------------------------------
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
    flash('Email verified! Welcome to T-Give Nexus.', 'success')
    return redirect(url_for('welcome'))
#-------------------------------------------------
def create_reset_token(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user.email, salt='password-reset-salt')
#-------------------------------------------------
def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email_addr = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email_addr
#-----------------------------------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
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
#-------------------------------------------------
def send_reset_email(user):
    token = create_reset_token(user)
    reset_link = url_for('reset_password', token=token, _external=True)

    msg = Message(
        subject="Password Reset Request",
        sender=("View Tv", "vinneyjoy1@gmail.com"),
        recipients=[user.email],
    )
    msg.html = render_template('forgot_password_email.html', reset_link=reset_link)
    mail.send(msg)
#-------------------------------------------------
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

#================================
#        >>>>ACCESS GRANTERS<<<<
#================================

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        name = request.form["name"]
        email_addr = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        code_input = request.form.get('code')

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
                        status=status, agreed=True)
        db.session.add(new_user)
        db.session.commit()

        send_verification_email(new_user)

        return redirect(url_for('home'))

    return render_template("register.html")

#-------------------------------------------------

@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        role = session.get('role') or current_user.role
        if role == 'admin':
            return redirect(url_for('home_admin'))
        elif role == 'plus':
            return redirect(url_for('home_2'))
        else:
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
                flash("?? Welcome back!", "success")

                if user.role == 'plus':
                    return redirect(url_for('home_2'))
                elif user.role == 'admin':
                    return redirect(url_for('home_admin'))
                else:
                    return redirect(url_for('home_1'))
            else:
                # Increase failed attempt count
                user.failed_login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                db.session.commit()

        flash('Invalid Credentials', "error")
        return redirect(url_for('login'))

    return render_template('login.html')

#=================================================
    
@app.route('/home_admin')
@login_required 
@admin_required
def home_admin():
    return render_template('home_admin.html')

#================================
#           >>>>ROLE BASED ACTIONS<<<<
#================================
#           >>>>VIP MODE<<<<
#================================
def plus_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'plus']:
            flash('This is a paid feature. Visit the plus page')
            return render_template("home_1.html")
        return f(*args, **kwargs)
    return decorated_function
#-------------------------------------------------
@app.route('/home_2')
@login_required
#@plus_required
def home_2():
    return render_template('home_2.html', user=current_user)
#------------------------------------------------

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
#------------------------------------------------
@app.route("/sports_playlist")
def sports_playlist():
    channels_by_group = get_grouped_channels()
    return render_template(
        "sports_playlist.html",
        channels_by_group=channels_by_group,
        current_year=datetime.now().year
    )
#------------------------------------------------
@app.route("/plus_playlist")
def plus_playlist():
    pass
#------------------------------------------------

@app.route('/player')
@login_required
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
    
#-------------------------------------------------
# Fetch & Save by Country
@app.route('/save_channels')
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
                        exists = Channel.query.filter_by(Tv=name, Tv_url=link).first()
                        if not exists:
                            db.session.add(Channel(Tv=name, Tv_url=link, country=country_code))
                            new_count += 1

        db.session.commit()
        print(f"[INFO] Added {new_count} new channels from {country_code}")
    except Exception as e:
        print(f"[ERROR] Failed to fetch from {url}: {e}")
#-------------------------------------------------
@app.route("/countries")
@login_required
#@plus_required
def countries():
    try:
        response = requests.get("https://iptv-org.github.io/api/countries.json")
        response.raise_for_status()
        countries = response.json()
        return render_template("countries.html", countries=countries)
    except Exception as e:
        return f"Error fetching countries: {e}"
#------------------------------------------------
@app.route("/country/<country_code>")
@login_required
#@plus_required
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
#-----------------------------------------------
@app.route("/category/<category_id>")
@login_required 
#@plus_required
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
#-------------------------------------------------
@app.route("/categories")
@login_required
#@plus_required
def categories():
    try:
        response = requests.get("https://iptv-org.github.io/api/categories.json")
        response.raise_for_status()
        categories = response.json()
        return render_template("categories.html", categories=categories)
    except Exception as e:
        return f"Failed to load categories: {e}"
#-------------------------------------------------
@app.route("/more-channels")
@login_required
#@plus_required
def more_channels():
    return render_template("more_channels.html")
#-------------------------------------------------
@app.route("/watch")
@login_required
#@plus_required
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
#-------------------------------------------------
@app.route('/browse')
def browse():
    return render_template('browse.html')
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

#================================
#             >>>>BASIC MODE<<<<
#================================
from channels import CUSTOM_CHANNELS 

#basic_mode Home page 
@app.route('/home_1')
def home_1():
    channels=CUSTOM_CHANNELS
    return render_template('home_1.html', user=current_user, channels=channels)

#with open('channels.json', 'r') as file:
#    custom_channels = json.load(file)

@app.route("/custom-list")
@login_required
def custom_list():
    return render_template("custom_list.html", channels=CUSTOM_CHANNELS)
#-------------------------------------------------
@app.route("/channel/<key>")
@login_required
#@plus_required
def play_channel(key):
    channel = CUSTOM_CHANNELS.get(key)
    if not channel:
        abort(404)

    channels = [
        {"key": k, "name": v["name"], "url": v["url"]}
        for k, v in CUSTOM_CHANNELS.items()
    ]

    return render_template(
        "custom_player.html",
        channel_name=channel["name"],
        stream_url=channel["url"],
        channels=channels,       # Now a list of dicts with name, url, key
        current_key=key          # Pass current key for highlighting
    )
#-------------------------------------------------
@app.route("/api/channel_stream_url")
@login_required
#@plus_required
def channel_stream_url():
    key = request.args.get("key")
    channel = CUSTOM_CHANNELS.get(key)
    if not channel:
        return jsonify({"error": "Channel not found"}), 404
    return jsonify({
        "stream_url": channel["url"],
        "name": channel["name"]
    })

#================================
#        >>>>PLUS & PAYMENT FEATURE<<<<
#================================
#free plus feature

@app.route("/get_plus")
def get_plus():
    return render_template("plus.html")

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
    user.role = "plus"
    db.session.commit()

    flash("🎁 Free Plus activated for 2 hours!", "success")
    return redirect(url_for("dashboard"))

#add || update plus(timer)

@app.route("/admin/manage_plus")
@login_required
#@admin_required
def manage_plus():
    users = User.query.filter(User.plus_expires_at != None).all()
    return render_template("manage_plus.html", users=users)   
#------------------------------------------------------------------
@app.route("/admin/update_plus/<int:user_id>", methods=["POST"])
@login_required
#@admin_required
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
        user.role = "plus"
        db.session.commit()

        flash(f"Updated Plus time for {user.email}", "success")
    except Exception as e:
        flash("Failed to update Plus", "error")

    return redirect(url_for("manage_plus"))
#-------------------------------------------------------------------    
@app.route("/admin/delete_plus/<int:user_id>", methods=["POST"])
@login_required
#@admin_required
def delete_plus(user_id):
    user = User.query.get_or_404(user_id)
    user.plus_expires_at = None
    user.plus_type = None
    user.role = "user"
    db.session.commit()

    flash(f"Revoked Plus for {user.email}", "success")
    return redirect(url_for("manage_plus"))
#-----------------------------------------------------------------------

@app.route('/payment')
def payment():
    return render_template('pay.html', user=current_user)

# ------------------------------------------------

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

    business_short_code = "174379"  # Use your actual shortcode
    callback_url = "https://viewtv.onrender.com/callback"

    try:
        auth_response = requests.get(
            "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
            auth=(consumer_key, consumer_secret)
        )
        print("Token response:", auth_response.text)
        auth_response.raise_for_status()
        access_token = auth_response.json().get("access_token")
    except Exception as e:
        return jsonify({"success": False, "message": f"Token error: {str(e)}"}), 500

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

    try:
        response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers=headers
        )
        print("STK Push response:", response.text)
        response.raise_for_status()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": f"Push error: {str(e)}"}), 500

# ------------------------------------------------
@app.route('/callback', methods=['POST'])
def callback():
    data = request.get_json()
    print("?? Callback Received:", data)

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
                    user.role = "VIP"
                    db.session.commit()

            print("?? Payment verified and VIP access granted.")
            return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})

        else:
            print("?? Payment failed:", result_desc)
            return jsonify({"ResultCode": 0, "ResultDesc": "Failed transaction"})

    except Exception as e:
        print("Callback processing error:", str(e))
        return jsonify({"ResultCode": 1, "ResultDesc": "Error processing callback"})
# ------------------------------------------------
@app.route('/vip-confirm')
def vip_confirm():
    flash("?? PAYMENT SUCCESSFUL. You are now a VIP. Please log in again.", "success")
    logout_user(current_user)
    return redirect(url_for('login'))
    
#================================
#       >>>>GENERAL ENDPOINTS<<<<
#================================
@app.route("/")
def home():
    channels = CUSTOM_CHANNELS
    return render_template('index.html', channels=channels, current_year=datetime.now().year)
#-------------------------------------------------
@app.route('/about')
def about():
    return render_template('about.html')
#-------------------------------------------------
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
            current_user.role = 'user'
            current_user.plus_expires_at = None
            current_user.plus_type = None
            db.session.commit()
            flash("Plus depleted. You’ll be redirected in 2 minutes.", "error")
            redirect_flag = True

    return render_template(
        "dashboard.html",
        user=current_user,
        time_remaining_seconds=remaining,
        redirect_in_2min=redirect_flag
    )
#-------------------------------------------------
@app.route('/copyright')
def copyright():
    return render_template('copyright.html')
#-------------------------------------------------
@app.route("/welcome")
@login_required
def welcome():
    return render_template("welcome.html")
#-------------------------------------------------
@app.route('/logout_current_user')
def logout_current_user():
    session.clear()
    flask_logout_user()
    return redirect(url_for("home"))
#-----------------------------------------------  
@app.route('/services') 
def services():
    return render_template('services.html')
#-----------------------------------------------
@app.route('/manifest.json')
def manifest():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'manifest.json', mimetype='application/manifest+json')
#--------------------------------
@app.route("/account")
def account():
    pass
#================================

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
    flash('Request cannot be completed', 'error')
    return redirect(request.referrer or url_for('home')), 500

@app.errorhandler(CSRFError)
@csrf.exempt
def handle_csrf_error(e):
    flash("CSRF token missing or invalid", "error")
    return redirect(request.referrer or url_for('home')), 400

#================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=47947, debug=False)
