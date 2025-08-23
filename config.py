#=====================================
#            >>>> CONFIG FILE MODEL<<<<
#=====================================
# config.py
import os
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_limiter.util import get_remote_address
from datetime import timedelta
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv

load_dotenv()

def choose_db_uri():
    new_uri = os.getenv('DATABASE_URL')
    render_uri = os.getenv('DATABASE_URL_2')
    if new_uri:
        try:
            engine = create_engine(new_uri)
            engine.connect().close()
            print("Connected to Render DB (DATABASE_URL)")
            return new_uri
        except OperationalError:
            print("⚠ Failed to connect to Render DB. Trying Render 2 DB...")

    if render_uri:
        try:
            engine = create_engine(render_uri)
            engine.connect().close()
            print("Connected to Render 2 DB (DATABASE_URL)")
            return render_uri
        except OperationalError:
            print("⚠ Failed to connect to Render 2 DB.")

    print("All remote DBs failed. Falling back to SQLite.")
    return "sqlite:///default.db"

def init_app(app):
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "12345QWER")
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "4321REWQ")
    app.config['SQLALCHEMY_DATABASE_URI'] = choose_db_uri()
    app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False

    # Uploads
    UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    # Mail
    app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
    app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT") or 0)
    app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == 'True'
    app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
    app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

    # Session lifetime
    app.permanent_session_lifetime = timedelta(days=1)

    # Init extensions
    # Extensions (global, to be used in app.py)
    db = SQLAlchemy()
    jwt = JWTManager()
    login_manager = LoginManager()
    mail = Mail()
    csrf = CSRFProtect()
    limiter = Limiter(key_func=get_remote_address)
    
    db.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    CORS(app)
#======================================
#                     >>>>DB MODEL<<<<
#======================================
def nairobi_time():
    return datetime.utcnow() + timedelta(hours=3)  # Converts GMT to Kenyan Local Time
#======================================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    # Basic Info
    name = db.Column(db.String(255), nullable=True)  # Optional full name
    email = db.Column(db.String(255), unique=True, nullable=False)  # Required
    password = db.Column(db.String(255), nullable=False)  # Should store hashed passwords

    # Role & Status
    role = db.Column(db.String(50), default='user', nullable=True)  # 'admin' or 'user'
    status = db.Column(db.String(50), nullable=True)  # Optional: Active, Paid, Deactivated, etc.

    # Login & Security
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=True)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=True)
    agreed = db.Column(db.Boolean, default=False, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=nairobi_time, nullable=True)

    # Plus Access Logic
    plus_type = db.Column(db.String(10), nullable=True, default=None)  # 'free' or 'paid'
    plus_expires_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow() - timedelta(seconds=1))
    last_free_plus = db.Column(db.DateTime, nullable=True, default=None)

    # ------------------------
    # Logic | Helpers
    # ------------------------

    def is_locked(self):
        """Check if user is temporarily locked due to failed logins."""
        if self.failed_login_attempts < 5:
            return False
        if not self.last_failed_login:
            return False

        unlock_time = self.last_failed_login + timedelta(minutes=5)
        if datetime.utcnow() > unlock_time:
            # Reset if lock duration has passed
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
        """Return True if Plus is active and not expired."""
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
    access = db.Column(db.String(15), nullable=True) # free | paid
    status = db.Column(db.Boolean, default=True, nullable=True) #True-Active False-Down
    
    
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
#-----------------------------------------------------------------------