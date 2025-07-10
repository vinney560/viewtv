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
    db.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    CORS(app)
#----------------------------------------------------------------------