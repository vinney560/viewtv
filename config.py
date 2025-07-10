#=====================================
#            >>>> CONFIG FILE MODEL<<<<
#=====================================
# Secure and fallback-safe config
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "12345QWER")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "4321REWQ")
#======================================
app.config.update({
    'PREFERRED_URL_SCHEME': 'https',
    'SERVER_NAME': 'viewtv-p2s3.onrender.com',
    'APPLICATION_ROOT': '/',
    'SESSION_COOKIE_PATH': '/',
    'TRAP_HTTP_EXCEPTIONS': True
})
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

def choose_db_uri():
    new_uri = os.getenv('DATABASE_URL')     # Prefer this (Old Render)
    render_uri = os.getenv('DATABASE_URL_2')    # Fallback ( New Render)

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

# Apply to Flask app
app.config['SQLALCHEMY_DATABASE_URI'] = choose_db_uri()
#======================================
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Persistent session lifetime
app.permanent_session_lifetime = timedelta(days=1)

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
limiter = Limiter(get_remote_address, app=app, default_limits=["1000 per hour"])

mail = Mail(app)
#-------------------------------------------------------------------------