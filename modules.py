#=====================================
#            >>>> MODULE FILE MODEL<<<<
#=====================================
# module.py
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer
import requests
from requests.auth import HTTPBasicAuth
import base64
import random
from datetime import datetime, timedelta