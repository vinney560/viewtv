#======================================
#            >>>> HELPER FUNCTIONS<<<<
#======================================
import os
from flask import Blueprint

helper = Blueprint("helper", __name__)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
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
@app.before_request
def make_session_permanent():
    session.permanent = True
#-----------------------------------------------------------------------
@app.before_request
def auto_logout_user():
    if current_user.is_authenticated:
        user = User.query.filter_by(id=current_user.id).first()
        if user and user.role != current_user.role:
            logout_current_user()
            flash("Role has changed. Please log in again.", "error")
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
        subject="Check Email to Verify your View Tv account",
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
#---------------------------------------------------------------------