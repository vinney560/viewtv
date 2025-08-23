#=======================================
#              >>>>ADMIN ENDPOINT<<<<
#=======================================
import os
from flask import Blueprint

admin = Blueprint("admin", __name__)
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
    users = User.query.filter(User.plus_expires_at != None).all()
    
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
        user.status = "Active"
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
    channels = CUSTOM_CHANNELS.get(key)
    stream=Streams.query.filter_by(url=url).first()
    
    try:
        for key, ch in channels.items():
            if not stream:
                new_stream=Streams(key=key, name=ch.name, url=ch.url, category="Not specified", logo="", access="free", status=True)
                db.session.add(new_stream)
                flash("Saved Channels", "success")
                return redirect(url_for("manage_channels"))
            flash("Channel exit {stream}", "error")
            return redirect(url_for("manage_channels"))
    except Exception as e:
       flash("Failed to save channels {e}")
       return redirect(url_for("manage_channels"))
    return redirect(url_for("manage_channels"))
       
#------------------------------------------------------------------------
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

@app.route("/admin/clone_data")
@login_required
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
        # Ensure destination DB has the tables
        db.metadata.create_all(dest_engine)

        # List of models to clone
        for model in [User, Channel, Payment]:  # add all models you want to migrate
            rows = source_session.query(model).all()
            for row in rows:
                clone = model(**{
                    col.name: getattr(row, col.name)
                    for col in model.__table__.columns
                })
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