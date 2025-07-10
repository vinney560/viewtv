#======================================
#                     >>>>DB MODEL<<<<
#======================================
import os
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