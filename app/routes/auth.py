from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, mail
from app.extensions import limiter
from app.models import User
from app.forms import LoginForm, SignupForm, RequestResetForm, ResetPasswordForm
from flask_mail import Message
from threading import Thread
import logging
from datetime import datetime, timedelta
import hashlib

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Serializer for tokens
def get_serializer(user=None, purpose=None):
    # Use a unique salt per user and purpose for extra security
    base_salt = current_app.config['SECRET_KEY']
    if user and purpose:
        salt = hashlib.sha256((str(user.id) + user.email + purpose + base_salt).encode()).hexdigest()
    elif user:
        salt = hashlib.sha256((str(user.id) + user.email + base_salt).encode()).hexdigest()
    else:
        salt = base_salt
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY']), salt

# --- Signup ---
@auth_bp.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit signup
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
        user = User(
            name=form.name.data,
            email=form.email.data,
            password_hash=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        # Send confirmation email asynchronously
        serializer, salt = get_serializer(user, 'email-confirm')
        token = serializer.dumps(user.email, salt=salt)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        send_email_async(user.email, 'Confirm Your Email', 'email/activate', confirm_url=confirm_url)
        flash('A confirmation email has been sent. Please check your inbox.', 'info')
        logout_user()  # Ensure user is logged out until confirmed
        return redirect(url_for('auth.login'))
    return render_template('auth/signup.html', form=form)

# --- Email Confirmation ---
@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    # User enumeration protection: generic error message
    user = None
    try:
        # Try all users (slow, but avoids enumeration)
        for u in User.query.all():
            serializer, salt = get_serializer(u, 'email-confirm')
            try:
                email = serializer.loads(token, salt=salt, max_age=3600)
                user = u
                break
            except Exception:
                continue
    except Exception:
        pass
    if not user:
        flash('The confirmation link is invalid or has expired.', 'danger')
        logout_user()
        return redirect(url_for('auth.login'))
    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True
        db.session.commit()
        flash('Your account has been confirmed. You can now log in.', 'success')
    return redirect(url_for('auth.login'))

# --- Login ---
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Apply rate limiting
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # Check if account is locked
        if user and user.account_locked_until and user.account_locked_until > datetime.utcnow():
            current_app.logger.warning(f"Locked account login attempt: {user.email}")
            flash('Account is temporarily locked due to multiple failed login attempts. Try again later.', 'danger')
            return render_template('login.html', form=form)
        # MFA placeholder (future):
        # if user and user.mfa_enabled:
        #     return redirect(url_for('auth.mfa', user_id=user.id))
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                flash('Please confirm your email address first.', 'warning')
                return render_template('login.html', form=form)
            # Reset failed attempts
            user.failed_login_attempts = 0
            user.account_locked_until = None
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard.index'))
        else:
            # Increment failed attempts and lock if needed
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                lockout_threshold = 5
                if user.failed_login_attempts >= lockout_threshold:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
                db.session.commit()
            # User enumeration protection: generic error
            flash('Invalid email or password.', 'danger')
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)

# --- Logout ---
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# --- Request Password Reset ---
@auth_bp.route('/password/reset', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Rate limit password reset requests
def request_reset():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # Always show same message to avoid user enumeration
        if user:
            serializer, salt = get_serializer(user, 'password-reset')
            token = serializer.dumps(user.email, salt=salt)
            reset_url = url_for('auth.reset_token', token=token, _external=True)
            send_email_async(user.email, 'Password Reset Request', 'email/reset_password', reset_url=reset_url)
        flash('If your email is registered, you will receive a password reset link.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/request_reset.html', form=form)

# --- Password Reset ---
@auth_bp.route('/password/reset/<token>', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Rate limit password reset
def reset_token(token):
    user = None
    for u in User.query.all():
        serializer, salt = get_serializer(u, 'password-reset')
        try:
            email = serializer.loads(token, salt=salt, max_age=3600)
            user = u
            break
        except Exception:
            continue
    if not user:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.request_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated. You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_token.html', form=form)

# --- Email sending functions ---
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email_async(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message(subject, recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    Thread(target=send_async_email, args=(app, msg)).start()

# --- End of auth routes ---
# Note: For production, implement MFA (TOTP) and consider using Flask-Talisman for advanced security headers and HTTPS enforcement.