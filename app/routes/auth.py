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
from datetime import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Serializer for tokens
def get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

# --- Signup ---
@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
        user = User(
            name=form.name.data,  # <-- restore name
            email=form.email.data,
            password_hash=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        # Send confirmation email asynchronously
        token = get_serializer().dumps(user.email, salt='email-confirm')
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        send_email_async(user.email, 'Confirm Your Email', 'email/activate', confirm_url=confirm_url)
        flash('A confirmation email has been sent. Please check your inbox.', 'info')
        logout_user()  # Ensure user is logged out until confirmed
        return redirect(url_for('auth.login'))
    return render_template('auth/signup.html', form=form)

# --- Email Confirmation ---
@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = get_serializer().loads(token, salt='email-confirm', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The confirmation link is invalid or has expired.', 'danger')
        logout_user()
        return redirect(url_for('auth.login'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:  # <-- fix here
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True  # <-- fix here
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
            
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                flash('Please confirm your email address first.', 'warning')
                return redirect(url_for('auth.login'))
            
            # Record successful login
            user.record_login(success=True)
            
            # Generate fresh session ID to prevent session fixation
            session.clear()
            login_user(user)
            
            # Security logging
            current_app.logger.info(f"Successful login: User {user.id} ({user.email})")
            
            next_page = request.args.get('next')
            # Only redirect to 'next' if it's a relative path (security)
            if next_page and not next_page.startswith('/'):
                next_page = None
                
            return redirect(next_page or url_for('dashboard.index'))
        elif user:
            # Record failed login
            user.record_login(success=False)
            current_app.logger.warning(f"Failed login attempt for user: {form.email.data}")
        else:
            current_app.logger.warning(f"Login attempt for non-existent user: {form.email.data}")
            
        flash('Invalid email or password.', 'danger')
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
def request_reset():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            # Send email with password reset instructions
            msg = Message('Password Reset Request',
                          recipients=[user.email])
            reset_url = url_for('auth.reset_token', token=token, _external=True)
            msg.body = f'''To reset your password, visit the following link:
{reset_url}
            
If you did not make this request, simply ignore this email and no changes will be made.
'''
            mail.send(msg)
            current_app.logger.info(f"Password reset requested for {user.email}")
        # Always show this message even if user doesn't exist (prevent user enumeration)
        flash('If that email address exists, we have sent instructions to reset your password.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/request_reset.html', form=form)

# --- Password Reset ---
@auth_bp.route('/password/reset/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('auth.reset_request'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        current_app.logger.info(f"Password reset successfully for {user.email}")
        flash('Your password has been updated! You can now log in', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

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