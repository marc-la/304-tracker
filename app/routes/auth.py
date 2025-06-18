from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
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
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                flash('Please confirm your email address first.', 'warning')
                return redirect(url_for('auth.login'))
            login_user(user)
            return redirect(url_for('dashboard.index'))  # <-- FIXED
        flash('Invalid email or password.')
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
            token = get_serializer().dumps(user.email, salt='password-reset')
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            send_email_async(user.email, 'Password Reset', 'email/reset_password', reset_url=reset_url)
        flash('If your email is registered, you will receive a password reset link.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/request_reset.html', form=form)

# --- Password Reset ---
@auth_bp.route('/password/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    try:
        email = get_serializer().loads(token, salt='password-reset', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.request_reset'))
    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
        db.session.commit()
        flash('Your password has been updated. Please log in.', 'success')
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