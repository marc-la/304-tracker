from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from app import mail  # Ensure you initialize Flask-Mail in your app/__init__.py
from app.models import db, User
from app.forms import LoginForm, SignupForm, RequestResetForm, ResetPasswordForm
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if not user.email_confirmed:
                # Redirect to a dedicated page for unconfirmed users
                return redirect(url_for('auth.unconfirmed', email=user.email))
            login_user(user)
            flash(f'Welcome back, {user.name}! You have successfully logged in.', 'success')
            return redirect(url_for('dashboard.index'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@auth_bp.route('/unconfirmed')
def unconfirmed():
    email = request.args.get('email')
    return render_template('unconfirmed.html', email=email)

@auth_bp.route('/resend_confirmation')
def resend_confirmation():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()
    if user and not user.email_confirmed:
        token = user.generate_confirmation_token()
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('email/activate.html', confirm_url=confirm_url)
        msg = Message('Confirm Your Email', recipients=[user.email], html=html)
        mail.send(msg)
        flash('A new confirmation email has been sent. Please check your inbox.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'warning')
        else:
            user = User(name=form.name.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            # Send confirmation email
            token = user.generate_confirmation_token()
            confirm_url = url_for('auth.confirm_email', token=token, _external=True)
            html = render_template('email/activate.html', confirm_url=confirm_url)
            msg = Message('Confirm Your Email', recipients=[user.email], html=html)
            mail.send(msg)
            flash('Signup successful! Please check your email to confirm your account before logging in.', 'success')
            return redirect(url_for('auth.login'))
    return render_template('signup.html', form=form)

@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    email = User.confirm_token(token)
    if not email:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.email_confirmed = True
        user.email_confirmed_at = datetime.utcnow()
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            reset_url = url_for('auth.reset_token', token=token, _external=True)
            html = render_template('email/reset_password.html', reset_url=reset_url)
            msg = Message('Password Reset Request', recipients=[user.email], html=html)
            mail.send(msg)
        flash('If your email is registered, you will receive a password reset link.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('reset_request.html', form=form)

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('auth.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('reset_token.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))