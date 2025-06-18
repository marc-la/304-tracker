from flask import Blueprint, render_template
from flask_login import current_user, login_required

hero_bp = Blueprint('hero', __name__)

@hero_bp.route('/')
def hero():
    # If user is logged in, redirect to dashboard
    if current_user.is_authenticated:
        from flask import redirect, url_for
        return redirect(url_for('dashboard.index'))
    return render_template('hero.html')