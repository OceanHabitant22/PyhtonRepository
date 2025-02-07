from functools import wraps
from flask import redirect, url_for
from flask_login import current_user

def custom_login_required(f):
    """
    An alternative to Flask-Login's login_required. Use this if you want to customize
    redirection or additional checks.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function
