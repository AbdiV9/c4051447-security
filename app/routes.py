import logging

from flask import (
    request,
    render_template,
    redirect,
    url_for,
    session,
    Blueprint,
    flash,
    abort,
)

from app import db
from app.models import User
from app.validation import (
    validate_username,
    validate_string,
    validate_role,
    sanitise_html,
)

main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)


# Centralized authorization helpers
def require_login():
    if "user" not in session:
        logger.warning("Access control: unauthenticated access to %s", request.path)
        abort(403)


def require_role(role):
    if "user" not in session or session.get("role") != role:
        logger.warning(
            "Access control: role '%s' required for %s (have '%s')",
            role,
            request.path,
            session.get("role"),
        )
        abort(403)


def require_any_role(*roles):
    if "user" not in session or session.get("role") not in roles:
        logger.warning(
            "Access control: one of roles %s required for %s (have '%s')",
            roles,
            request.path,
            session.get("role"),
        )
        abort(403)



@main.route('/')
def home():
    return render_template('home.html')



@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            # Validate email/username and password format
            username = validate_username(request.form.get('username'))
            password = validate_string(request.form.get('password'), "Password", min_len=10, max_len=128)
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('login.html'), 400

        # ORM lookup replaces unsafe SQL select
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):

            #  Renew session to prevent session fixation
            session.clear()

            #  Store minimal authenticated info
            session['user'] = user.username
            session['role'] = user.role
            session['bio'] = user.bio

            logger.info(
                "Authentication success for user %s from %s",
                username,
                request.remote_addr,
            )  # Part H
            return redirect(url_for("main.dashboard"))

        logger.warning(
            "Authentication failure for user %s from %s",
            username,
            request.remote_addr,
        )  # Part H
        flash("Login credentials are invalid, please try again", "error")

    return render_template('login.html')




@main.route('/dashboard')
def dashboard():
    require_login()  # Part F
    return render_template(
        "dashboard.html",
        username=session["user"],
        bio=session.get("bio", ""),
    )





@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Validate all input fields
            username = validate_username(request.form.get('username'))
            password = validate_string(request.form.get('password'), "Password", min_len=10, max_len=128)
            role = validate_role(request.form.get('role', 'user'))
            bio = sanitise_html(request.form.get('bio', ""), max_len=500)
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('register.html'), 400

        #  Reject duplicate accounts
        if User.query.filter_by(username=username).first():
            flash('An account with that email already exists.', 'error')


        # Password is hashed inside the User model constructor
        # ORM insert replaces unsafe SQL
        new_user = User(username=username,password=password, role=role,bio=bio)
        db.session.add(new_user)
        db.session.commit()


        logger.info("User %s successfully registered", username)
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html')



@main.route('/admin-panel')
def admin():
    require_role('admin') # Part F Protecting sensitive route
    return render_template('admin.html')


@main.route('/logout')
def logout():
    require_login()
    session.clear()
    session.modified = True
    logger.info("User logged out")
    return redirect(url_for('main.login'))


@main.route('/moderator')
def moderator():
    require_role('moderator') # Part F Protecting sensitive route
    return render_template('moderator.html')


@main.route('/user-dashboard')
def user_dashboard():
    require_role('user')# Protecting sensitive route
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    require_login() # rotecting sensitive route
     # ORM fetch instead of unsafe SQL
    user = User.query.filter_by(username=session['user']).first()
    if not user:
        abort(403)

    if request.method == 'POST':
        try:
            # Validate string lengths
            current_password = validate_string(request.form.get('current_password'), "Current password", min_len=1, max_len=128)
            new_password = validate_string(request.form.get('new_password'), "New password", min_len=10, max_len=128)
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('change_password.html'), 400

        # Verify current password using hashing
        if not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html')

        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html')

        # Securely update password (hashed)
        # Hash and Pepper
        user.set_password(new_password)
        db.session.commit()


        logger.info("Password changed successfully")
        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')

