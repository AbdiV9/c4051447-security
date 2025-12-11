import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf import CSRFProtect
import os

from config import DevelopmentConfig, ProductionConfig


db = SQLAlchemy()
csrf = CSRFProtect() #  CSRF Protection



def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Enviroment specific behaviour
    env = os.environ.get("FLASK_ENV", "development")
    if env == "development":
        app.config.from_object("config.DevelopmentConfig")
    else:
        app.config.from_object("config.ProductionConfig")



    db.init_app(app)
    csrf.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    # Security headers applied to every response
    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), fullscreen=(self)"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
        )
        return response

    # Logging and monitoring
    configure_logging(app)
    register_error_handlers(app)


    with app.app_context():
        from .models import User

        db.drop_all()
        db.create_all()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        # Insert only if not already in DB (prevents UNIQUE constraint error)
        for u in users:
            if not User.query.filter_by(username=u["username"]).first():
                user = User(
                    username=u["username"],
                    password=u["password"],
                    role=u["role"],
                    bio=u["bio"]
                )
                db.session.add(user)

        db.session.commit()

    return app


def configure_logging(app: Flask):
    # Rotating file-based logging
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=1_000_000,  # 1MB
        backupCount=5,
    )

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)




def register_error_handlers(app: Flask):
    # Custom error pages with same styling, no debug info

    @app.errorhandler(400)
    def bad_request(e):
        app.logger.warning("400 Bad Request: %s", e)
        return render_template("400.html"), 400

    @app.errorhandler(403)
    def forbidden(e):
        app.logger.warning("403 Forbidden: %s", e)
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        app.logger.warning("404 Not Found: %s", e)
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.error("500 Internal Server Error", exc_info=e)
        return render_template("500.html"), 500