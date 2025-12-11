import os
class BaseConfig:
    # Base config shared by all enviroments


    SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Password pepper — mixed into password before hashing
    PASSWORD_PEPPER = os.environ.get(
        "PASSWORD_PEPPER",
        "dev-pepper-change-me"
    )

    #  Fernet key for encrypting/decrypting biography text
    BIO_ENC_KEY = os.environ.get(
        "BIO_ENC_KEY",
        "kP9mtklV7z97BJSxk4n8dNHQWfhTR0Y6z2M8CMPbUZw="  # Example valid key
    )


class DevelopmentConfig(BaseConfig):
    #  development config (debug enabled, local DB)
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DEV_DATABASE_URL", "sqlite:///site.db")
    SESSION_COOKIE_SECURE = False  # HTTP ok for local dev


class ProductionConfig(BaseConfig):
    # Production config (debug disabled, secure)
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")  # must be set in env
    SESSION_COOKIE_SECURE = True  # HTTPS required


# Keep this for compatibility if something still imports Config
Config = DevelopmentConfig
