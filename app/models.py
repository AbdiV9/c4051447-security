from app import db
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet  # Part G: encryption for bios


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

    # hashed (peppered) password
    password = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(50), default="user", nullable=False)

    # Encrypted biography stored in DB
    _bio = db.Column("bio", db.Text, nullable=False)

    # Fernet helper
    def _get_fernet(self) -> Fernet:
        key = current_app.config["BIO_ENC_KEY"].encode()
        return Fernet(key)

    # Decrypted bio property
    @property
    def bio(self) -> str:
        if not self._bio:
            return ""
        f = self._get_fernet()
        return f.decrypt(self._bio.encode()).decode("utf-8")

    # Encrypt bio before storing
    @bio.setter
    def bio(self, value: str) -> None:
        plaintext = (value or "").encode("utf-8")
        f = self._get_fernet()
        token = f.encrypt(plaintext).decode("utf-8")
        self._bio = token

    # Password pepper
    def _pepper(self, password: str) -> str:
        pepper = current_app.config.get("PASSWORD_PEPPER", "")
        return f"{password}{pepper}"

    # Set password with hash + pepper
    def set_password(self, new_password: str) -> None:
        self.password = generate_password_hash(self._pepper(new_password))

    # Check password with hash + pepper
    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password, self._pepper(password))

    def __init__(self, username: str, password: str, role: str, bio: str):
        self.username = username
        self.role = role
        self.bio = bio  # encrypted via setter
        self.set_password(password)
