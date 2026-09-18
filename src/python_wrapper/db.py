import hashlib
import re
import sqlite3
import threading

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    api_token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_token_hash ON users(api_token_hash);
"""


class UsernameTakenError(Exception):
    pass


class TokenCollisionError(Exception):
    pass


class InvalidUsernameError(ValueError):
    pass


class InvalidPasswordError(ValueError):
    pass


def validate_username(username):
    if not isinstance(username, str) or not USERNAME_REGEX.match(username):
        raise InvalidUsernameError(
            "El nombre de usuario solo puede contener letras, numeros, guiones y guiones bajos (1-64 caracteres)"
        )
    return username


def validate_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise InvalidPasswordError(
            f"La contraseña debe tener al menos {MIN_PASSWORD_LEN} caracteres"
        )
    if len(password) > MAX_PASSWORD_LEN:
        raise InvalidPasswordError(
            f"La contraseña no puede exceder {MAX_PASSWORD_LEN} caracteres"
        )
    return password


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class UserStore:
    def __init__(self, db_path):
        self._lock = threading.Lock()
        with self._lock:
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode = WAL;")
            self.conn.execute("PRAGMA synchronous = NORMAL;")
            self.conn.execute("PRAGMA busy_timeout = 5000;")
            self.conn.execute("PRAGMA temp_store = MEMORY;")
            self.conn.execute("PRAGMA cache_size = -2000;")
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def create_user(self, username, password_hash, api_token_hash):
        validate_username(username)
        with self._lock:
            try:
                cursor = self.conn.execute(
                    "INSERT INTO users (username, password_hash, api_token_hash) VALUES (?, ?, ?)",
                    (username, password_hash, api_token_hash),
                )
                self.conn.commit()
            except sqlite3.IntegrityError as error:
                self.conn.rollback()
                if "api_token_hash" in str(error):
                    raise TokenCollisionError("Colision de token, reintentar con uno nuevo") from error
                raise UsernameTakenError(f"El usuario '{username}' ya existe") from error
            return cursor.lastrowid

    def get_by_username(self, username):
        with self._lock:
            cursor = self.conn.execute(
                "SELECT id, username, password_hash, api_token_hash, created_at FROM users WHERE username = ?",
                (username,),
            )
            return cursor.fetchone()

    def get_by_token_hash(self, api_token_hash):
        with self._lock:
            cursor = self.conn.execute(
                "SELECT id, username, password_hash, api_token_hash, created_at FROM users WHERE api_token_hash = ?",
                (api_token_hash,),
            )
            return cursor.fetchone()

    def count(self):
        with self._lock:
            cursor = self.conn.execute("SELECT COUNT(*) AS total FROM users")
            return cursor.fetchone()["total"]

    def update_user_token(self, user_id, new_token_hash):
        with self._lock:
            try:
                self.conn.execute(
                    "UPDATE users SET api_token_hash = ? WHERE id = ?",
                    (new_token_hash, user_id),
                )
                self.conn.commit()
            except sqlite3.IntegrityError as error:
                self.conn.rollback()
                raise TokenCollisionError("Colision de token al actualizar") from error

    def close(self):
        with self._lock:
            self.conn.close()
