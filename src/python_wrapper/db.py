import hashlib
import sqlite3


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    api_token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class UsernameTakenError(Exception):
    pass


class TokenCollisionError(Exception):
    pass


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class UserStore:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def create_user(self, username, password_hash, api_token_hash):
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
        cursor = self.conn.execute(
            "SELECT id, username, password_hash, api_token_hash, created_at FROM users WHERE username = ?",
            (username,),
        )
        return cursor.fetchone()

    def get_by_token_hash(self, api_token_hash):
        cursor = self.conn.execute(
            "SELECT id, username, password_hash, api_token_hash, created_at FROM users WHERE api_token_hash = ?",
            (api_token_hash,),
        )
        return cursor.fetchone()

    def count(self):
        cursor = self.conn.execute("SELECT COUNT(*) AS total FROM users")
        return cursor.fetchone()["total"]

    def close(self):
        self.conn.close()
