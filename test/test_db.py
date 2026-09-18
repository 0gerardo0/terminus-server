import pytest

from db import (
    UserStore,
    TokenCollisionError,
    UsernameTakenError,
    InvalidUsernameError,
    InvalidPasswordError,
    validate_username,
    validate_password,
    hash_token,
)


@pytest.fixture()
def store(tmp_path):
    store = UserStore(str(tmp_path / "test_terminus.db"))
    yield store
    store.close()


def test_crea_usuario_y_recupera_por_username(store):
    user_id = store.create_user("gerardo", "$argon2id$HASH", hash_token("token-abc"))

    assert user_id > 0

    row = store.get_by_username("gerardo")
    assert row is not None
    assert row["id"] == user_id
    assert row["password_hash"] == "$argon2id$HASH"


def test_username_duplicado_rechazado(store):
    store.create_user("gerardo", "$argon2id$A", hash_token("token-1"))

    with pytest.raises(UsernameTakenError):
        store.create_user("gerardo", "$argon2id$B", hash_token("token-2"))


def test_busqueda_de_usuario_inexistente_devuelve_none(store):
    assert store.get_by_username("nadie") is None


def test_busqueda_por_token_hash(store):
    token = "token-secreto-123"
    store.create_user("gerardo", "$argon2id$A", hash_token(token))

    row = store.get_by_token_hash(hash_token(token))
    assert row is not None
    assert row["username"] == "gerardo"

    assert store.get_by_token_hash(hash_token("token-falso")) is None
    assert store.get_by_token_hash("") is None


def test_colision_de_token_lanza_error(store):
    same_hash = hash_token("mismo-token")
    store.create_user("gerardo", "$argon2id$A", same_hash)

    with pytest.raises(TokenCollisionError):
        store.create_user("otro", "$argon2id$B", same_hash)


def test_count_y_tabla_vacia(store):
    assert store.count() == 0

    store.create_user("a", "$argon2id$A", hash_token("t-a"))
    store.create_user("b", "$argon2id$B", hash_token("t-b"))
    assert store.count() == 2


def test_created_at_se_genera_solo(store):
    store.create_user("gerardo", "$argon2id$A", hash_token("t"))

    row = store.get_by_username("gerardo")
    assert row["created_at"] is not None
    assert len(row["created_at"]) >= 19


@pytest.mark.parametrize(
    "invalid_name",
    [
        "",
        "../admin",
        "user/slash",
        "con espacio",
        "user@mail.com",
        "a" * 65,
        None,
        123,
    ],
)
def test_username_invalido_rechazado(store, invalid_name):
    with pytest.raises(InvalidUsernameError):
        store.create_user(invalid_name, "$argon2id$A", hash_token(f"tok-{invalid_name}"))


def test_password_validation():
    assert validate_password("12345678") == "12345678"
    assert validate_password("a" * 128) == "a" * 128
    with pytest.raises(InvalidPasswordError):
        validate_password("1234567")
    with pytest.raises(InvalidPasswordError):
        validate_password("a" * 129)
    with pytest.raises(InvalidPasswordError):
        validate_password("")
    with pytest.raises(InvalidPasswordError):
        validate_password(None)


def test_embedded_pragmas_aplicados(store):
    with store._lock:
        journal_mode = store.conn.execute("PRAGMA journal_mode;").fetchone()[0]
        busy_timeout = store.conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        temp_store = store.conn.execute("PRAGMA temp_store;").fetchone()[0]
        cache_size = store.conn.execute("PRAGMA cache_size;").fetchone()[0]

    assert journal_mode.upper() == "WAL"
    assert busy_timeout == 5000
    assert temp_store == 2  # 2 = MEMORY
    assert cache_size == -2000


def test_acceso_concurrente_threads(tmp_path):
    import concurrent.futures

    db_path = str(tmp_path / "concurrent.db")
    store = UserStore(db_path)

    def insert_user(idx):
        store.create_user(f"user_{idx}", f"$hash${idx}", hash_token(f"token_{idx}"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(insert_user, range(20)))

    assert store.count() == 20
    store.close()


def test_update_user_token(store):
    uid = store.create_user("gerardo", "$argon2id$A", hash_token("token-antiguo"))
    assert store.get_by_token_hash(hash_token("token-antiguo"))["username"] == "gerardo"

    store.update_user_token(uid, hash_token("token-nuevo"))
    assert store.get_by_token_hash(hash_token("token-antiguo")) is None
    assert store.get_by_token_hash(hash_token("token-nuevo"))["username"] == "gerardo"


def test_update_user_token_collision(store):
    u1 = store.create_user("u1", "$hash$1", hash_token("tok-1"))
    store.create_user("u2", "$hash$2", hash_token("tok-2"))

    with pytest.raises(TokenCollisionError):
        store.update_user_token(u1, hash_token("tok-2"))
