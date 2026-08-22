import pytest

from db import (
    UserStore,
    TokenCollisionError,
    UsernameTakenError,
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
