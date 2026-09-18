import json
import random
import string
import time
import pytest
import requests

import main_server
from main_server import C, python_request_handler


def random_string(length=8):
    return "".join(random.choices(string.ascii_lowercase, k=length))


@pytest.fixture(scope="module")
def live_server():
    port = random.randint(20000, 45000)
    daemon = C.start_server(port, python_request_handler)
    assert daemon != main_server.ffibuilder.NULL
    time.sleep(0.15)
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    C.stop_server(daemon)


def test_status_endpoint_is_public(live_server):
    # GET /status no debe requerir token Bearer
    resp = requests.get(f"{live_server}/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_register_success(live_server):
    username = f"user_{random_string(6)}"
    password = "password123"

    resp = requests.post(
        f"{live_server}/auth/register",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "ok"
    assert data["username"] == username
    assert "token" in data
    assert len(data["token"]) >= 32
    assert "user_id" in data


def test_register_duplicate_username_fails(live_server):
    username = f"user_{random_string(6)}"
    password = "password123"

    # Primer registro exitoso
    resp1 = requests.post(
        f"{live_server}/auth/register",
        json={"username": username, "password": password},
    )
    assert resp1.status_code == 201

    # Segundo registro con el mismo username -> 409 Conflict
    resp2 = requests.post(
        f"{live_server}/auth/register",
        json={"username": username, "password": password},
    )
    assert resp2.status_code == 409
    assert resp2.json()["code"] == "USER_EXISTS"


def test_register_invalid_inputs(live_server):
    # Contraseña muy corta (< 8)
    resp = requests.post(
        f"{live_server}/auth/register",
        json={"username": "valid_user", "password": "123"},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "VALIDATION_ERROR"

    # Username con path traversal o caracteres no permitidos
    resp = requests.post(
        f"{live_server}/auth/register",
        json={"username": "../hacker", "password": "password123"},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "VALIDATION_ERROR"

    # JSON malformado o vacío
    resp = requests.post(
        f"{live_server}/auth/register",
        data="not a json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_login_success(live_server):
    username = f"user_{random_string(6)}"
    password = "password123"

    # 1. Registrar usuario
    reg_resp = requests.post(
        f"{live_server}/auth/register",
        json={"username": username, "password": password},
    )
    assert reg_resp.status_code == 201
    initial_token = reg_resp.json()["token"]

    # 2. Login con credenciales correctas
    login_resp = requests.post(
        f"{live_server}/auth/login",
        json={"username": username, "password": password},
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["status"] == "ok"
    assert login_data["username"] == username
    assert "token" in login_data

    new_token = login_data["token"]
    # El token debe haberse rotado
    assert new_token != initial_token

    # 3. El nuevo token funciona para acceder a endpoints protegidos
    files_resp = requests.get(
        f"{live_server}/files",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert files_resp.status_code == 200

    # 4. El token anterior ya no es válido tras la rotación
    old_files_resp = requests.get(
        f"{live_server}/files",
        headers={"Authorization": f"Bearer {initial_token}"},
    )
    assert old_files_resp.status_code == 401


def test_login_invalid_credentials(live_server):
    username = f"user_{random_string(6)}"
    password = "correct_password_123"

    requests.post(
        f"{live_server}/auth/register",
        json={"username": username, "password": password},
    )

    # Contraseña incorrecta
    resp1 = requests.post(
        f"{live_server}/auth/login",
        json={"username": username, "password": "wrong_password"},
    )
    assert resp1.status_code == 401
    assert resp1.json()["code"] == "INVALID_CREDENTIALS"

    # Usuario inexistente
    resp2 = requests.post(
        f"{live_server}/auth/login",
        json={"username": "user_inexistente_999", "password": password},
    )
    assert resp2.status_code == 401
    assert resp2.json()["code"] == "INVALID_CREDENTIALS"


def test_legacy_admin_token_still_works(live_server):
    # El API_TOKEN configurado en config.json debe seguir funcionando
    legacy_token = main_server.API_TOKEN
    resp = requests.get(
        f"{live_server}/files",
        headers={"Authorization": f"Bearer {legacy_token}"},
    )
    assert resp.status_code == 200


def test_payload_too_large_rejected(live_server):
    huge_data = json.dumps({"username": "user", "password": "x" * 5000})
    resp = requests.post(
        f"{live_server}/auth/register",
        data=huge_data.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json()["code"] == "PAYLOAD_TOO_LARGE"


def test_json_non_dict_rejected(live_server):
    resp = requests.post(
        f"{live_server}/auth/register",
        data=b"[1, 2, 3]",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "INVALID_JSON"


def test_malformed_auth_headers_rejected(live_server):
    # Sin prefijo Bearer
    resp = requests.get(
        f"{live_server}/files",
        headers={"Authorization": "Basic somecredentials"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "TOKEN_INVALID"

    # Solo la palabra Bearer sin token
    resp = requests.get(
        f"{live_server}/files",
        headers={"Authorization": "Bearer"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "TOKEN_INVALID"
