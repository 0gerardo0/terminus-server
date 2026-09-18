import os
import random
import string
import time
import pytest
import requests

import main_server
from main_server import C, python_request_handler, STORAGE_DIR, API_TOKEN


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


def register_user(base_url):
    username = f"usr_{random_string(8)}"
    password = "password123"
    resp = requests.post(
        f"{base_url}/auth/register",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 201
    data = resp.json()
    return {
        "user_id": data["user_id"],
        "username": data["username"],
        "token": data["token"],
        "headers": {"Authorization": f"Bearer {data['token']}"},
    }


def test_user_storage_isolation_listing(live_server):
    user_a = register_user(live_server)
    user_b = register_user(live_server)

    filename = f"file_{random_string(6)}.txt"
    content = b"Contenido privado de Usuario A"

    # Usuario A sube archivo
    resp = requests.post(f"{live_server}/files/{filename}", data=content, headers=user_a["headers"])
    assert resp.status_code == 201

    # Usuario B consulta /files -> NO debe ver el archivo de Usuario A
    resp_b = requests.get(f"{live_server}/files", headers=user_b["headers"])
    assert resp_b.status_code == 200
    files_b = resp_b.json()
    assert filename not in files_b

    # Usuario A consulta /files -> SÍ debe ver su archivo
    resp_a = requests.get(f"{live_server}/files", headers=user_a["headers"])
    assert resp_a.status_code == 200
    files_a = resp_a.json()
    assert filename in files_a


def test_cross_user_file_access_blocked(live_server):
    user_a = register_user(live_server)
    user_b = register_user(live_server)

    filename = f"secret_{random_string(6)}.txt"
    content = b"Informacion ultra secreta"

    # Usuario A sube archivo
    resp = requests.post(f"{live_server}/files/{filename}", data=content, headers=user_a["headers"])
    assert resp.status_code == 201

    # Usuario B intenta descargar archivo de Usuario A -> 404
    resp_get = requests.get(f"{live_server}/files/{filename}", headers=user_b["headers"])
    assert resp_get.status_code == 404
    assert resp_get.json()["code"] == "FILE_NOT_FOUND"

    # Usuario B intenta ver info del archivo de Usuario A -> 404
    resp_info = requests.get(f"{live_server}/files/{filename}/info", headers=user_b["headers"])
    assert resp_info.status_code == 404
    assert resp_info.json()["code"] == "FILE_NOT_FOUND"

    # Usuario B intenta borrar archivo de Usuario A -> 404
    resp_del = requests.delete(f"{live_server}/files/{filename}", headers=user_b["headers"])
    assert resp_del.status_code == 404
    assert resp_del.json()["code"] == "FILE_NOT_FOUND"

    # Archivo de Usuario A sigue intacto
    resp_check = requests.get(f"{live_server}/files/{filename}", headers=user_a["headers"])
    assert resp_check.status_code == 200
    assert resp_check.content == content


def test_same_filename_distinct_users(live_server):
    user_a = register_user(live_server)
    user_b = register_user(live_server)

    shared_name = f"comun_{random_string(6)}.txt"
    content_a = b"Contenido unico de A"
    content_b = b"Contenido unico de B completamente diferente"

    # Ambos suben con el mismo nombre
    resp_a = requests.post(f"{live_server}/files/{shared_name}", data=content_a, headers=user_a["headers"])
    assert resp_a.status_code == 201

    resp_b = requests.post(f"{live_server}/files/{shared_name}", data=content_b, headers=user_b["headers"])
    assert resp_b.status_code == 201

    # Cada uno recupera su contenido
    get_a = requests.get(f"{live_server}/files/{shared_name}", headers=user_a["headers"])
    assert get_a.status_code == 200
    assert get_a.content == content_a

    get_b = requests.get(f"{live_server}/files/{shared_name}", headers=user_b["headers"])
    assert get_b.status_code == 200
    assert get_b.content == content_b

    # Usuario A borra su archivo
    del_a = requests.delete(f"{live_server}/files/{shared_name}", headers=user_a["headers"])
    assert del_a.status_code == 200

    # Usuario A ya no lo tiene
    assert requests.get(f"{live_server}/files/{shared_name}", headers=user_a["headers"]).status_code == 404

    # Usuario B todavía lo tiene con su contenido original
    get_b2 = requests.get(f"{live_server}/files/{shared_name}", headers=user_b["headers"])
    assert get_b2.status_code == 200
    assert get_b2.content == content_b


@pytest.mark.parametrize(
    "malicious_filename",
    [
        "..%2Fsecret.txt",
        "../secret.txt",
        "..\\secret.txt",
        ".hidden_file",
        "nested/sub/file.txt",
        "file\x00inject.txt",
        "   ",
        "archivo con espacios.txt",
        "archivo;cmd.txt",
    ],
)
def test_path_traversal_attempts_blocked(live_server, malicious_filename):
    user = register_user(live_server)

    # Subida
    resp_post = requests.post(
        f"{live_server}/files/{malicious_filename}",
        data=b"intruso",
        headers=user["headers"],
    )
    assert resp_post.status_code in [400, 403, 404]
    if resp_post.headers.get("content-type") == "application/json":
        assert resp_post.json()["code"] in ["INVALID_FILENAME", "INVALID_PATH", "FORBIDDEN_FILE", "ENDPOINT_NOT_FOUND"]

    # Descarga
    resp_get = requests.get(
        f"{live_server}/files/{malicious_filename}",
        headers=user["headers"],
    )
    assert resp_get.status_code in [400, 403, 404]
    if resp_get.headers.get("content-type") == "application/json":
        assert resp_get.json()["code"] in ["INVALID_FILENAME", "INVALID_PATH", "FORBIDDEN_FILE", "ENDPOINT_NOT_FOUND"]


def test_system_reserved_files_blocked(live_server):
    user = register_user(live_server)

    for reserved in ["config.json", "terminus.db", "client_config.json"]:
        resp = requests.get(f"{live_server}/files/{reserved}", headers=user["headers"])
        assert resp.status_code in [400, 403]
        assert resp.json()["code"] in ["INVALID_FILENAME", "FORBIDDEN_FILE"]


def test_physical_disk_partitioning(live_server):
    user = register_user(live_server)
    uid = user["user_id"]
    filename = f"disktest_{random_string(6)}.txt"

    resp = requests.post(f"{live_server}/files/{filename}", data=b"en_disco", headers=user["headers"])
    assert resp.status_code == 201

    expected_user_file = os.path.join(STORAGE_DIR, f"u_{uid}", filename)
    unexpected_root_file = os.path.join(STORAGE_DIR, filename)

    assert os.path.isfile(expected_user_file), f"El archivo debe existir en {expected_user_file}"
    assert not os.path.exists(unexpected_root_file), f"El archivo NO debe existir en la raíz {unexpected_root_file}"


def test_legacy_admin_operates_in_u_0(live_server):
    admin_headers = {"Authorization": f"Bearer {API_TOKEN}"}
    admin_filename = f"admin_{random_string(6)}.txt"
    admin_content = b"Documento administrativo raiz"

    # Admin sube archivo
    resp = requests.post(f"{live_server}/files/{admin_filename}", data=admin_content, headers=admin_headers)
    assert resp.status_code == 201

    # Físicamente debe guardarse en u_0/
    admin_path_disk = os.path.join(STORAGE_DIR, "u_0", admin_filename)
    assert os.path.isfile(admin_path_disk)

    # Admin puede listarlo y descargarlo
    list_resp = requests.get(f"{live_server}/files", headers=admin_headers)
    assert list_resp.status_code == 200
    assert admin_filename in list_resp.json()

    get_resp = requests.get(f"{live_server}/files/{admin_filename}", headers=admin_headers)
    assert get_resp.status_code == 200
    assert get_resp.content == admin_content

    # Usuario regular NO puede verlo en su lista ni descargarlo
    user = register_user(live_server)
    user_list = requests.get(f"{live_server}/files", headers=user["headers"]).json()
    assert admin_filename not in user_list

    user_get = requests.get(f"{live_server}/files/{admin_filename}", headers=user["headers"])
    assert user_get.status_code == 404


def test_file_named_info_lifecycle(live_server):
    user = register_user(live_server)
    content = b"Contenido de un archivo que se llama info literalmente"

    # 1. Subir archivo llamado 'info'
    upload_resp = requests.post(f"{live_server}/files/info", data=content, headers=user["headers"])
    assert upload_resp.status_code == 201

    # 2. Obtener metadatos con GET /files/info/info
    info_resp = requests.get(f"{live_server}/files/info/info", headers=user["headers"])
    assert info_resp.status_code == 200
    meta = info_resp.json()
    assert meta["filename"] == "info"
    assert meta["size_bytes"] > 0
    assert "modified_at" in meta

    # 3. Descargar el archivo con GET /files/info
    get_resp = requests.get(f"{live_server}/files/info", headers=user["headers"])
    assert get_resp.status_code == 200
    assert get_resp.content == content

    # 4. Borrar archivo
    del_resp = requests.delete(f"{live_server}/files/info", headers=user["headers"])
    assert del_resp.status_code == 200

    # 5. Confirmar 404 tras borrado
    assert requests.get(f"{live_server}/files/info", headers=user["headers"]).status_code == 404


def test_file_info_owner_success(live_server):
    user = register_user(live_server)
    filename = f"meta_{random_string(6)}.txt"
    content = b"Metadatos de prueba"

    post_resp = requests.post(f"{live_server}/files/{filename}", data=content, headers=user["headers"])
    assert post_resp.status_code == 201

    info_resp = requests.get(f"{live_server}/files/{filename}/info", headers=user["headers"])
    assert info_resp.status_code == 200
    data = info_resp.json()
    assert data["filename"] == filename
    assert data["size_bytes"] > len(content)  # Cifrado añade nonce y MAC
    assert "modified_at" in data


def test_symlink_rejection(live_server, tmp_path):
    user = register_user(live_server)
    uid = user["user_id"]
    user_dir = os.path.join(STORAGE_DIR, f"u_{uid}")
    os.makedirs(user_dir, exist_ok=True)

    # Crear symlink dentro de la carpeta del usuario apuntando fuera
    target_file = tmp_path / "target_secret.txt"
    target_file.write_text("sensible")

    symlink_name = "symlink_test.txt"
    symlink_path = os.path.join(user_dir, symlink_name)
    try:
        os.symlink(str(target_file), symlink_path)

        # GET /files no debe listar el symlink
        list_resp = requests.get(f"{live_server}/files", headers=user["headers"])
        assert list_resp.status_code == 200
        assert symlink_name not in list_resp.json()

        # GET /files/<symlink> debe ser rechazado con 403
        get_resp = requests.get(f"{live_server}/files/{symlink_name}", headers=user["headers"])
        assert get_resp.status_code == 403
        assert get_resp.json()["code"] == "SYMLINK_FORBIDDEN"
    finally:
        if os.path.islink(symlink_path):
            os.unlink(symlink_path)

