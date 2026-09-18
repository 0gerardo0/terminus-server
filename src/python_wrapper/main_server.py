import cffi
import os 
from pathlib import Path
import shutil
import re
import json
import time
import logging
from config import load_config
from datetime import datetime
import secrets
from db import (
    UserStore,
    UsernameTakenError,
    TokenCollisionError,
    InvalidUsernameError,
    InvalidPasswordError,
    validate_username,
    validate_password,
    hash_token,
)

config = load_config()
PORT = config["server_port"]
STORAGE_DIR = config["storage_directory"]
API_TOKEN = config["api_secret_token"]
DB_PATH = config.get("database_path", "terminus.db")
user_store = UserStore(DB_PATH)

LOG_LEVEL = config.get("log_level", "INFO").upper()
LOG_FILE = config.get("log_file", "terminus.log")

KEY_FILE = os.path.join(STORAGE_DIR, ".secret_key")

APP_VERSION = "1.1.0-docker"


logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE),
              logging.StreamHandler()]
)

def api_error(connection, message, status_code, error_code=None):
    if 400 <= status_code < 500:
        logging.warning(f"Error de cliente ({status_code}): {message}")
    else:
        logging.error(f"Error de servidor ({status_code}): {message}")

    response_dict = {"error": message}
    if error_code:
        response_dict["code"] = error_code
    
    json_response = json.dumps(response_dict)
    
    return C.send_binary_response(connection, 
                                  json_response.encode('utf-8'),
                                  len(json_response),
                                  b"application/json; charset=utf-8",
                                  status_code)

ffibuilder = cffi.FFI()
ffibuilder.cdef("""
    struct MHD_Daemon;
    struct MHD_Connection;
    typedef struct {
        char* buffer;
        size_t len;
    } BytesBuffer;

    enum MHD_ValueKind {
      MHD_HEADER_KIND = 0
    };

    const char *MHD_lookup_connection_value(struct MHD_Connection *connection,
                                            enum MHD_ValueKind kind,
                                            const char *key);

    BytesBuffer encrypt_message(const unsigned char* message, size_t message_len,
                                  const unsigned char* key);
    BytesBuffer decrypt_message(const unsigned char* full_payload, size_t payload_len,
                                  const unsigned char* key);
    void free_buffer(BytesBuffer buffer);
    size_t get_key_bytes(void);

    typedef int (*request_handler_callback)(
        void *cls,
        struct MHD_Connection *connection,
        const char *url,
        const char *method,
        const char *post_data,
        size_t post_data_size,
        const char *auth_header
    );

    struct MHD_Daemon* start_server(unsigned int port, request_handler_callback handler);
    void stop_server(struct MHD_Daemon* daemon);
    int send_text_response(struct MHD_Connection *connection, const char *body,
                           unsigned int status_code);
    int send_binary_response(struct MHD_Connection *connection, const char *body,
                             size_t body_len, const char *content_type,
                             unsigned int status_code);
    
    BytesBuffer hash_password(const char* password, size_t password_len);
    int verify_password(const char* stored_hash, const char* password, size_t password_len);
""")

try:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    _PROJECT_ROOT =  os.path.dirname(os.path.dirname(_SCRIPT_DIR))
    _LIB_PATH = os.path.join(_PROJECT_ROOT, "build", "libterminus_core.so")
except NameError:
    _LIB_PATH = '.build/libterminus_core.so'


try:
    C = ffibuilder.dlopen(_LIB_PATH)
except OSError as e:
    logging.critical(f"No se pudo cargar la biblioteca 'libterminus_core.so'. El servidor no se puede iniciar. Error: {e}")
    logging.critical("Asegúrate de haber compilado el proyecto con 'bash scripts/build.sh'")
    exit(1)


def hash_password_c(password: str) -> str:
    pw_bytes = password.encode("utf-8")
    buf = C.hash_password(pw_bytes, len(pw_bytes))
    if buf.buffer == ffibuilder.NULL:
        raise RuntimeError("Error al generar hash de contraseña con Argon2id")
    try:
        return ffibuilder.unpack(buf.buffer, buf.len).decode("utf-8")
    finally:
        C.free_buffer(buf)


def verify_password_c(stored_hash: str, password: str) -> bool:
    pw_bytes = password.encode("utf-8")
    hash_bytes = stored_hash.encode("utf-8")
    return C.verify_password(hash_bytes, pw_bytes, len(pw_bytes)) == 0


SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$")
SYSTEM_RESERVED_NAMES = frozenset({
    ".secret_key",
    ".gitignore",
    "config.json",
    "client_config.json",
    "terminus.db",
    "terminus.log",
})


def get_user_storage_dir(user_id: int) -> Path:
    return (Path(STORAGE_DIR).resolve() / f"u_{user_id}").resolve()


def resolve_user_file_path(user_id: int, filename: str) -> tuple[Path | None, tuple[str, int, str] | None]:
    if not isinstance(filename, str) or not filename.strip() or "\x00" in filename:
        return None, ("Nombre de archivo invalido.", 400, "INVALID_FILENAME")

    if not SAFE_FILENAME_REGEX.fullmatch(filename):
        return None, ("Nombre de archivo invalido. Debe comenzar con caracter alfanumerico y no contener rutas relativas.", 400, "INVALID_FILENAME")

    if filename.lower() in SYSTEM_RESERVED_NAMES:
        return None, ("Acceso denegado a archivo reservado del sistema.", 403, "FORBIDDEN_FILE")

    user_dir = get_user_storage_dir(user_id)
    if os.path.islink(user_dir / filename):
        return None, ("No se permiten enlaces simbolicos.", 403, "SYMLINK_FORBIDDEN")

    try:
        resolved = (user_dir / filename).resolve(strict=False)
    except Exception:
        return None, ("Ruta no valida.", 400, "INVALID_PATH")

    if not resolved.is_relative_to(user_dir) or resolved == user_dir:
        return None, ("Intento de escape de directorio detectado.", 400, "INVALID_PATH")

    if resolved.is_symlink():
        return None, ("No se permiten enlaces simbolicos.", 403, "SYMLINK_FORBIDDEN")

    return resolved, None


def setup_storage():
    logging.info(f"Asegurando que el directorio de almacenamiento '{STORAGE_DIR}' existe")
    os.makedirs(STORAGE_DIR, exist_ok=True)
    
    gitignore_path = os.path.join(STORAGE_DIR, ".gitignore")
    if not os.path.exists(gitignore_path):
        logging.info(f"Creando archivos .gitignore en '{STORAGE_DIR}' para proteger los archivos")
        with open(gitignore_path, "w") as f:
            f.write("*\n")
            f.write("!.gitignore\n")

    legacy_dir = os.path.join(STORAGE_DIR, "u_0")
    os.makedirs(legacy_dir, exist_ok=True)

    try:
        for item in os.listdir(STORAGE_DIR):
            if item.startswith("."):
                continue
            src = os.path.join(STORAGE_DIR, item)
            if os.path.isdir(src) and (item == "u_0" or (item.startswith("u_") and item[2:].isdigit())):
                continue
            if os.path.isfile(src) and not os.path.islink(src):
                dst = os.path.join(legacy_dir, item)
                if not os.path.exists(dst):
                    shutil.move(src, dst)
                    logging.info(f"Migrado archivo legado '{item}' a '{legacy_dir}'")
    except Exception as e:
        logging.warning(f"Error al migrar archivos legados a u_0: {e}")
setup_storage()


def keyapp():
    os.makedirs(STORAGE_DIR, exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key_bytes = f.read()
            logging.info("Clave secreta cargada desde archivo existente.")
    else:
        logging.info("No se encontro clave secreta. Generando una nueva")
        key_bytes = os.urandom(C.get_key_bytes())
        with open(KEY_FILE, "wb") as f:
            f.write(key_bytes)
        logging.warning(f"Nueva clave secreta guardada en '{KEY_FILE}'. ¡Es crucial no perder este archivo!") 

    return key_bytes
key_bytes = keyapp()


@ffibuilder.callback("int(void*, struct MHD_Connection*, const char*, const char*, const char*, size_t, const char*)")
def python_request_handler(cls, connection, url, method, post_data, post_data_size, auth_header_ptr):
    
    url = ffibuilder.string(url)
    method = ffibuilder.string(method)

    # 1. Endpoint público: GET /status
    if method == b"GET" and url == b"/status":
        status_info = {
            "status": "ok",
            "version": APP_VERSION
        }
        json_response = json.dumps(status_info)
        return C.send_binary_response(connection, json_response.encode('utf-8'), len(json_response), b"application/json", 200)

    # 2. Endpoint público: POST /auth/register
    if method == b"POST" and url == b"/auth/register":
        if post_data_size <= 0:
            return api_error(connection, "Cuerpo de la petición vacío", 400, "EMPTY_BODY")
        if post_data_size > 4096:
            return api_error(connection, "Cuerpo de la petición excede el límite permitido", 413, "PAYLOAD_TOO_LARGE")

        try:
            raw_body = ffibuilder.unpack(post_data, post_data_size).decode('utf-8')
            payload = json.loads(raw_body)
        except Exception:
            return api_error(connection, "JSON malformado", 400, "INVALID_JSON")

        if not isinstance(payload, dict):
            return api_error(connection, "JSON debe ser un objeto", 400, "INVALID_JSON")

        username = payload.get("username")
        password = payload.get("password")

        try:
            validate_username(username)
            validate_password(password)
        except (InvalidUsernameError, InvalidPasswordError) as e:
            return api_error(connection, str(e), 400, "VALIDATION_ERROR")

        try:
            pw_hash = hash_password_c(password)
            token = secrets.token_urlsafe(32)
            token_hash = hash_token(token)
            user_id = user_store.create_user(username, pw_hash, token_hash)
        except UsernameTakenError:
            return api_error(connection, f"El usuario '{username}' ya existe", 409, "USER_EXISTS")
        except Exception as e:
            logging.error(f"Error al registrar usuario: {e}")
            return api_error(connection, "Error interno al crear usuario", 500, "INTERNAL_ERROR")

        resp = {
            "status": "ok",
            "user_id": user_id,
            "username": username,
            "token": token
        }
        json_resp = json.dumps(resp)
        return C.send_binary_response(connection, json_resp.encode('utf-8'), len(json_resp), b"application/json", 201)

    # 3. Endpoint público: POST /auth/login
    if method == b"POST" and url == b"/auth/login":
        if post_data_size <= 0:
            return api_error(connection, "Cuerpo de la petición vacío", 400, "EMPTY_BODY")
        if post_data_size > 4096:
            return api_error(connection, "Cuerpo de la petición excede el límite permitido", 413, "PAYLOAD_TOO_LARGE")

        try:
            raw_body = ffibuilder.unpack(post_data, post_data_size).decode('utf-8')
            payload = json.loads(raw_body)
        except Exception:
            return api_error(connection, "JSON malformado", 400, "INVALID_JSON")

        if not isinstance(payload, dict):
            return api_error(connection, "JSON debe ser un objeto", 400, "INVALID_JSON")

        username = payload.get("username")
        password = payload.get("password")

        if not username or not password or not isinstance(username, str) or not isinstance(password, str):
            return api_error(connection, "Credenciales invalidas", 401, "INVALID_CREDENTIALS")

        user = user_store.get_by_username(username)
        if not user:
            return api_error(connection, "Credenciales invalidas", 401, "INVALID_CREDENTIALS")

        if not verify_password_c(user["password_hash"], password):
            return api_error(connection, "Credenciales invalidas", 401, "INVALID_CREDENTIALS")

        try:
            new_token = secrets.token_urlsafe(32)
            user_store.update_user_token(user["id"], hash_token(new_token))
        except Exception as e:
            logging.error(f"Error al actualizar token de login: {e}")
            return api_error(connection, "Error interno al iniciar sesión", 500, "INTERNAL_ERROR")

        resp = {
            "status": "ok",
            "user_id": user["id"],
            "username": user["username"],
            "token": new_token
        }
        json_resp = json.dumps(resp)
        return C.send_binary_response(connection, json_resp.encode('utf-8'), len(json_resp), b"application/json", 200)

    # --- RUTAS PROTEGIDAS (Requieren Token Bearer) ---
    if not auth_header_ptr:
        return api_error(connection, "Se requiere autenticacion", 401, "AUTH_REQUIRED")

    auth_header = ffibuilder.string(auth_header_ptr).decode('utf-8')
    parts = auth_header.split()
    if len(parts) != 2 or parts[0] != "Bearer":
        return api_error(connection, "Token invalido o mal formado", 401, "TOKEN_INVALID")

    token_val = parts[1]
    authenticated_user = None

    user_row = user_store.get_by_token_hash(hash_token(token_val))
    if user_row:
        authenticated_user = user_row
    elif secrets.compare_digest(token_val, API_TOKEN):
        authenticated_user = {"id": 0, "username": "admin"}

    if not authenticated_user:
        return api_error(connection, "Token invalido o no autorizado", 401, "TOKEN_INVALID")

    user_id = authenticated_user["id"]
    logging.info(f"Petición AUTENTICADA (usuario '{authenticated_user['username']}'): {method.decode('utf-8')} {url.decode('utf-8')}")

    #if method == b"POST" and url == b"/encrypt":
    #    if post_data_size > 0:
    #        data_to_encrypt = ffibuilder.unpack(post_data, post_data_size);
    #        encrypted_buffer = C.encrypt_message(data_to_encrypt, len(data_to_encrypt), app_key)
    #        encrypted_hex = ffibuilder.unpack(encrypted_buffer.buffer, encrypted_buffer.len).hex()
    #        C.free_buffer(encrypted_buffer)
    #        return C.send_text_response(connection, encrypted_hex.encode('utf-8'), 200)
    #    else:
    #        return C.send_text_response(connection, b"Endpoint no encontrado.", 404)
    
    if method == b"GET" and url == b"/files":
        logging.info("Solicitud recibida para listar archivos en el directorio de almacenamiento")

        user_dir = get_user_storage_dir(user_id)
        if not user_dir.is_dir():
            return C.send_binary_response(connection, b"[]", 2, b"application/json", 200)

        with os.scandir(user_dir) as entries:
            filtered_files = [
                entry.name for entry in entries
                if not entry.name.startswith('.') and entry.is_file(follow_symlinks=False)
            ]
        json_response = json.dumps(filtered_files)

        logging.info(f"Se listaron {len(filtered_files)} archivos exitosamente para usuario {user_id}")
        return C.send_binary_response(connection, json_response.encode('utf-8'), len(json_response), b"application/json", 200)
    
    elif method == b"GET" and url.startswith(b"/files/") and url.endswith(b"/info") and url != b"/files/info":
        filename_raw = url[len(b"/files/"):-len(b"/info")]
        if not filename_raw:
            return api_error(connection, "URL malformado.", 400, "MALFORMED_URL")
        if b"/" in filename_raw:
            return api_error(connection, "Nombre de archivo invalido. No puede contener subdirectorios.", 400, "INVALID_FILENAME")
        try:
            filename_str = filename_raw.decode('utf-8')
        except UnicodeDecodeError:
            return api_error(connection, "URL malformado.", 400, "MALFORMED_URL")
        
        file_path, err = resolve_user_file_path(user_id, filename_str)
        if err:
            return api_error(connection, err[0], err[1], err[2])

        if not file_path.is_file():
            return api_error(connection, f"El archivo '{filename_str}', no fue encontrado.", 404, "FILE_NOT_FOUND")
        
        try:
            stats = os.stat(file_path)

            info = {
                "filename": filename_str,
                "size_bytes": stats.st_size,
                "modified_at": datetime.fromtimestamp(stats.st_mtime).isoformat()
            }
            json_response = json.dumps(info)

            return C.send_binary_response(connection, json_response.encode('utf-8'), len(json_response), b"application/json", 200)
        except OSError as e:
            return api_error(connection, f"Error interno al leer metadatos: {e}", 500, "STAT_ERROR")


    elif url.startswith(b"/files/"):
        subpath = url[len(b"/files/"):]
        if b"/" in subpath:
            return api_error(connection, "Nombre de archivo invalido. No puede contener subdirectorios.", 400, "INVALID_FILENAME")

        try:
            filename_str = subpath.decode('utf-8')
        except UnicodeDecodeError:
            return api_error(connection, "URL malformado.", 400, "MALFORMED_URL")

        file_path, err = resolve_user_file_path(user_id, filename_str)
        if err:
            return api_error(connection, err[0], err[1], err[2])

        # ENDPOINT de Subida
        if method == b"POST":
            if post_data_size > 0:

                logging.info(f"Iniciando subida y cifrado para el archivo: '{filename_str}'.")

                data_to_encrypt = ffibuilder.unpack(post_data, post_data_size)

                encrypted_buffer = C.encrypt_message(data_to_encrypt, len(data_to_encrypt), app_key)
                if encrypted_buffer.buffer == ffibuilder.NULL:
                    return api_error(connection, "Fallo interno al cifrar el archivo.", 500, "ENCRYPTION_FAILED")

                try:
                    encrypted_data = ffibuilder.unpack(encrypted_buffer.buffer, encrypted_buffer.len)
                finally:
                    C.free_buffer(encrypted_buffer)
            
                os.makedirs(file_path.parent, exist_ok=True)
                try:
                    with open(file_path, "wb") as f:
                        f.write(encrypted_data)
                    logging.info(f"Archivo '{filename_str}' guardado y cifrado exitosamente ({len(encrypted_data)} bytes).")
                    success_msg = f"Archivo '{filename_str}' guardado y cifrado"
                    return C.send_text_response(connection, success_msg.encode('utf-8'), 201)
                except IOError as e:
                    return api_error(connection, f"Error interno al escribir el archivo: {e}", 500, "FILE_WRITE_ERROR")
            else:
                return api_error(connection, "Cuerpo de la peticion vacio.", 400, "EMPTY_BODY")

        #ENDPOINT de Descarga
        elif method == b"GET":

            logging.info(f"Iniciando descarga y descifrando el archivo: '{filename_str}'")
            if not file_path.is_file():
                return api_error(connection, f"El archivo '{filename_str}' no fue encontrado.", 404, "FILE_NOT_FOUND")

            try:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
            except IOError as e:
                return api_error(connection, f"Error interno al leer el archivo: {e}", 500, "FILE_READ_ERROR")
            
            decrypted_buffer = C.decrypt_message(encrypted_data, len(encrypted_data), app_key)
            
            if decrypted_buffer.buffer == ffibuilder.NULL:
                return api_error(connection, "Fallo al descifrar el archivo. Puede estar corrupto o la clave cambió.", 500, "DECRYPTION_FAILED")
            
            decrypted_data = ffibuilder.unpack(decrypted_buffer.buffer, decrypted_buffer.len)
            C.free_buffer(decrypted_buffer)
            
            logging.info(f"Archivo '{filename_str}' descifrado y enviado exitosamente ({len(decrypted_data)} bytes)")
            return C.send_binary_response(connection, decrypted_data, len(decrypted_data), b"application/octet-stream", 200) 
        
        #ENDPOINT de Eliminacion
        elif method == b"DELETE":
            if not file_path.is_file():
                return api_error(connection, f"El archivo '{filename_str}' no fue encontrado.", 404, "FILE_NOT_FOUND")

            try:
                os.remove(file_path)
                success_msg = f"Archivo {filename_str} borrado exitosamente"
                logging.info(success_msg)
                return C.send_text_response(connection, success_msg.encode('utf-8'), 200)
            except OSError as e:
                return api_error(connection, f"Error interno al borrar el archivo: {e}", 500, "FILE_DELETE_ERROR")
        

    return api_error(connection, "Endpoint no encontrado.", 404, "ENDPOINT_NOT_FOUND")

mhd_daemon = ffibuilder.NULL
app_key = ffibuilder.new("unsigned char[]", key_bytes)

def main():
    global mhd_daemon 
    
    logging.info("Clave de cifrado inicializada correctamente.")

    mhd_daemon = C.start_server(PORT, python_request_handler)

    if mhd_daemon == ffibuilder.NULL:
        logging.critical("ERROR: El núcleo en C falló al iniciar el servidor.")
        return
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("\nInterrupción (Ctrl+C) detectada. Saliendo...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.error("\n Interrupción detectada. Deteniendo y saliendo del servidor.")
    finally:
        if mhd_daemon and mhd_daemon != ffibuilder.NULL:
            C.stop_server(mhd_daemon)
        user_store.close()
