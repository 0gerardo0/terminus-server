import cffi
import time
import os 
import json
import logging
from config import load_config

config = load_config()
PORT = config["server_port"]
STORAGE_DIR = config["storage_directory"]
API_TOKEN = config["api_secret_token"]

LOG_LEVEL = config.get("log_level", "INFO").upper()
LOG_FILE = config.get("log_file", "terminus.log")

KEY_FILE = os.path.join(STORAGE_DIR, ".secret_key")


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


def is_filename_safe(filename):
    return ".." not in filename and "/" not in filename


def keyapp():
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

def setup_storage():
    logging.info(f"Asegurando que el directorio de almacenamiento '{STORAGE_DIR}' existe")
    os.makedirs(STORAGE_DIR, exist_ok=True)
    
    gitignore_path = os.path.join(STORAGE_DIR, ".gitignore")
    if not os.path.exists(gitignore_path):
        logging.info(f"Creando archivos .gitignore en '{STORAGE_DIR}' para proteger los archivos")
        with open(gitignore_path, "w") as f:
            f.write("*\n")
            f.write("!.gitignore\n")
setup_storage()


@ffibuilder.callback("int(void*, struct MHD_Connection*, const char*, const char*, const char*, size_t, const char*)")
def python_request_handler(cls, connection, url, method, post_data, post_data_size, auth_header_ptr):
    
    url = ffibuilder.string(url)
    method = ffibuilder.string(method)

    if not auth_header_ptr:
        return api_error(connection, "Se requiere autenticacion", 401, "AUTH_REQUIRED")
    
    auth_header = ffibuilder.string(auth_header_ptr).decode('utf-8')
    logging.debug(f"AUTH_HEADER recibido: {repr(auth_header)}")
    logging.debug(f"API_TOKEN esperado: {repr(API_TOKEN)}")
    
    parts = auth_header.split()
    logging.debug(f"Partes del header de autenticación: {parts}")
    
    if len(parts) != 2 or parts[0] != "Bearer" or parts[1] != API_TOKEN:
        return api_error(connection, f"Token invalido o mal formado", 401, "TOKEN_INVALID")

    
    logging.info(f"Petición AUTENTICADA recibida: {method.decode("utf-8")} {url.decode("utf-8")}")

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

        if os.path.exists(STORAGE_DIR) and os.path.isdir(STORAGE_DIR):
            files = os.listdir(STORAGE_DIR)
            filtered_files = [f for f in files if not f.startswith('.')]
            json_response = json.dumps(filtered_files)

            logging.info(f"Se listaron {len(filtered_files)} archivos exitosamente")
            return C.send_binary_response(connection, json_response.encode('utf-8'), len(json_response), b"application/json", 200)
        else:
            return api_error(connection, "El directorio de almacenamiento no existe en el servidor", 500, "STORAGE_NOT_FOUND")
    

    elif url.startswith(b"/files/"):
        filename_bytes = url.split(b"/")[-1]
        filename_str = filename_bytes.decode('utf-8')

        if filename_str.startswith('.'):
            return api_error(connection, "Acceso a archivos de sistema no permitido", 403, "FORBIDDEN_FILENAME")

        if not is_filename_safe(filename_str):
            return api_error(connection, "Nombre de archivo invalido. No puede contener '..' o '/'.", 400, "INVALID_FILENAME")

        file_path = os.path.join(STORAGE_DIR, filename_str)

        # ENDPOINT de Subida
        if method == b"POST":
            if post_data_size > 0:

                logging.info(f"Iniciando subida y cifrado para el archivo: '{filename_str}'.")

                data_to_encrypt = ffibuilder.unpack(post_data, post_data_size)

                encrypted_buffer = C.encrypt_message(data_to_encrypt, len(data_to_encrypt), app_key)
                encrypted_data = ffibuilder.unpack(encrypted_buffer.buffer, encrypted_buffer.len)
                C.free_buffer(encrypted_buffer)
            
                file_path = os.path.join(STORAGE_DIR, filename_str)
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
            file_path = os.path.join(STORAGE_DIR, filename_str)
            if not os.path.exists(file_path):
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
            file_path = os.path.join(STORAGE_DIR, filename_str)
            if not os.path.exists(file_path):
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
    
    logging.info(f"Clave de sesion generada: {bytes(app_key).hex()}")
    logging.info("Server iniciado en el puerto 8080")

    mhd_daemon = C.start_server(PORT, python_request_handler)

    if mhd_daemon == ffibuilder.NULL:
        logging.error("Error al iniciar el servidor")
        return

    while True:
        print("\nPanel de Control del Servidor")

        #if mhd_daemon == ffibuilder.NULL:
        #    print("  [start]  - Iniciar el servidor API")
        #else:
        #    print("  [stop]   - Detener el servidor")

        print("  [status] - Ver estado actual")
        print("  [exit]   - Salir")
        
        command = input("> ").strip().lower()

        #if command == "start":
        #    if mhd_daemon == ffibuilder.NULL:
        #        print("Iniciando servidor con el manejador de API de python")
        #        mhd_daemon = C.start_server(PORT, python_request_handler, ffibuilder.NULL)
        #        if mhd_daemon == ffibuilder.NULL:
        #            print("ERROR: El núcleo en C falló al iniciar el servidor.")
        #    else:
        #        print("AVISO: El servidor ya está en funcionamiento.")
        
        #Aqui cambie el control para iniciar el server, provisional
        if command == "stop":
            if mhd_daemon != ffibuilder.NULL:
                C.stop_server(mhd_daemon)
                mhd_daemon = ffibuilder.NULL
            logging.info("Saliendo del panel de control. Servidor detenido")
            break
            #else:
            #    print("AVISO: El servidor ya está detenido.")

        elif command == "status":
            if mhd_daemon == ffibuilder.NULL:
                logging.info("Estatus del servidor: DETENIDO")
            else:
                logging.info(f"Estatus del servidor: Funcionando en el puerto: {PORT}")
        
        elif command == "exit":
            if mhd_daemon != ffibuilder.NULL:
                logging.info("Estatus del servidor: [EXIT] Servidor detenido")
                C.stop_server(mhd_daemon)
                mhd_daemon = ffibuilder.NULL
            logging.info("Saliendo del panel de control. Servidor detenido")
            break
        
        else:
            logging.info(f"Comando desconocido '{command}'")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.error("\n Interrupción detectada. Deteniendo y saliendo del servidor.")
    finally:
        if mhd_daemon and mhd_daemon != ffibuilder.NULL:
            C.stop_server(mhd_daemon)
