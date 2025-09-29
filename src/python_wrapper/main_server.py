import cffi
import time
import os 
import json

ffibuilder = cffi.FFI()
ffibuilder.cdef("""
    struct MHD_Daemon;
    struct MHD_Connection;

    typedef struct {
        char* buffer;
        size_t len;
    } BytesBuffer;

    BytesBuffer encrypt_message(const unsigned char* message, size_t message_len, const unsigned char* key);

    BytesBuffer decrypt_message(const unsigned char* full_payload, size_t payload_len, const unsigned char* key);

    void free_buffer(BytesBuffer buffer);
    size_t get_key_bytes(void);

    typedef int (*request_handler_callback)(void *cls, struct MHD_Connection *connection,
                                            const char *url, const char *method,
                                            const char *post_data,
                                            size_t post_data_size);

    struct MHD_Daemon* start_server(unsigned int port, request_handler_callback handler, void* cls);
    void stop_server(struct MHD_Daemon* daemon);

    int send_text_response(struct MHD_Connection *connection, const char *body, unsigned int status_code);
    int send_binary_response(struct MHD_Connection *connection, const char *body, size_t body_len, const char *content_type,
                            unsigned int status_code);
""")

try:
    C = ffibuilder.dlopen('./src/python_wrapper/libterminus_core.so')
except OSError as e:
    print(f"Error: No se pudo cargar la biblioteca 'libterminus_core.so'.\n{e}")
    print("Asegúrate de haber compilado el proyecto con 'bash scripts/build.sh'")
    exit(1)


def is_filename_safe(filename):
    return ".." not in filename and "/" not in filename

STORAGE_DIR = "terminus_storage"
KEY_FILE = os.path.join(STORAGE_DIR, ".secret_key")

def keyapp():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key_bytes = f.read()
            print("Clave secreta cargada desde archivo")
    else:
        print("No se encontro clave secreta. Gerando una nueva")
        key_bytes = os.urandom(C.get_key_bytes())
        with open(KEY_FILE, "wb") as f:
            f.write(key_bytes)
        print(f"Nueva clave secreta guardada en '{KEY_FILE}'. ¡No perder!")

    return key_bytes

def setup_storage():
    print(f"Aegurando que el directorio de almacenamiento '{STORAGE_DIR}' existe")
    os.makedirs(STORAGE_DIR, exist_ok=True)
    
    gitignore_path = os.path.join(STORAGE_DIR, ".gitignore")
    if not os.path.exists(gitignore_path):
        print(f"Creando archivos .gitignore en '{STORAGE_DIR}")
        with open(gitignore_path, "w") as f:
            f.write("*\n")
            f.write("!.gitignore\n")

key_bytes = keyapp()
setup_storage()

@ffibuilder.callback("int(void*, struct MHD_Connection*, const char*, const char*, const char*, size_t)")
def python_request_handler(cls, connection, url, method, post_data, post_data_size):
    method = ffibuilder.string(method)
    url = ffibuilder.string(url)

    print(f"\n [API] Petición recibida: {method.decode()} {url.decode()} con {post_data_size} bytes de datos.")

    if method == b"POST" and url == b"/encrypt":
        if post_data_size > 0:
            data_to_encrypt = ffibuilder.unpack(post_data, post_data_size);
            encrypted_buffer = C.encrypt_message(data_to_encrypt, len(data_to_encrypt), app_key)
            encrypted_hex = ffibuilder.unpack(encrypted_buffer.buffer, encrypted_buffer.len).hex()
            C.free_buffer(encrypted_buffer)
            return C.send_text_response(connection, encrypted_hex.encode('utf-8'), 200)
        else:
            return C.send_text_response(connection, b"Endpoint no encontrado.", 404)
    
    elif method == b"GET" and url == b"/files":
        if os.path.exists(STORAGE_DIR) and os.path.isdir(STORAGE_DIR):
            files = os.listdir(STORAGE_DIR)
            filtered_files = [f for f in files if not f.startswith('.')]
            json_response = json.dumps(filtered_files)
            return C.send_binary_response(connection, json_response.encode('utf-8'), len(json_response), b"application/json", 200)
        else:
            return C.send_binary_response(connection, b"[]", len(b"[]"), b"application/json", 200)
    

    elif url.startswith(b"/files/"):
        filename_bytes = url.split(b"/")[-1]
        filename_str = filename_bytes.decode('utf-8')

        if filename_str.startswith('.'):
            error_msg = b"Acceso a archivos de sistema no permitido"
            return C.send_text_response(connection, error_msg, 403)
        
        if not is_filename_safe(filename_str):
            error_msg = b"Nombre de archivo invalido"  
            return C.send_text_response(connection, error_msg, 400)
        file_path = os.path.join(STORAGE_DIR, filename_str)

        # ENDPOINT de Subida
        if method == b"POST":
            if post_data_size > 0:
                data_to_encrypt = ffibuilder.unpack(post_data, post_data_size)

                encrypted_buffer = C.encrypt_message(data_to_encrypt, len(data_to_encrypt), app_key)
                encrypted_data = ffibuilder.unpack(encrypted_buffer.buffer, encrypted_buffer.len)
                C.free_buffer(encrypted_buffer)
            
                file_path = os.path.join(STORAGE_DIR, filename_str)
                try:
                    with open(file_path, "wb") as f:
                        f.write(encrypted_data)
                    success_msg = f"Archivo '{filename_str}' guardado y cifrado".encode('utf-8')
                    return C.send_text_response(connection, success_msg, 201)
                except IOError as e:
                    error_msg = f"Error al escribir el archivo: {e}".encode('utf-8')
                    return C.send_text_response(connection, error_msg, 500)
            else:
                return C.send_text_response(connection, b"Cuerpo dela peticion vacio", 400)

        #ENDPOINT de Descarga
        elif method == b"GET":
            file_path = os.path.join(STORAGE_DIR, filename_str)
            if not os.path.exists(file_path):
                error_msg = b"Archivo no encontrado"
                return C.send_text_response(connection, error_msg, 404)

            try:
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
            except IOError as e:
                error_msg = f"Error al leer el archivo: {e}".encode('utf-8')
                return C.send_text_response(connection, error_msg, 500)
            
            decrypted_buffer = C.decrypt_message(encrypted_data, len(encrypted_data), app_key)
            
            if decrypted_buffer.buffer == ffibuilder.NULL:
                error_msg = b"Fallo al decifrar el archivo"
                return C.send_text_response(connection, error_msg, 500)
            
            decrypted_data = ffibuilder.unpack(decrypted_buffer.buffer, decrypted_buffer.len)
            C.free_buffer(decrypted_buffer)

            return C.send_binary_response(connection, decrypted_data, len(decrypted_data), b"application/octet-stream", 200) 
        
        #ENDPOINT de ELiminacion
        elif method == b"DELETE":
            file_path = os.path.join(STORAGE_DIR, filename_str)
            if not os.path.exists(file_path):
                error_msg = b"Archivo no encontrado"
                return C.send_text_response(connection, error_msg, 404)

            try:
                os.remove(file_path)
                success_msg = f"Archivo {filename_str} borrado exitosamente".encode('utf-8')
                return C.send_text_response(connection, success_msg, 200)
            except OSError as e:
                error_msg = f"Error al borrar el archivo: {e}".encode('utf-8')
                return C.send_text_response(connection, error_msg, 500)
    
    return C.send_text_response(connection, b"404 Not Found", 404)

PORT = 8080
mhd_daemon = ffibuilder.NULL
app_key = ffibuilder.new("unsigned char[]", key_bytes)

def main():

    global mhd_daemon 
    
    print(f"Clave de sesion generada: {bytes(app_key).hex()}")

    while True:
        print("\nPanel de Control del Servidor")

        if mhd_daemon == ffibuilder.NULL:
            print("  [start]  - Iniciar el servidor API")
        else:
            print("  [stop]   - Detener el servidor")

        print("  [status] - Ver estado actual")
        print("  [exit]   - Salir")
        
        command = input("> ").strip().lower()

        if command == "start":
            if mhd_daemon == ffibuilder.NULL:
                print("Iniciando servidor con el manejador de API de python")
                mhd_daemon = C.start_server(PORT, python_request_handler, ffibuilder.NULL)
                if mhd_daemon == ffibuilder.NULL:
                    print("ERROR: El núcleo en C falló al iniciar el servidor.")
            else:
                print("AVISO: El servidor ya está en funcionamiento.")
        
        elif command == "stop":
            if mhd_daemon != ffibuilder.NULL:
                C.stop_server(mhd_daemon)
                mhd_daemon = ffibuilder.NULL
            else:
                print("AVISO: El servidor ya está detenido.")

        elif command == "status":
            if mhd_daemon == ffibuilder.NULL:
                print("Estado: Detenido")
            else:
                print(f"Estado: Funcionando en el puerto {PORT}")
        
        elif command == "exit":
            if mhd_daemon != ffibuilder.NULL:
                print("Deteniendo el servidor antes de salir...")
                C.stop_server(mhd_daemon)
                mhd_daemon = ffibuilder.NULL
            print("Saliendo del panel de control.")
            break
        
        else:
            print(f"Comando desconocido: '{command}'")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupción detectada. Saliendo...")
    finally:
        if mhd_daemon and mhd_daemon != ffibuilder.NULL:
            C.stop_server(mhd_daemon)
