import cffi
import time
import os 

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

""")

try:
    C = ffibuilder.dlopen('./src/python_wrapper/libterminus_core.so')
except OSError as e:
    print(f"Error: No se pudo cargar la biblioteca 'libterminus_core.so'.\n{e}")
    print("Asegúrate de haber compilado el proyecto con 'bash scripts/build.sh'")
    exit(1)

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
    print("DEBUG: La condición "if" falló. Devolviendo 404.")
    return C.send_text_response(connection, b"404 Not Found", 404)

PORT = 8080
mhd_daemon = ffibuilder.NULL
app_key = ffibuilder.new("unsigned char[]", os.urandom(C.get_key_bytes()))

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
