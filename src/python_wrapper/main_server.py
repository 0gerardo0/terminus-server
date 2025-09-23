import cffi
import time

ffibuilder = cffi.FFI()
ffibuilder.cdef("""
    struct MHD_Daemon;
    struct MHD_Daemon* start_server(unsigned int port);
    void stop_server(struct MHD_Daemon* daemon);
""")

try:
    C = ffibuilder.dlopen('./src/python_wrapper/libserver_core.so')
except OSError as e:
    print(f"Error: No se pudo cargar la biblioteca 'libserver_core.so'.\n{e}")
    print("Asegúrate de haber compilado el proyecto con 'bash scripts/build.sh'")
    exit(1)

PORT = 8080
mhd_daemon = ffibuilder.NULL

def main():
    """Función principal que contiene el bucle interactivo."""
    global mhd_daemon 
    while True:
        print("\n--- Panel de Control del Servidor ---")

        if mhd_daemon == ffibuilder.NULL:
            print("  [start]  - Iniciar el servidor")
        else:
            print("  [stop]   - Detener el servidor")
            print(f"  (Puedes probarlo con: curl http://127.0.0.1:{PORT})")

        print("  [status] - Ver estado actual")
        print("  [exit]   - Salir")
        
        command = input("> ").strip().lower()

        if command == "start":
            if mhd_daemon == ffibuilder.NULL:
                mhd_daemon = C.start_server(PORT)
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
