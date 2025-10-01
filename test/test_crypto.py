import cffi
import os
import time

ffibuilder = cffi.FFI()

ffibuilder.cdef("""
    typedef struct {
        char* buffer;
        size_t len;
    } BytesBuffer;
    

    BytesBuffer encrypt_message(const unsigned char* message, size_t message_len, const unsigned char* key);
    BytesBuffer decrypt_message(const unsigned char* full_payload, size_t payload_len, const unsigned char* key);
    void free_buffer(BytesBuffer buffer);
   
    size_t get_key_bytes(void); 
""")
try:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    _PROJECT_ROOT =  os.path.dirname(_SCRIPT_DIR)
    _LIB_PATH = os.path.join(_PROJECT_ROOT, "build", "libterminus_core.so")
except NameError:
    _LIB_PATH = '.build/libterminus_core.so'


C = ffibuilder.dlopen(_LIB_PATH)



plaintext = "------Mensaje secreto muy secreto secretoso----".encode('utf-8')

key_size = C.get_key_bytes()
key = os.urandom(key_size)

print(f"Texto original: {plaintext.decode('utf-8')}")
print(f"Clave (hex): {key.hex()}")
print("-" * 20)


start_time = time.perf_counter()
print(f"[PY-DEBUG] Llamando a C.encrypt_message con {len(plaintext)} bytes...")
encrypt_buffer = C.encrypt_message(plaintext, len(plaintext), key)
print(f"[PY-DEBUG] C devolvió un buffer de longitud {encrypt_buffer.len}")
end_time = time.perf_counter()

duration_ms = (end_time - start_time) * 1000
print(f"\nLa función en C 'encrypt_message' tardó: {duration_ms:.4f} ms")

encrypted_payload = ffibuilder.unpack(encrypt_buffer.buffer, encrypt_buffer.len)
print(f"Payload cifrado (hex); {encrypted_payload.hex()}")

C.free_buffer(encrypt_buffer)

decrypt_buffer = C.decrypt_message(encrypted_payload, len(encrypted_payload), key)

if decrypt_buffer.buffer == ffibuilder.NULL:
    print("\n Mensaje alterado, fallo")
    exit(1)
else:
    decrypt_text_bytes = ffibuilder.unpack(decrypt_buffer.buffer, decrypt_buffer.len)

    C.free_buffer(decrypt_buffer)

    print("-" *20)
    print(f"Texto descifrado: {decrypt_text_bytes.decode('utf-8')}")

    assert plaintext == decrypt_text_bytes
    print("\n Verificacion: Texto original y descifrado coinciden")
