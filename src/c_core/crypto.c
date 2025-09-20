#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

typedef struct  {
  char* buffer;
  size_t len;
}BytesBuffer;


BytesBuffer encrypt_message(const unsigned char* message, size_t message_len, const unsigned char* key){
  printf("[C-DEBUG] Entrando a encrypt_message. Longitud del mensaje: %zu\n", message_len);
  if(sodium_init() < 0) {
    return (BytesBuffer){NULL, 0};
  }

  unsigned long long ciphertext_len = crypto_secretbox_MACBYTES + message_len;
  unsigned char* ciphertext = malloc(ciphertext_len);
  if (ciphertext == NULL){
    return (BytesBuffer){NULL, 0};
  }
  
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  crypto_secretbox_easy(ciphertext, message, message_len, nonce, key);

  size_t total_len = sizeof(nonce) + ciphertext_len;
  char* full_payload = malloc(total_len);
  if (full_payload == NULL){
    free(ciphertext);
    return (BytesBuffer){NULL, 0};
  }

  memcpy(full_payload, nonce, sizeof(nonce));
  memcpy(full_payload + sizeof(nonce), ciphertext, ciphertext_len);
  
  free(ciphertext);

  printf("[C-DEBUG] Saliendo de encrypt_message. Longitud del payload: %zu\n", total_len);
  return (BytesBuffer){full_payload, total_len};
}

BytesBuffer decrypt_message(const unsigned char* full_payload, size_t payload_len, const unsigned char* key){
  if (sodium_init() < 0) {
    return (BytesBuffer){NULL, 0};
  }

  if (payload_len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
    return (BytesBuffer){NULL, 0};
  }

  const unsigned char* nonce = full_payload;
  const unsigned char* ciphertext = full_payload + crypto_secretbox_NONCEBYTES;
  size_t ciphertext_len = payload_len - crypto_secretbox_NONCEBYTES;

  size_t decrypted_len = ciphertext_len - crypto_secretbox_MACBYTES;
  unsigned char* decrypted = malloc(decrypted_len);
  if (decrypted == NULL) {
    return (BytesBuffer){NULL, 0};
  }

  if (crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key) != 0) {
    free(decrypted);
    
    return (BytesBuffer){NULL, 0};
  }

  return (BytesBuffer){(char*)decrypted, decrypted_len};
}

size_t get_key_bytes(void) {
  return crypto_secretbox_KEYBYTES;
}

void free_buffer(BytesBuffer buffer) {
  if (buffer.buffer != NULL){
    free(buffer.buffer);
  }
}
