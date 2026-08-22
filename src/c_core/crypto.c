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

BytesBuffer hash_password(const char* password, size_t password_len ){
  if(sodium_init() < 0 ){
    return (BytesBuffer){NULL, 0};
  }
  if (password == NULL || password_len == 0) {
    return (BytesBuffer){NULL, 0};
  }
  char* encoded = malloc(crypto_pwhash_STRBYTES);
  if (encoded == NULL) {
    return (BytesBuffer){NULL, 0};
  }
  if (crypto_pwhash_str(encoded, password, password_len, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) !=0 ) {
    free(encoded);
    return (BytesBuffer){NULL, 0};
  }
  return (BytesBuffer){encoded, strlen(encoded)};
}

int verify_password(const char* stored_hash, const char* password, size_t password_len) {
  if (sodium_init() < 0) {
    return -1;
  }
  if (stored_hash == NULL || password == NULL || password_len == 0) {
    return -1;
  }
  if (strlen(stored_hash) < 16) {
    return -1;
  }
  return crypto_pwhash_str_verify(stored_hash,password, password_len);
}

void free_buffer(BytesBuffer buffer) {
  if (buffer.buffer != NULL){
    free(buffer.buffer);
  }
}
