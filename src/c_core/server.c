#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static enum MHD_Result header_printer(void *cls,
                          enum MHD_ValueKind kind,
                          const char *key,
                          const char *value) {
  if (kind == MHD_HEADER_KIND && key && value) {
    fprintf(stderr, "HEADER: %s: %s\n", key, value);
  }
  return MHD_YES;
}

typedef struct {
  char *data;
  size_t size;
} PostContext;

typedef enum MHD_Result (*request_handler_callback)(void *cls, 
                                                    struct MHD_Connection *connection,
                                                    const char *url,
                                                    const char *method,
                                                    const char *post_data,
                                                    size_t post_data_size,
                                                    const char *auth_header);

static void request_completed_callback(void *cls,
                                       struct MHD_Connection *connection,
                                       void **con_cls,
                                       enum MHD_RequestTerminationCode toe);

static enum MHD_Result answer_to_connection(void *cls, 
                                            struct MHD_Connection *connection,
                                            const char *url, 
                                            const char *method,
                                            const char *version, 
                                            const char *upload_data,
                                            size_t *upload_data_size, 
                                            void **con_cls) {
  
  if (0 != strcmp(method, MHD_HTTP_METHOD_POST)) {
    const char *auth = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
    MHD_get_connection_values(connection, MHD_HEADER_KIND, &header_printer, NULL);
    request_handler_callback handler = cls;
    return handler(cls, connection, url, method, NULL, 0, auth);
  }
  
  PostContext *post_ctx = *con_cls;
  
  if (NULL == post_ctx) {
    post_ctx = calloc(1, sizeof(PostContext));
    if (NULL == post_ctx){
      return MHD_NO;
    }
    *con_cls = post_ctx;
    return MHD_YES;
  }

  if (*upload_data_size != 0) {
    post_ctx->data = realloc(post_ctx->data, post_ctx->size + *upload_data_size);
    if(NULL == post_ctx->data){
      return MHD_NO;
    }
    memcpy(post_ctx->data + post_ctx->size, upload_data, *upload_data_size);
    post_ctx->size += *upload_data_size;
    *upload_data_size = 0;
    return MHD_YES;
  } 
  const char *auth = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
  MHD_get_connection_values(connection, MHD_HEADER_KIND, &header_printer, NULL);
  request_handler_callback handler = cls;
  return handler(cls, connection, url, method, post_ctx->data, post_ctx->size, auth);

}

static void request_completed_callback(void *cls, struct MHD_Connection *connection, void **con_cls,
                                       enum MHD_RequestTerminationCode toe){

  PostContext *post_ctx = *con_cls;

  if (NULL == post_ctx){
    return;
  }

  if (post_ctx->data) {
    free(post_ctx->data);
  }
  free(post_ctx);
  *con_cls = NULL;

}

struct MHD_Daemon *start_server(unsigned int port, request_handler_callback handler) {
  struct MHD_Daemon *MHD_daemon;

  MHD_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
                                port,
                                NULL,
                                NULL,
                                &answer_to_connection,
                                handler,
                                MHD_OPTION_NOTIFY_COMPLETED,
                                &request_completed_callback,
                                NULL,
                                MHD_OPTION_END);

  if (NULL == MHD_daemon) {
    fprintf(stderr, "Error: No se pudo iniciar el demonio de libmicrohttpd\n");
    return NULL;
  }

  printf("Servidor Terminus iniciado en http://127.0.0.1:%u\n", port);
  return MHD_daemon;
}

void stop_server(struct MHD_Daemon *MHD_daemon) {
  if (MHD_daemon != NULL) {
    MHD_stop_daemon(MHD_daemon);
    printf("Servidor Terminus detenido.\n");
  }
}

enum MHD_Result send_text_response(struct MHD_Connection *connection, const char *body, unsigned int status_code) {
  struct MHD_Response *MHD_response;
  enum MHD_Result ret;

  MHD_response = MHD_create_response_from_buffer(strlen(body), (void *)body, MHD_RESPMEM_MUST_COPY);

  if (NULL == MHD_response){
    return MHD_NO;
  }

  MHD_add_response_header(MHD_response, "Content-Type", "text/plain; charset=utf-8");
  ret = MHD_queue_response(connection, status_code, MHD_response);
  MHD_destroy_response(MHD_response);

  return ret;
}

enum MHD_Result send_binary_response(struct MHD_Connection *connection, const char *body, size_t body_len,
                                     const char *content_type, unsigned int status_code){

  struct MHD_Response *mhd_response;
  enum MHD_Result ret;

  mhd_response = MHD_create_response_from_buffer(body_len, (void *)body, MHD_RESPMEM_MUST_COPY);

  if(NULL ==  mhd_response) {
    return MHD_NO;
  }

  MHD_add_response_header(mhd_response, "Content-Type", content_type);
  ret = MHD_queue_response(connection, status_code, mhd_response);
  MHD_destroy_response(mhd_response);

  return ret;
}
