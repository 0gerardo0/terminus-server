#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                            const char *url, const char *method,
                                            const char *version, const char *upload_data,
                                            size_t *upload_data_size, void **con_cls) {
  const char *page = "<html><body><h1>Servidor esta funcionado asi super wow</h1></body></html>";
  struct MHD_Response *response;
  enum MHD_Result ret;

  response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
  
  MHD_add_response_header(response, "Content-Type", "text/html; charset=utf-8");

  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

  MHD_destroy_response(response);

  return ret;
}

struct MHD_Daemon *start_server(unsigned int port) {
  struct MHD_Daemon *MHD_daemon;

  MHD_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
                            &answer_to_connection, NULL, MHD_OPTION_END);

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
