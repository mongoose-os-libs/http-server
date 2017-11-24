/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_HTTP_SERVER_SRC_MGOS_HTTP_SERVER_H_
#define CS_MOS_LIBS_HTTP_SERVER_SRC_MGOS_HTTP_SERVER_H_

#include <stdbool.h>

#include "mgos_config.h"
#include "mgos_init.h"
#include "common/cs_dbg.h"

#if defined(__cplusplus)
extern "C" {  // Make sure we have C-declarations in C++ programs
#endif

bool mgos_http_server_init(void);

struct mg_connection *mgos_get_sys_http_server(void);

/* Register HTTP endpoint handler `handler` on URI `uri_path` */
void mgos_register_http_endpoint(const char *uri_path,
                                 mg_event_handler_t handler, void *user_data);
void mgos_register_http_endpoint_opt(const char *uri_path,
                                     mg_event_handler_t handler,
                                     struct mg_http_endpoint_opts opts);

/*
 * Set document root to serve static content from. Setting it to NULL disables
 * static server (404 will be returned).
 */
void mgos_http_server_set_document_root(const char *document_root);

#if defined(__cplusplus)
}
#endif

#endif /* CS_MOS_LIBS_HTTP_SERVER_SRC_MGOS_HTTP_SERVER_H_ */
