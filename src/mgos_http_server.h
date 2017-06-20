/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MOS_LIBS_HTTP_SERVER_SRC_MGOS_HTTP_SERVER_H_
#define CS_MOS_LIBS_HTTP_SERVER_SRC_MGOS_HTTP_SERVER_H_

#include <stdbool.h>

#include "sys_config.h"
#include "fw/src/mgos_init.h"
#include "common/cs_dbg.h"

bool mgos_http_server_init(void);

struct mg_connection *mgos_get_sys_http_server(void);

/* Register HTTP endpoint handler `handler` on URI `uri_path` */
void mgos_register_http_endpoint(const char *uri_path,
                                 mg_event_handler_t handler, void *user_data);
void mgos_register_http_endpoint_opt(const char *uri_path,
                                     mg_event_handler_t handler,
                                     struct mg_http_endpoint_opts opts);

#endif /* CS_MOS_LIBS_HTTP_SERVER_SRC_MGOS_HTTP_SERVER_H_ */
