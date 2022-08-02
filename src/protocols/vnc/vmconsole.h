/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef GUAC_VNC_VMCONSOLE_H
#define GUAC_VNC_VMCONSOLE_H

#include "config.h"
#include "vnc.h"
#include "settings.h"

#include <guacamole/client.h>
#include <rfb/rfbclient.h>
#include <curl/curl.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <pthread.h>

extern int
vm_console_get_unix_path(struct sockaddr_un *addr);

extern char *
vm_console_get_session(guac_client* client, guac_vnc_settings* settings,
                       CURL *curl, int vm_server_version);

extern char *
vm_console_get_ticket(guac_client* client, guac_vnc_settings* settings,
                        CURL *curl, int vm_server_version, const char *session);

extern void
guac_vnc_wsthread_state_update(guac_vnc_client *client,
                        guac_vnc_vmconsole_state_t state);

extern int
guac_vnc_wsthread_state_wait_for_ready(guac_vnc_client *client);

extern void *
guac_vnc_vmconsole_ws_thread(void* data);

#endif
