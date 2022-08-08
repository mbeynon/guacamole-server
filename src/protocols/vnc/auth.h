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

#ifndef GUAC_VNC_AUTH_H
#define GUAC_VNC_AUTH_H

#include "config.h"

#ifdef ENABLE_VNC_TO_VM_CONSOLE
#include "client.h"
#endif

#include <rfb/rfbclient.h>
#include <rfb/rfbproto.h>

/**
 * Callback which is invoked by libVNCServer when it needs to read the user's
 * VNC password. As this user's password, if any, will be stored in the
 * connection settings, this function does nothing more than return that value.
 *
 * @param client
 *     The rfbClient associated with the VNC connection requiring the password.
 *
 * @return
 *     The password to provide to the VNC server.
 */
char* guac_vnc_get_password(rfbClient* client);

#ifdef ENABLE_VNC_GENERIC_CREDENTIALS
/**
 * Callback which is invoked by libVNCServer when it needs to read the user's
 * VNC credentials.  The credentials are stored in the connection settings,
 * so they will be retrieved from that.
 * 
 * @param client
 *     The rfbClient associated with the VNC connection requiring the
 *     authentication.
 * 
 * @param credentialType
 *     The credential type being requested, as defined by the libVNCclient
 *     code in the rfbclient.h header.
 * 
 * @return
 *     The rfbCredential object that contains the required credentials.
 */
rfbCredential* guac_vnc_get_credentials(rfbClient* client, int credentialType);
#endif

#ifdef ENABLE_VNC_TO_VM_CONSOLE
/**
 * Function to obtain the VM Server credentials from settings, or by prompting
 * the user if they are not provided.  This is not a callback, rather it's
 * called directly during connection setup.
 * 
 * @param gc
 *     The guac client for the vnc connection.
 * 
 * @return
 *     int == 0 success
 */
int guac_vnc_vm_server_get_credentials(guac_client* gc);
#endif

#endif

