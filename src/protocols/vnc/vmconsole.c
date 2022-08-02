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

#include "config.h"

#include "auth.h"
#include "client.h"
#include "log.h"
#include "vmconsole.h"

#include <guacamole/client.h>
#include <guacamole/protocol.h>
#include <guacamole/recording.h>
#include <guacamole/socket.h>
#include <guacamole/timestamp.h>
#include <guacamole/wol.h>
#include <rfb/rfbclient.h>
#include <rfb/rfbconfig.h>
#include <rfb/rfbproto.h>

#include <cjson/cJSON.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <libwebsockets.h>
#include <uuid/uuid.h>


/**
 * @brief Generate a unique file name for a unix domain socket
 * 
 * @param addr = struct to fill out with the unique unix path
 * @return 0 on success
 */
int vm_console_get_unix_path(struct sockaddr_un *paddr) {
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    char uuid[36 + 1];
    uuid_unparse_lower(binuuid, uuid);

    memset(paddr, 0, sizeof(struct sockaddr_un));
    paddr->sun_family = AF_UNIX;
    size_t sz = snprintf(paddr->sun_path, sizeof(paddr->sun_path), "/tmp/guacd-vnc-%s.sock", uuid);

    return (sz == 15 + 36 + 5) ? 0 : 1;
}

typedef struct response {
    char *memory;
    size_t size;
} writememory_chunk_t;

static size_t
curl_writememory_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    writememory_chunk_t *mem = (writememory_chunk_t *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

/**
 * @brief Call the VM server to allocate a new session for making later calls.
 * 
 * @param client
 *     The guac client for this connection.
 *
 * @param settings
 *     The guac VNC settings for this connection.
 *
 * @param curl
 *     Handle to instance of libcurl.
 *
 * @param vm_server_version
 *     Which API to use (1 or 2).
 *
 * @returns
 *     An allocated string (caller must free) of the VM server session ID.
 *     NULL means failure.
 */
char *vm_console_get_session(guac_client* client, guac_vnc_settings* settings,
                             CURL *curl, int vm_server_version) {
    CURLcode res;

    /* create a base64 encoded username:password string */
    const char *username = settings->username ? settings->username : "";
    const char *password = settings->password ? settings->password : "";
    const char *auth_hdr_prefix = "authorization: Basic ";
    int imax=strlen(username) + 1 + strlen(password) + 1;
    int omax=strlen(auth_hdr_prefix) + (imax*4/3 + 4) * 2;  /* larger than needed for base64 part */
    char ibuf[imax], obuf[omax];
    size_t ilen = snprintf(ibuf, imax, "%s:%s", username, password);
    size_t oprefix = snprintf(obuf, omax, "%s", auth_hdr_prefix);
    size_t olen = lws_b64_encode_string(ibuf, ilen, obuf + oprefix, omax - oprefix);
    if (olen == 0) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR,
            "Internal failure creating base64 of credentials.");
        return NULL;
    }

    /* URL for session */
    CURLU *u = curl_url();
    char portbuf[6];
    snprintf(portbuf, 6, "%d", settings->port);
    if (curl_url_set(u, CURLUPART_SCHEME, (settings->port == 443 ? "https" : "http"), 0) ||
        curl_url_set(u, CURLUPART_HOST, settings->hostname, 0) ||
        curl_url_set(u, CURLUPART_PORT, portbuf, 0) ||
        curl_url_set(u, CURLUPART_PATH,
            (vm_server_version == 1 ? "/rest/com/vmware/cis/session" : "/api/session"), 0)
        ) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR,
            "Internal failure creating URL from hostname `%s` and port `%d`.",
            settings->hostname, settings->port);
        return NULL;
    }

    /* POST for session */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_CURLU, u);
    struct curl_slist *list = NULL;
    list = curl_slist_append(list, "accept: application/json");
    list = curl_slist_append(list, "vmware-use-header-authn: true");
    list = curl_slist_append(list, obuf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    if (settings->vm_allow_insecure_tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    writememory_chunk_t chunk = { .memory = malloc(0), .size = 0 };
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writememory_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        char *part;
        curl_url_get(u, CURLUPART_URL, &part, 0);
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
            "Failure getting session from VM server (POST %s) : %s.",
            part, curl_easy_strerror(res));
        curl_free(part);
        return NULL;
    }
    long code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_off_t size;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &size);

    cJSON *json_resp = NULL;
    if (vm_server_version == 1) {
        json_resp = cJSON_ParseWithLength(chunk.memory, chunk.size);
    } else {  // bare quoted string response won't parse with cJSON, so wrap same as v1 returns
        size_t tmpmax = 10 + chunk.size + 1;
        char tmpbuf[tmpmax];
        size_t tmplen = snprintf(tmpbuf, tmpmax, "{\"value\":%s}", chunk.memory);
        json_resp = cJSON_ParseWithLength(tmpbuf, tmplen);
    }
    cJSON *json = cJSON_GetObjectItemCaseSensitive(json_resp, "value");
    if (! (cJSON_IsObject(json_resp) && cJSON_IsString(json) && json->valuestring != NULL)) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
            "Failure getting session from VM server: missing token in json response");
        return NULL;
    }
    char *session = strdup(json->valuestring);
    cJSON_Delete(json_resp);

    curl_slist_free_all(list);
    curl_url_cleanup(u);
    return session;
}

/**
 * @brief Call the VM server to request a webmks ticket for a specific VM oid.
 * 
 * @param client
 *     The guac client for this connection.
 *
 * @param settings
 *     The guac VNC settings for this connection.
 *
 * @param curl
 *     Handle to instance of libcurl.
 *
 * @param vm_server_version
 *     Which API to use (1 or 2).
 *
 * @param session
 *     The current API session.
 *
 * @returns
 *     An allocated string (caller must free) of the VM server URL to get a
 *     WSS console.  NULL means failure.
 */
char *vm_console_get_ticket(guac_client* client, guac_vnc_settings* settings,
                            CURL *curl, int vm_server_version, const char *session) {
    CURLcode res;

    /* URL for ticket */
    CURLU *u = curl_url();
    size_t pathlen = 33 + strlen(settings->vm_id) + 1;
    char pathbuf[pathlen];
    if (vm_server_version == 1) {
        snprintf(pathbuf, pathlen, "/rest/vcenter/vm/%s/console/tickets", settings->vm_id);
    } else {
        snprintf(pathbuf, pathlen, "/api/vcenter/vm/%s/console/tickets", settings->vm_id);
    }

    char portbuf[6];
    snprintf(portbuf, 6, "%d", settings->port);

    if (curl_url_set(u, CURLUPART_SCHEME, (settings->port == 443 ? "https" : "http"), 0) ||
        curl_url_set(u, CURLUPART_HOST, settings->hostname, 0) ||
        curl_url_set(u, CURLUPART_PORT, portbuf, 0) ||
        curl_url_set(u, CURLUPART_PATH, pathbuf, 0))
    {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR,
            "Internal failure creating URL from hostname `%s` and port `%d`.",
            settings->hostname, settings->port);
        return NULL;
    }

    size_t sessionlen = 23 + strlen(session) + 1;
    char sessionbuf[sessionlen];
    snprintf(sessionbuf, sessionlen, "vmware-api-session-id: %s", session);

    // v1: {"spec": {"type":"WEBMKS"}}
    // v2: {"type":"WEBMKS"}
    // TODO: add lock for multiple threads using cJSON concurrently
    cJSON *json_req = cJSON_CreateObject();
    if (!json_req || !cJSON_AddStringToObject(json_req, "type", "WEBMKS")) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR,
            "Internal failure creating JSON spec.");
        return NULL;
    }
    if (vm_server_version == 1) {
        cJSON *json = cJSON_CreateObject();
        if (!json) {
            guac_client_abort(client, GUAC_PROTOCOL_STATUS_SERVER_ERROR,
                "Internal failure creating JSON spec.");
            cJSON_Delete(json_req);
            return NULL;
        }
        cJSON_AddItemToObject(json, "spec", json_req);
        json_req = json;
    }
    char *alloc_json_req = cJSON_PrintUnformatted(json_req);    
    cJSON_Delete(json_req);

    /* POST for ticket */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, alloc_json_req);
    free(alloc_json_req);
    curl_easy_setopt(curl, CURLOPT_CURLU, u);
    struct curl_slist *list = NULL;
    list = curl_slist_append(list, "vmware-use-header-authn: true");
    list = curl_slist_append(list, sessionbuf);
    list = curl_slist_append(list, "accept: application/json");
    list = curl_slist_append(list, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    if (settings->vm_allow_insecure_tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    writememory_chunk_t chunk = { .memory = malloc(0), .size = 0 };
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writememory_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
            "Failure getting session from VM server: %s.",
            curl_easy_strerror(res));
        return NULL;
    }
    long code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_off_t size;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &size);

    char *ticket = NULL;
    cJSON *json_resp = cJSON_ParseWithLength(chunk.memory, chunk.size);
    cJSON *json = json_resp;
    // v1: unwrap "value:"
    if (vm_server_version == 1) {
        json = cJSON_GetObjectItemCaseSensitive(json, "value");
        if (! (cJSON_IsObject(json) && json != NULL)) {
            guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
                "Failure getting ticket from VM server: missing \"value\" token in json response: %s", chunk.memory);
            cJSON_Delete(json_resp);
            return NULL;
        }
    }
    // v1+v2: unwrap "ticket:"
    json = cJSON_GetObjectItemCaseSensitive(json, "ticket");
    if (! (cJSON_IsString(json) && json->valuestring != NULL)) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
            "Failure getting ticket from VM server: missing \"ticket\" token in json response: %s", chunk.memory);
        cJSON_Delete(json_resp);
        return NULL;
    }
    ticket = strdup(json->valuestring);
    cJSON_Delete(json_resp);

    curl_slist_free_all(list);
    curl_url_cleanup(u);
    return ticket;
}


//
// websocket client
//

static int bExit = 0;
static int bDenyDeflate = 1;

static int ws_callback_binary(struct lws* wsi, enum lws_callback_reasons reason, void *user, void* in, size_t len);

/**
 * @brief Signal handler to break out of loop
 * 
 * @param sig 
 * @return * void 
 */
static void onSigInt(int sig) {
	bExit = 1;
}

// #define QUEUELEN 10
// #define QUEUELEN 16
// #define QUEUELEN 20
#define QUEUELEN 64
// #define QUEUELEN 128

/* queue free space below this, rx flow is disabled */
// #define RXFLOW_MIN 4
#define RXFLOW_MIN ((1 * QUEUELEN) / 4)

/* queue free space above this, rx flow is enabled */
#define RXFLOW_MAX ((2 * QUEUELEN) / 4)

// #define RXBUFSIZE 128
// #define RXBUFSIZE 256
// #define RXBUFSIZE 512
// #define RXBUFSIZE 1024
// #define RXBUFSIZE 2048
#define RXBUFSIZE 4096
// #define RXBUFSIZE 8192
// #define RXBUFSIZE 16384
// #define RXBUFSIZE 32768
// #define RXBUFSIZE 65536

/* this is the element in the ring */
struct msg {
	void *payload;
	size_t len;
};

struct per_session_data {
    struct lws_ring *ring;
    bool flow_controlled;

    size_t bufmax;
    char *buf;
};

struct per_vhost_data {
    struct lws *wsi_client;
    struct lws *wsi_server;
    struct per_session_data *pss_client;
    struct per_session_data *pss_server;
};

/**
 * @brief array of supported protocols
 * { "protocol name", protocol callback, data size per session (can be 0), recv buffer size (can be 0) }
 */
static struct lws_protocols protocols[] = {
	{ "binary", ws_callback_binary, sizeof(struct per_session_data), RXBUFSIZE },
	{ NULL, NULL, 0 } // array end marker
};

enum protocolList {
	PROTOCOL_BINARY,
	PROTOCOL_LIST_COUNT // enum end marker
};

/**
 * @brief supported LWS extensions, may be required
 */
static const struct lws_extension extensions[] = {
	{
	    "permessage-deflate",
	    lws_extension_callback_pm_deflate,
		"permessage-deflate; client_max_window_bits"
	},
	{
		"deflate-frame",
		lws_extension_callback_pm_deflate,
		"deflate_frame"
	},
	{ NULL, NULL, NULL } // array end marker
};

static struct msg *__new_message(void *p, size_t l) {
    struct msg *pmsg = malloc(sizeof(struct msg));
    if (!pmsg) return NULL;
    pmsg->len = l;
    pmsg->payload = malloc(LWS_PRE + l);
    if (!pmsg->payload) {
        free(pmsg);
        return NULL;
    }
    memcpy((char *)pmsg->payload + LWS_PRE, p, l);
    return pmsg;
}

static void
__destroy_message(void *_pmsg) {
    if (!_pmsg) return;
    struct msg *pmsg = _pmsg;
    pmsg->len = 0;
    if (pmsg->payload) {
        free(pmsg->payload);
        pmsg->payload = NULL;
    }
}

static void
__fix_message_partial_send(struct msg *msg, size_t n) {
    if (!msg || !msg->payload || !msg->len || n <= 0 || n >= msg->len)
        return;  // do nothing for bad cases
    memmove(((char *)msg->payload) + LWS_PRE, ((char *)msg->payload) + LWS_PRE + n, msg->len - n);
    msg->len -= n;
}


/**
 * @brief Callback for the binary websocket protocol
 * 
 * @param wsi 
 * @param reason 
 * @param user 
 * @param in 
 * @param len 
 * @return int 
 */
static int
ws_callback_binary(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
	struct per_session_data *pss = (struct per_session_data *)user;
	struct per_vhost_data *vhd = (struct per_vhost_data *)
        lws_protocol_vh_priv_get(lws_get_vhost(wsi), lws_get_protocol(wsi));
    guac_client *client = lws_context_user(lws_get_context(wsi));

    const struct msg *cpmsg;
    struct msg *pmsg;
	int n, m;

	switch (reason) {
    /* callbacks for wsi and protocol binding */
    case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
        guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_PROTOCOL_INIT(%d): nop (pss=%p)", LWS_CALLBACK_PROTOCOL_INIT, (void*)pss);
        break;

    case LWS_CALLBACK_WSI_CREATE:
        guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_WSI_CREATE(%d): nop (pss=%p)", LWS_CALLBACK_WSI_CREATE, (void*)pss);
        break;
    
    case LWS_CALLBACK_WSI_DESTROY:
        guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_WSI_DESTROY(%d): nop (pss=%p)", LWS_CALLBACK_WSI_DESTROY, (void*)pss);
        break;

    case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
        guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_WS_PEER_INITIATED_CLOSE(%d): report why ...", LWS_CALLBACK_WS_PEER_INITIATED_CLOSE);
        // TODO: check guac error level and emit hexdump
        lwsl_hexdump_err((char *)in, len);
        break;

    // [ws_server] websocket client closed
    case LWS_CALLBACK_CLIENT_CLOSED:
		guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_CLIENT_CLOSED(%d): [ws_server] websocket closed vhd=%p",
            LWS_CALLBACK_CLIENT_CLOSED, (void*)vhd);
        struct lws_context *ctx = lws_get_context(wsi);
        if (vhd) {
            if (vhd->pss_client) {
                lws_ring_destroy(vhd->pss_client->ring);
                vhd->pss_client->ring = NULL;
                if (vhd->pss_client->buf) {
                    free(vhd->pss_client->buf);
                    vhd->pss_client->buf = NULL;
                }
            }
            vhd->wsi_client = NULL;
            if (vhd->pss_server) {
                lws_ring_destroy(vhd->pss_server->ring);
                vhd->pss_server->ring = NULL;
                if (vhd->pss_server->buf) {
                    free(vhd->pss_server->buf);
                    vhd->pss_server->buf = NULL;
                }
            }
            vhd->wsi_server = NULL;
        }
        bExit = 1;
        lws_cancel_service(ctx);
        // TODO: close ws_client
        // TODO: ensure ws_thread exits cleanly
		break;

    // confirm extension support
	case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		if (strcmp((char*)in, "deflate-stream") == 0) {
			if (bDenyDeflate) {
				guac_client_log(client, GUAC_LOG_DEBUG,
                    "[binary] Denied deflate-stream extension");
				return 1;
			}
		}
		break;

    // websocket client connection success
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_CLIENT_ESTABLISHED(%d): entry (pss=%p, ringbuf=%d/%d/%d)",
            LWS_CALLBACK_CLIENT_ESTABLISHED, (void*)pss, QUEUELEN, RXFLOW_MIN, RXFLOW_MAX);
        pss->ring = lws_ring_create(sizeof(struct msg), QUEUELEN,
                                    __destroy_message);
        pss->bufmax = 0;
        pss->buf = NULL;  // not needed for wsi_server
        if (!pss->ring)
            return 1;
        if (!vhd) {
            guac_client_log(client, GUAC_LOG_TRACE,
            "LWS_CALLBACK_CLIENT_ESTABLISHED(%d): create vhd", LWS_CALLBACK_CLIENT_ESTABLISHED);
            vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
                    lws_get_protocol(wsi), sizeof(struct per_vhost_data));
            if (!vhd)
                return -1;
            vhd->pss_client = NULL;
            vhd->pss_server = NULL;
        }
        vhd->pss_server = pss;
        vhd->wsi_server = wsi;
        break;

    // connection closed
    case LWS_CALLBACK_CLOSED:
		guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_CLOSED(%d): nop (pss=%p)", LWS_CALLBACK_CLOSED, (void*)pss);
		break;

    // [ws-server] have data to recv from server
	case LWS_CALLBACK_CLIENT_RECEIVE:
        if (!vhd || !vhd->pss_client || !vhd->pss_client->ring) {
			guac_client_log(client, GUAC_LOG_WARNING,
                "LWS_CALLBACK_CLIENT_RECEIVE(%d): client ring is gone, abort", LWS_CALLBACK_CLIENT_RECEIVE);
            return -1;
        }
        n = (int)lws_ring_get_count_free_elements(vhd->pss_client->ring);
		if (!n) {
			guac_client_log(client, GUAC_LOG_WARNING,
                "LWS_CALLBACK_CLIENT_RECEIVE(%d): no room in client_ring, drop message", LWS_CALLBACK_CLIENT_RECEIVE);
			break;
		}

        // heap allocate
        pmsg = __new_message(in, len);
        if (!pmsg) {
            guac_client_log(client, GUAC_LOG_WARNING,
                "LWS_CALLBACK_CLIENT_RECEIVE(%d): OOM, drop message", LWS_CALLBACK_CLIENT_RECEIVE);
            break;
        }
		// printf("[wsi_server] recv <-: (%ld) o=%p d=%p\n", pmsg->len, (char*)pmsg, pmsg->payload);
        // lwsl_hexdump_err((char *)pmsg->payload + LWS_PRE, pmsg->len);

		if (!lws_ring_insert(vhd->pss_client->ring, pmsg, 1)) {
            guac_client_log(client, GUAC_LOG_WARNING,
                "LWS_CALLBACK_CLIENT_RECEIVE(%d): fail ring insert, drop message", LWS_CALLBACK_CLIENT_RECEIVE);
            break;
		}
        lws_callback_on_writable(vhd->wsi_client);

		if (!vhd->pss_client->flow_controlled) {
            int c = lws_ring_get_count_free_elements(vhd->pss_client->ring);
            if (c < RXFLOW_MIN) {
                vhd->pss_client->flow_controlled = true;
                lws_rx_flow_control(wsi, 0);
                guac_client_log(client, GUAC_LOG_DEBUG,
                    "[wsi_server] flow control: (%d free < %d min), so STOP my recv", c, RXFLOW_MIN);
                // TODO: only output if guac_log is DEBUG or TRACE
                lws_ring_dump(vhd->pss_client->ring, NULL);
                lws_ring_dump(vhd->pss_server->ring, NULL);
                // lws_cancel_service(lws_get_context(vhd->wsi_client));
            }
        }
		break;

    // [ws-server] can now write data
	case LWS_CALLBACK_CLIENT_WRITEABLE:
        cpmsg = lws_ring_get_element(pss->ring, NULL);
        if (!cpmsg) {  // spurious wakeup
            break;
        }

        m = lws_write(wsi, ((unsigned char *)cpmsg->payload) + LWS_PRE,
                    cpmsg->len, LWS_WRITE_BINARY);
		guac_client_log(client, GUAC_LOG_TRACE,
            "[wsi_server] sent ->: (%d of %ld)", m, cpmsg->len);

        if (m == 0) {  // try again
            guac_client_log(client, GUAC_LOG_TRACE,
                "LWS_CALLBACK_CLIENT_WRITEABLE: ERROR lws_write() return %d bytes, return and try again", m);
			lws_callback_on_writable(wsi);
            return 0;
        } else if (m < 0 || m < (int)cpmsg->len) {  // error or partial
            guac_client_log(client, GUAC_LOG_TRACE,
                "LWS_CALLBACK_CLIENT_WRITEABLE: ERROR lws_write() return %d instead of %ld bytes", m, cpmsg->len);
            return -1;
        }
        // printf("[wsi_server] sent %d of expected %ld bytes.", m, cpmsg->len);
        lws_ring_consume(pss->ring, NULL, NULL, 1);

        if (lws_ring_get_count_waiting_elements(pss->ring, NULL)) {
			lws_callback_on_writable(wsi);
            guac_client_log(client, GUAC_LOG_TRACE,
                "[wsi_server] ask for another writable callback");
            lws_ring_dump(pss->ring, NULL);
        }
        if (pss->flow_controlled) {
            int c = lws_ring_get_count_free_elements(pss->ring);
            if (c > RXFLOW_MAX) {
                pss->flow_controlled = false;
                lws_rx_flow_control(vhd->wsi_client, 1);
                guac_client_log(client, GUAC_LOG_TRACE,
                    "[wsi_server] flow control: (%d free > %d max), so START wsi_client recv", c, RXFLOW_MAX);
                lws_ring_dump(vhd->pss_client->ring, NULL);
                lws_ring_dump(vhd->pss_server->ring, NULL);
            }
        }        
		break;

    // connection error
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		guac_client_log(client, GUAC_LOG_ERROR,
                "LWS_CALLBACK_CLIENT_CONNECTION_ERROR(%d): [wsi_server] There was a connection error: %s",
                LWS_CALLBACK_CLIENT_CONNECTION_ERROR, in ? (char*)in : "(no error information)");
		break;

    // 
    case LWS_CALLBACK_RAW_ADOPT_FILE:
        guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_RAW_ADOPT_FILE(%d): entry, (pss=%p, ringbuf=%d/%d/%d)",
            LWS_CALLBACK_RAW_ADOPT_FILE, (void*)pss, QUEUELEN, RXFLOW_MIN, RXFLOW_MAX);
        pss->ring = lws_ring_create(sizeof(struct msg), QUEUELEN,
                                    __destroy_message);
        pss->bufmax = RXBUFSIZE;
        pss->buf = malloc(RXBUFSIZE);
        if (!pss->ring || !pss->buf)
            return 1;

        if (!vhd) {
            guac_client_log(client, GUAC_LOG_TRACE,
                "LWS_CALLBACK_RAW_ADOPT_FILE(%d): create vhd", LWS_CALLBACK_RAW_ADOPT_FILE);
            vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
                    lws_get_protocol(wsi), sizeof(struct per_vhost_data));
            if (!vhd)
                return -1;
            vhd->pss_client = NULL;
            vhd->pss_server = NULL;
        }
        vhd->pss_client = pss;
        vhd->wsi_client = wsi;
        break;
    
    // 
    case LWS_CALLBACK_RAW_RX_FILE:
        if (!vhd || !vhd->pss_server || !vhd->pss_server->ring) {
			guac_client_log(client, GUAC_LOG_ERROR,
                "LWS_CALLBACK_RAW_RX_FILE: server ring is gone, abort");
            return -1;
        }

        // adopted raw files are manually read
        // use input arg that's not used for this cb reason
        do {
            len = read(lws_get_socket_fd(wsi), pss->buf, pss->bufmax);
        } while (len == -1 && errno == EAGAIN);
        if (len == -1) {
            return -1;
        } else if (len == 0) {
            return 0;  // try again
        }

        n = (int)lws_ring_get_count_free_elements(vhd->pss_server->ring);
		if (!n) {
			guac_client_log(client, GUAC_LOG_WARNING,
                "LWS_CALLBACK_RAW_RX_FILE: no room in server_ring, drop message");
			break;
		}
        // heap allocate
        pmsg = __new_message(pss->buf, len);
        if (!pmsg) {
			guac_client_log(client, GUAC_LOG_WARNING,
                "LWS_CALLBACK_RAW_RX_FILE: OOM, drop message");
            break;
        }
		// printf("[wsi_client] recv ->: (%ld) o=%p d=%p\n", pmsg->len, (char*)pmsg, pmsg->payload);
        // lwsl_hexdump_err((char *)pmsg->payload + LWS_PRE, pmsg->len);

		if (!lws_ring_insert(vhd->pss_server->ring, pmsg, 1)) {
			guac_client_log(client, GUAC_LOG_WARNING,
                "LWS_CALLBACK_RAW_RX_FILE: fail ring insert, drop message");
            break;
		}
        lws_callback_on_writable(vhd->wsi_server);

		if (!vhd->pss_server->flow_controlled) {
            int c = lws_ring_get_count_free_elements(vhd->pss_server->ring);
            if (c < RXFLOW_MIN) {
                vhd->pss_server->flow_controlled = true;
                lws_rx_flow_control(wsi, 0);
                guac_client_log(client, GUAC_LOG_TRACE,
                    "[wsi_client] flow control: (%d free < %d min), so STOP my recv", c, RXFLOW_MIN);
                lws_ring_dump(vhd->pss_client->ring, NULL);
                lws_ring_dump(vhd->pss_server->ring, NULL);
            }
        }
        break;

    // [ws-client] write data in my outgoing ring buffer to the client (VNC Client)
    case LWS_CALLBACK_RAW_WRITEABLE_FILE:
        cpmsg = lws_ring_get_element(pss->ring, NULL);
        if (!cpmsg) {  // spurious wake up
            break;
        }
        do {  // write all we can without blocking
            int retry_ct = 0;
            do {
                m = write(lws_get_socket_fd(wsi),
                            (char *)cpmsg->payload + LWS_PRE,
                            cpmsg->len);
                if (retry_ct > 0)
                    guac_timestamp_msleep(100);
            } while (m == -1 && errno == EAGAIN && ++retry_ct < 10);
            if (m < 1 || retry_ct >= 10) {
                guac_client_log(client, GUAC_LOG_ERROR,
                    "[wsi_client] failed write (ret=%d, retry_ct=%d errno=%d, %s)",
                    m, retry_ct, errno, strerror(errno));
                break;  // TODO: try to let lws_callback_on_writable() work instead of failing the connection?
                return -1;
            }
            guac_client_log(client, GUAC_LOG_TRACE,
                "[wsi_client] sent <-: (%d of %ld)", m, cpmsg->len);
            // lwsl_hexdump_err((char *)cpmsg->payload + LWS_PRE, m);

            if (m < cpmsg->len) {
                __fix_message_partial_send((struct msg *)cpmsg, m);
                break;
            } else {
                lws_ring_consume(pss->ring, NULL, NULL, 1);
            }
            if (pss->flow_controlled) {
                int c = lws_ring_get_count_free_elements(pss->ring);
                if (c > RXFLOW_MAX) {
                    pss->flow_controlled = false;
                    lws_rx_flow_control(vhd->wsi_server, 1);
                    guac_client_log(client, GUAC_LOG_TRACE,
                        "[wsi_client] flow control: (%d free > %d max), so START wsi_server recv", c, RXFLOW_MAX);
                    lws_ring_dump(vhd->pss_client->ring, NULL);
                    lws_ring_dump(vhd->pss_server->ring, NULL);
                }
            }

            // get the next from the ring?
            cpmsg = lws_ring_get_element(pss->ring, NULL);
        } while (cpmsg);

        if (lws_ring_get_count_waiting_elements(pss->ring, NULL)) {
            guac_client_log(client, GUAC_LOG_TRACE,
                "[wsi_client] ask for another writable callback");
            lws_callback_on_writable(wsi);
            lws_ring_dump(pss->ring, NULL);
        }
        break;

    //    
    case LWS_CALLBACK_RAW_CLOSE_FILE:
		guac_client_log(client, GUAC_LOG_DEBUG,
            "LWS_CALLBACK_RAW_CLOSE_FILE(%d): [wsi_client] nop (pss=%p)", LWS_CALLBACK_RAW_CLOSE_FILE, (void*)pss);
        break;

    /*
     * External pool loop callbacks
     */
    case LWS_CALLBACK_GET_THREAD_ID:
    case LWS_CALLBACK_ADD_POLL_FD:
    case LWS_CALLBACK_DEL_POLL_FD:
    case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
    case LWS_CALLBACK_LOCK_POLL:
    case LWS_CALLBACK_UNLOCK_POLL:
        break;  // silent skip
    
    /*
     * Misc things we don't care about
     */
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:  // server TLS
    case LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL:  // http client
    case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:  // http server
    case LWS_CALLBACK_EVENT_WAIT_CANCELLED:  // generic wsi event
    case LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION:  // client TLS
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:  // websocket client
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:  // websocket client
        break;  // silent skip

	default:
		guac_client_log(client, GUAC_LOG_DEBUG, "[ws-thread] default reason=%d", reason);
		break;
	}
	return 0;
}

static void log_emitter(int level, const char *line) {
    printf("lws_log: %s", line);
}

/**
 * @brief setup and connect websocket, processing ws messages in a loop
 * 
 * @param client - guac client from thread that spawned us
 * @param fd_client - socket from the vncclient library
 * @return int - 0 == success, !0 == failure
 */
static int vm_console_ws_loop(guac_client *client, int fd_client) {

    guac_vnc_client* vnc_client = (guac_vnc_client*) client->data;
    guac_vnc_settings* settings = vnc_client->settings;

	// lws_set_log_level(LLL_ERR | LLL_WARN, lwsl_emit_syslog);
	// lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG | LLL_CLIENT, log_emitter);
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, log_emitter);

    // TODO: move to early init before threads created?
	signal(SIGINT, onSigInt); // Register the SIGINT handler

    /* handle ws url */
	struct lws_context_creation_info ctxCreationInfo; // Context creation info
	struct lws_client_connect_info clientConnectInfo; // Client creation info
	struct lws_context *ctx; // The context to use

	struct lws *wsi_server, *wsi_client;
	const char *urlProtocol, *urlTempPath; // the protocol of the URL, and a temporary pointer to the path

	memset(&ctxCreationInfo, 0, sizeof(ctxCreationInfo));
	memset(&clientConnectInfo, 0, sizeof(clientConnectInfo));

	// parse url <protocol>://<address>:<port>/<path>
	if (lws_parse_uri(vnc_client->vm_server_url, &urlProtocol, &clientConnectInfo.address,
                      &clientConnectInfo.port, &urlTempPath)) {
        guac_client_log(client, GUAC_LOG_ERROR,
            "ws_thread: could not parse URL %s", vnc_client->vm_server_url);
        return 1;
	}

	// prepend '/' to urlPath and store in connect info
    int umax = 1 + strlen(urlTempPath) + 1;
    char urlPath[umax];
    snprintf(urlPath, umax, "/%s", urlTempPath);
	clientConnectInfo.path = urlPath;

	// setup context creation info
	ctxCreationInfo.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    ctxCreationInfo.port = CONTEXT_PORT_NO_LISTEN_SERVER;
	ctxCreationInfo.protocols = protocols;
	ctxCreationInfo.gid = -1;
	ctxCreationInfo.uid = -1;
	ctxCreationInfo.extensions = extensions;
    ctxCreationInfo.fd_limit_per_thread = 1+1+1;  // TODO: validate this
    ctxCreationInfo.ws_ping_pong_interval = 20;  // seconds if no other traffic
    ctxCreationInfo.user = (void *)client;

	ctx = lws_create_context(&ctxCreationInfo);
	if (ctx == NULL) {
        guac_client_log(client, GUAC_LOG_ERROR,
            "ws_thread: internal error creating context");
        return 1;
	}

    /* adopt fd_client, which causes these callbacks in the ws_loop:
     *     LWS_CALLBACK_RAW_ADOPT_FILE
     *     LWS_CALLBACK_RAW_RX_FILE
     *     LWS_CALLBACK_RAW_WRITEABLE_FILE
     *     LWS_CALLBACK_RAW_CLOSE_FILE
     */
    lws_sock_file_fd_type u;
    u.filefd = fd_client;
    wsi_client = lws_adopt_descriptor_vhost(lws_get_vhost_by_name(ctx, "default"),
                        0, u, protocols[PROTOCOL_BINARY].name, NULL);
    if (!wsi_client) {
        guac_client_log(client, GUAC_LOG_ERROR,
            "ws_thread: internal error adopting fd_client");
        return 1;
    }

	// setup client creation info
    int ssl_connection = LCCSCF_USE_SSL;
    if (settings->vm_allow_insecure_tls) {
        ssl_connection |= LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_INSECURE | \
                          LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK | LCCSCF_ALLOW_EXPIRED;
    }
	clientConnectInfo.context = ctx;
	clientConnectInfo.ssl_connection = (strncmp("wss", urlProtocol, 3) == 0 ? ssl_connection : 0);
	clientConnectInfo.host = clientConnectInfo.address;
	clientConnectInfo.origin = clientConnectInfo.address;
	clientConnectInfo.ietf_version_or_minus_one = -1;  // latest
	clientConnectInfo.protocol = protocols[PROTOCOL_BINARY].name;
	clientConnectInfo.pwsi = &wsi_server;

	// connect
	lws_client_connect_via_info(&clientConnectInfo);
	if (wsi_server == NULL) {
        guac_client_log(client, GUAC_LOG_ERROR,
            "ws_thread: error connecting to %s://%s:%d%s", urlProtocol,
            clientConnectInfo.address, clientConnectInfo.port, urlPath);
		return 1;
	}
    guac_client_log(client, GUAC_LOG_INFO,
        "ws_thread: connected to %s://%s:%d%s", urlProtocol,
        clientConnectInfo.address, clientConnectInfo.port, urlPath);

    // not using parent-child relationship, since want to adopt before connect to get order right

	// run forever, until bExit (SIGINT)
	while (!bExit) {
        int n = lws_service(ctx, 1000);
        if (n < 0) {
            guac_client_log(client, GUAC_LOG_ERROR,
                "ws_thread: error servicing libwebsocket loop (ret=%d)", n);
            break;
        } else if (n > 0) {
            guac_client_log(client, GUAC_LOG_DEBUG,
                "ws_thread: lws_service() ret=%d", n);
        }
        // printf(".");
	}

	// cleanup
	lws_context_destroy(ctx);

    guac_client_log(client, GUAC_LOG_DEBUG,
        "ws_thread: done executing lws loop");

	return 0;
}


/**
 * Updates the state of the wsthread, and signal threads
 * blocked in guac_vnc_wsthread_state_wait().  Called by
 * the ws_thread.
 *
 * @param client
 *     The vnc client whose state should be updated.
 *
 * @param state
 *     The new state to assign
 */
void guac_vnc_wsthread_state_update(guac_vnc_client *client, guac_vnc_vmconsole_state_t state) {

    pthread_mutex_lock(&(client->state_lock));

    if (client->state != state) {
        client->state = state;
        pthread_cond_signal(&(client->state_modified));
    }

    pthread_mutex_unlock(&(client->state_lock));
}

/**
 * Suspends the current thread until the wsthread has been setup to
 * receive connection requests.  Called by vnc connection thread.
 *
 * @param client
 *     The vnc client whose ws_thread should be waited for.
 *
 * @return
 *     Zero in all cases except for error
 */
int guac_vnc_wsthread_state_wait_for_ready(guac_vnc_client *client) {

    pthread_mutex_lock(&client->state_lock);

    while (client->state != GUAC_VNC_VMCONSOLE_READY_FOR_CONNECT) {
        pthread_cond_wait(&client->state_modified, &client->state_lock);
    }

    pthread_mutex_unlock(&client->state_lock);
    return 0;
}

/**
 * Thread to continuously read and write from the ws connection to the
 * VM server and the VNC thread.
 *
 * @param data
 *     Pointer to guac_client from the thread that spawned us.
 *
 * @return
 *     Always NULL.
 */
void* guac_vnc_vmconsole_ws_thread(void* data) {

    guac_client* client = (guac_client*) data;
    guac_vnc_client* vnc_client = (guac_vnc_client*) client->data;
    // guac_vnc_settings* settings = vnc_client->settings;

    /* get the connection from main thread rfb client */
    if (listen(vnc_client->fd_unix_sock, 1) != 0) {
        guac_client_log(client, GUAC_LOG_ERROR,
            "Error listening on unix domain socket with path \"%s\": (%d) %s",
            vnc_client->unix_sock_path, errno, strerror(errno));
        return NULL;
    }

    guac_client_log(client, GUAC_LOG_DEBUG, "ws_thread: ready for connection");
    guac_vnc_wsthread_state_update(vnc_client, GUAC_VNC_VMCONSOLE_READY_FOR_CONNECT);

    struct sockaddr_un addr;
    unsigned int lenaddr = sizeof(addr);
    int fd_client = accept(vnc_client->fd_unix_sock, (struct sockaddr *) &addr, &lenaddr);
    if (fd_client == -1) {
        guac_client_log(client, GUAC_LOG_ERROR,
            "Error accepting connection on unix domain socket with path \"%s\": (%d) %s",
            vnc_client->unix_sock_path, errno, strerror(errno));
        return NULL;
    }
    guac_client_log(client, GUAC_LOG_DEBUG,
        "ws_thread: accepted connection on unix domain socket with path \"%s\"",
        vnc_client->unix_sock_path);

    // enter ws_loop
    int ret = vm_console_ws_loop(client, fd_client);
    if (ret != 0) {
        guac_client_abort(client, GUAC_PROTOCOL_STATUS_UPSTREAM_ERROR,
            "Failure connecting VM server websocket.");
    }
    close(fd_client);
    close(vnc_client->fd_unix_sock);

    guac_client_log(client, GUAC_LOG_DEBUG, "ws_thread exit.");
    return NULL;
}

