/*
 * Copyright 2011-2025 Matteo Mazzarella <matteo@dharma.dancingbear.it>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <netdb.h>

#include "apr_strings.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"


typedef enum {
    DNSBL_ACTION_UNKN,
    DNSBL_ACTION_ENV,
    DNSBL_ACTION_BLOCK
} dnsbl_action_t;

typedef struct {
    int dnsblcheck;
    dnsbl_action_t action;
    int methods;
    int status;
    char *message;
    apr_array_header_t *dnsblprefix;
    apr_array_header_t *whitelist;
} dnsblcheck_cfg;

typedef enum {
    DNSBL_WL_UNKN,
    DNSBL_WL_ENV,
    DNSBL_WL_ALL,
    DNSBL_WL_IP,
    DNSBL_WL_HOST
} dnsbl_wl_type;

/* derived from mod_access */
typedef struct {
    union {
        char *from;
        apr_ipsubnet_t *ip;
    } x;
    dnsbl_wl_type type;
} allow;

module AP_MODULE_DECLARE_DATA dnsblcheck_module;

static void *
create_config(apr_pool_t *p)
{
    dnsblcheck_cfg *cfg = (dnsblcheck_cfg *)
                          apr_pcalloc(p, sizeof(dnsblcheck_cfg));

    cfg->whitelist = apr_array_make(p, 0, sizeof(allow));
    cfg->dnsblprefix = apr_array_make(p, 0, sizeof(char *));
    cfg->status = HTTP_FORBIDDEN;

    return (void *)cfg;
}

static void *
dnsblcheck_merge_config(apr_pool_t *p, void *basev, void *addv)
{
    dnsblcheck_cfg *add = (dnsblcheck_cfg *) addv;
    dnsblcheck_cfg *base = (dnsblcheck_cfg *) basev;
    dnsblcheck_cfg *ncfg = (dnsblcheck_cfg *) create_config(p);

    ncfg->dnsblcheck = add->dnsblcheck;
    ncfg->action = (add->action) ? add->action : base->action;
    ncfg->status = (add->status) ? add->status : base->status;
    ncfg->methods = (add->methods) ? add->methods : base->methods;
    ncfg->message = (add->message) ? add->message : base->message;

    if (add->dnsblprefix->nelts > 0)
        ncfg->dnsblprefix = apr_array_copy(p, add->dnsblprefix);
    else if (base->dnsblprefix->nelts > 0)
        ncfg->dnsblprefix = apr_array_copy(p, base->dnsblprefix);

    if (add->whitelist->nelts > 0)
        ncfg->whitelist = apr_array_copy(p, add->whitelist);
    else if (base->whitelist->nelts > 0)
        ncfg->whitelist = apr_array_copy(p, base->whitelist);

    return ncfg;
}

static void *
dnsblcheck_dir_config(apr_pool_t *p, char *path)
{
    return create_config(p);
}

/*
 * derived from mod_access
 */
static int
in_domain(const char *domain, const char *what)
{
    int dl = strlen(domain);
    int wl = strlen(what);

    if ((wl - dl) >= 0) {
        if (strcasecmp(domain, &what[wl - dl]) != 0)
            return 0;

        return (wl == dl) ? 1 : (domain[0] == '.' || what[wl - dl - 1] == '.');
    }

    return 0;
}

static int
dnsblcheck_whitelist(request_rec *r, apr_array_header_t *a, int method)
{
    allow *ap = (allow *) a->elts;
    const char *remotehost = NULL;
    int gothost = 0;
    int i;

    for (i=0; i < a->nelts; i++) {
        switch (ap[i].type) {
        case DNSBL_WL_ENV:
            if (apr_table_get(r->subprocess_env, ap[i].x.from))
                return 1;
            break;
        case DNSBL_WL_ALL:
            return 1;
        case DNSBL_WL_IP:
            if (apr_ipsubnet_test(ap[i].x.ip, r->connection->client_addr))
                return 1;
            break;
        case DNSBL_WL_HOST:
            if (!gothost) {
                int remotehost_is_ip;

                remotehost = ap_get_remote_host(r->connection,
                                                r->per_dir_config, REMOTE_DOUBLE_REV,
                                                &remotehost_is_ip);

                gothost = (remotehost == NULL || remotehost_is_ip) ? 1 : 2;
            }

            if ((gothost == 2) && in_domain(ap[i].x.from, remotehost))
                return 1;
        }
    }

    return 0;
}

static int
reverse_ipv6(const char *ipv6, char *output, size_t output_size)
{
    struct in6_addr addr6;

    if (inet_pton(AF_INET6, ipv6, &addr6) != 1)
        return -1;

    char *ptr = output;
    size_t remaining = output_size;

    for (int i = 15; i >= 0; i--) {
        int written = snprintf(ptr, remaining, "%x.%x.", addr6.s6_addr[i] & 0x0F, (addr6.s6_addr[i] >> 4) & 0x0F);
        if (written < 0 || written >= remaining) {
            return -1;
        }
        ptr += written;
        remaining -= written;
    }

    return 0;
}

static int
dnsblcheck_dns(const char *ip, const char *prefix)
{
    char query[1024];
    struct addrinfo *hres = NULL, *p;
    int herr, ret = 0;

    struct in_addr raddr;
    if (inet_aton(ip, &raddr)) {
        unsigned char a, b, c, d;
        d = (unsigned char)(raddr.s_addr >> 24) & 0xFF;
        c = (unsigned char)(raddr.s_addr >> 16) & 0xFF;
        b = (unsigned char)(raddr.s_addr >> 8) & 0xFF;
        a = (unsigned char)raddr.s_addr & 0xFF;

        snprintf(query, sizeof(query), "%d.%d.%d.%d.%s",
                 d, c, b, a, prefix);

    }
    else if (strchr(ip, ':')) {
        char reversed[1024];
        if (reverse_ipv6(ip, reversed, sizeof(reversed)) != 0)
            return 0;

        snprintf(query, sizeof(query), "%s%s", reversed, prefix);
    }
    else {
        return 0;
    }

    if ((herr = getaddrinfo(query, NULL, NULL, &hres)) != 0) {
        ret = 0;
        goto done;
    }

    for (p = hres; p != NULL; p = p->ai_next) {
        if (p->ai_family == PF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
            uint32_t ip = ntohl(sin->sin_addr.s_addr);
            unsigned char a = (ip >> 24) & 0xFF;

            if (a == 127) {
                ret = 1;
                break;
            }
        }
    }

done:
    if (hres != NULL)
        freeaddrinfo(hres);

    return ret;
}

static int
dnsblcheck_query(request_rec *r, dnsblcheck_cfg *cfg)
{
    int i;
    int matched_dnsbl = 0;
    apr_status_t sr;
    /* const char *referer = apr_table_get(r->headers_in, "Referer"); */
    apr_uri_t *uri = (apr_uri_t *) apr_pcalloc (r->pool, sizeof (apr_uri_t));

    if (r == NULL || cfg == NULL || !cfg->dnsblcheck)
        return DECLINED;

    if (cfg->methods != 0 &&
            !(cfg->methods & (AP_METHOD_BIT << r->method_number)))
        return DECLINED;

    if (cfg->whitelist->nelts > 0 &&
            dnsblcheck_whitelist(r, cfg->whitelist, r->method_number))
        return DECLINED;

    if (cfg->dnsblprefix->nelts == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "DNSBLPrefix not defined for %s", r->hostname);
        return DECLINED;
    }

    char **dnsblprefix = (char **)cfg->dnsblprefix->elts;
    char *dnsbleprefix = NULL;
    char *dnsblematched = NULL;

    for (i = 0; i < cfg->dnsblprefix->nelts; i++) {
        int matched = dnsblcheck_dns(r->connection->client_ip, dnsblprefix[i]);

        if (cfg->action == DNSBL_ACTION_BLOCK && matched) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                          "dnsblcheck: block %s from %s to %s%s querying %s",
                          r->method, r->connection->client_ip, r->hostname,
                          r->uri, dnsblprefix[i]);

            if (cfg->message != NULL) {
                r->content_type = "text/plain";
                ap_custom_response(r, cfg->status, cfg->message);
            }

            return cfg->status;
        }

        switch (cfg->action) {
        case DNSBL_ACTION_ENV:
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                          "dnsblcheck: %s from %s to %s%s querying %s: %s",
                          r->method, r->connection->client_ip, r->hostname,
                          r->uri, dnsblprefix[i], matched ? "matched" : "not matched");

            if (matched) {
                dnsblematched = (dnsblematched) ? \
                                apr_pstrcat(r->pool, dnsblematched, " ", dnsblprefix[i],
                                            NULL) : \
                                apr_pstrcat(r->pool, dnsblprefix[i], NULL);
            }

            dnsbleprefix = (dnsbleprefix) ? \
                           apr_pstrcat(r->pool, dnsbleprefix, " ", dnsblprefix[i],
                                       NULL) : \
                           apr_pstrcat(r->pool, dnsblprefix[i], NULL);

            if (i == cfg->dnsblprefix->nelts-1) {
                apr_table_set(r->subprocess_env, "DNSBL_MATCH",
                              dnsblematched);
                apr_table_set(r->subprocess_env, "DNSBL_PREFIX",
                              dnsbleprefix);
            }

            break;
        }
    }

    return OK;
}

static int
dnsblcheck_access_handler(request_rec *r)
{
    dnsblcheck_cfg *cfg = (dnsblcheck_cfg *)
                          ap_get_module_config(r->per_dir_config, &dnsblcheck_module);

    return dnsblcheck_query(r, cfg);
}

static const char *
dnsblcheck_command_handler(cmd_parms *cmd, void *dv, const char *arg)
{
    dnsblcheck_cfg *cfg = (dnsblcheck_cfg *) dv;

    if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, dnsblcheck)) {
        if (!(cfg->dnsblcheck= !strcasecmp(arg, "on")) &&
                strcasecmp(arg, "off"))
            return "DNSBLEngine value not valid";
    }
    else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, action))
        cfg->action = (strcasecmp(arg, "block") == 0) ? DNSBL_ACTION_BLOCK :
                      DNSBL_ACTION_ENV;
    else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, message))
        cfg->message = (char *)apr_pstrdup(cmd->pool, arg);
    else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, status)) {
        const char *p = arg;

        while (*p)
            if (!isdigit(*p++))
                return "Argument must be numeric";

        cfg->status = atoi(arg);
    }

    return NULL;
}

static const char *
dnsblcheck_iterate_handler(cmd_parms *cmd, void *dv, const char *v)
{
    dnsblcheck_cfg *cfg = (dnsblcheck_cfg *)dv;

    if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, dnsblprefix)) {
        *(char **) apr_array_push(cfg->dnsblprefix) =
            (char *)apr_pstrdup(cmd->pool, v);
    } else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, methods)) {
        int m = 0;

        if ((m = ap_method_number_of(v)) == M_INVALID)
            return (char *)apr_pstrcat(cmd->pool, "Invalid Method ", v, NULL);

        cfg->methods |= (AP_METHOD_BIT << m);
    } else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, whitelist)) {
        char msgbuf[120];
        apr_status_t rv;
        char *s;

        char *where = (char *) apr_pstrdup(cmd->pool, v);
        allow *a = (allow *) apr_array_push(cfg->whitelist);

        a->x.from = where;

        if (strncasecmp(where, "env=", 4) == 0) {
            a->type = DNSBL_WL_ENV;
            a->x.from += 4;
        }
        else if (strcasecmp(where, "all") == 0)
            a->type = DNSBL_WL_ALL;
        else if ((s = strchr(where, '/'))) {
            *s++ = '\0';

            rv = apr_ipsubnet_create(&a->x.ip, where, s, cmd->pool);
            if (APR_STATUS_IS_EINVAL(rv))
                return "IP Address was expected";
            else if (rv != APR_SUCCESS) {
                apr_strerror(rv, msgbuf, sizeof msgbuf);
                return (char *)apr_pstrdup(cmd->pool, msgbuf);
            }

            /* success */
            a->type = DNSBL_WL_IP;
        }
        else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&a->x.ip,
                                            where, NULL, cmd->pool))) {
            if (rv != APR_SUCCESS) {
                apr_strerror(rv, msgbuf, sizeof msgbuf);
                return (char *)apr_pstrdup(cmd->pool, msgbuf);
            }

            a->type = DNSBL_WL_IP;
        }
        else
            a->type = DNSBL_WL_HOST;
    }

    return NULL;
}


static const command_rec dnsblcheck_cmds[] =
{
    AP_INIT_FLAG("DNSBLEngine", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(dnsblcheck_cfg, dnsblcheck),
                 ACCESS_CONF|RSRC_CONF,
                 "Check request with DNSBL"),

    AP_INIT_TAKE1("DNSBLAction", dnsblcheck_command_handler,
                  (void *)APR_OFFSETOF(dnsblcheck_cfg, action),
                  ACCESS_CONF|RSRC_CONF,
                  "Action to perform when positive to DNSBL check"),

    AP_INIT_TAKE1("DNSBLMessage", dnsblcheck_command_handler,
                  (void *)APR_OFFSETOF(dnsblcheck_cfg, message),
                  ACCESS_CONF|RSRC_CONF,
                  "Message to show when blocked by DNSBL"),

    AP_INIT_TAKE1("DNSBLHttpStatus", dnsblcheck_command_handler,
                  (void *)APR_OFFSETOF(dnsblcheck_cfg, status),
                  ACCESS_CONF|RSRC_CONF,
                  "HTTP Status  when blocked by DNSBL"),

    AP_INIT_ITERATE("DNSBLPrefix", dnsblcheck_iterate_handler,
                    (void *)APR_OFFSETOF(dnsblcheck_cfg, dnsblprefix),
                    ACCESS_CONF|RSRC_CONF,
                    "DNSBL Servers"),

    AP_INIT_ITERATE("DNSBLTestMethods", dnsblcheck_iterate_handler,
                    (void *)APR_OFFSETOF(dnsblcheck_cfg, methods),
                    ACCESS_CONF|RSRC_CONF,
                    "Check only these methods"),

    AP_INIT_ITERATE("DNSBLWhitelist", dnsblcheck_iterate_handler,
                    (void *)APR_OFFSETOF(dnsblcheck_cfg, whitelist),
                    ACCESS_CONF|RSRC_CONF,
                    "IP / domains / env whitelist"),

    {NULL}
};

static int dnsblcheck_access_ex(request_rec *r)
{
    dnsblcheck_cfg *cfg =
        ap_get_module_config(r->per_dir_config, &dnsblcheck_module);
    return dnsblcheck_query(r, cfg);
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_access_ex(dnsblcheck_access_ex,
                            NULL,
                            NULL,
                            APR_HOOK_MIDDLE,
                            AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA dnsblcheck_module=
{
    STANDARD20_MODULE_STUFF,
    dnsblcheck_dir_config,      /* dir config creater */
    dnsblcheck_merge_config,    /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    dnsblcheck_cmds,            /* command apr_table_t */
    register_hooks              /* register hooks */
};
