/*
 * Copyright 2011 Matteo Mazzarella <matteo@dancingbear.it> 
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
#include <netdb.h>

#include "apr_strings.h"

#include "httpd.h"
#include "http_core.h" 
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h" 


typedef enum {
    DNSBL_ACTION_UNKN,
    DNSBL_ACTION_TEST, 
    DNSBL_ACTION_BLOCK
} dnsbl_action_t;

typedef struct {
    int dnsblcheck;
    int log;
    int env;
    dnsbl_action_t action;
    int methods;
    char *message;
    apr_array_header_t *dnsblhosts;
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

static void *create_config(apr_pool_t *p)
{
    dnsblcheck_cfg *cfg = (dnsblcheck_cfg *)
        apr_pcalloc(p, sizeof(dnsblcheck_cfg));

    cfg->log = 1;
    cfg->env = 1;
    cfg->whitelist = apr_array_make(p, 0, sizeof(allow));
    cfg->dnsblhosts = apr_array_make(p, 0, sizeof(char *));

    return (void *)cfg;
}

static void *dnsblcheck_merge_config(apr_pool_t *p, void *basev, void *addv)
{
    dnsblcheck_cfg *add = (dnsblcheck_cfg *) addv;
    dnsblcheck_cfg *base = (dnsblcheck_cfg *) basev;
    dnsblcheck_cfg *ncfg = (dnsblcheck_cfg *) create_config(p);

    ncfg->dnsblcheck = add->dnsblcheck;
    ncfg->action = (add->action) ? add->action : base->action;
    ncfg->methods = (add->methods) ? add->methods : base->methods;
    ncfg->message = (add->message) ? add->message : base->message;

    ncfg->log = add->log;
    ncfg->env = add->env;

    if (add->dnsblhosts->nelts > 0)
        ncfg->dnsblhosts = apr_array_copy(p, add->dnsblhosts);
    else if (base->dnsblhosts->nelts > 0)
        ncfg->dnsblhosts = apr_array_copy(p, base->dnsblhosts);

    if (add->whitelist->nelts > 0) 
        ncfg->whitelist = apr_array_copy(p, add->whitelist);
    else if (base->whitelist->nelts > 0)
        ncfg->whitelist = apr_array_copy(p, base->whitelist);
 
    return ncfg;
}

static void *dnsblcheck_dir_config(apr_pool_t *p, char *path)
{
    return create_config(p);
}

static int little_chiricahua()
{
    int n = 1;

    return *((char *) &n);
}

/*
 * derived from mod_access
 */
static int in_domain(const char *domain, const char *what)
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
                if (apr_ipsubnet_test(ap[i].x.ip, r->connection->remote_addr)) 
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

static int dnsblcheck_dns(const char *ip, const char *rblhost)
{
    char query[128];
    struct in_addr raddr;
    struct addrinfo *hres = NULL, *p;
    int little, herr, i, ret = 0;
    unsigned char a, b, c, d;

    if (inet_aton(ip, &raddr) == 0) 
        goto done;

    d = (unsigned char)(raddr.s_addr >> 24) & 0xFF;
    c = (unsigned char)(raddr.s_addr >> 16) & 0xFF;
    b = (unsigned char)(raddr.s_addr >> 8) & 0xFF;
    a = (unsigned char)raddr.s_addr & 0xFF;

    if ((little = little_chiricahua()))
        snprintf(query, sizeof(query), "%d.%d.%d.%d.%s",
            d, c, b, a, rblhost);
    else 
        snprintf(query, sizeof(query), "%d.%d.%d.%d.%s",
            a, b, c, d, rblhost);

    if ((herr = getaddrinfo(query, NULL, NULL, &hres)) != 0) {
        ret = 0;
        goto done;
    }
    
    for (p = hres; p != NULL; p = p->ai_next) {
        if (p->ai_family == PF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)
                p->ai_addr;

            a = (unsigned char)
                (sin->sin_addr.s_addr >> ((little) ? 0 : 24)) & 0xff; 
                
            if (a == 0x7f) { 
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

static int dnsblcheck_query(request_rec *r, dnsblcheck_cfg *cfg)
{
    int i;
    apr_status_t sr;
    /* const char *referer = apr_table_get(r->headers_in, "Referer"); */
    apr_uri_t *uri = (apr_uri_t *) apr_pcalloc (r->pool, sizeof (apr_uri_t));

    if (r == NULL || cfg == NULL || !cfg->dnsblcheck || 
        strchr(r->connection->remote_ip, ':'))
        return DECLINED;

    if (cfg->methods != 0 &&
        !(cfg->methods & (AP_METHOD_BIT << r->method_number)))
        return DECLINED;

    if (cfg->whitelist->nelts > 0 && 
        dnsblcheck_whitelist(r, cfg->whitelist, r->method_number))
        return DECLINED;


    if (cfg->dnsblhosts->nelts == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, 
            "DNSBLHosts not defined for %s", r->hostname);
        return DECLINED;
    }

    char **dnsblhosts = (char **)cfg->dnsblhosts->elts;

    for (i = 0; i < cfg->dnsblhosts->nelts; i++) {
        if (!dnsblcheck_dns(r->connection->remote_ip, dnsblhosts[i]))
            continue;

        switch (cfg->action) {
            case DNSBL_ACTION_BLOCK:
                r->content_type = "text/plain";
                ap_custom_response(r, HTTP_FORBIDDEN,
                    cfg->message == NULL ?
                    "Blocked for SPAM" : cfg->message);

                if (cfg->log)
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                        "dnsblcheck: block %s from %s to %s%s querying %s",
                        r->method, r->connection->remote_ip, r->hostname,
                        r->uri, dnsblhosts[i]);

                return HTTP_FORBIDDEN;
            case DNSBL_ACTION_TEST: 
            default:
                if (cfg->env) {
                    apr_table_set(r->subprocess_env, "DNSBL_CHECK", "1");                    
                    apr_table_set(r->subprocess_env, "DNSBL_HOST", 
			dnsblhosts[i]);
                }

                if (cfg->log)
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                        "dnsblcheck: %s from %s to %s%s querying %s",
                        r->method, r->connection->remote_ip,r->hostname,
                        r->uri, dnsblhosts[i]);
        }

        /* break at the first positive result */
        break;
    }

    return OK;
}

static int dnsblcheck_access_handler(request_rec *r)
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
            return "DNSBLCheck value not valid";
    }
    else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, log))
        cfg->log = !strcasecmp(arg, "on");
    else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, env))
        cfg->env = !strcasecmp(arg, "on");
    else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, action)) 
        cfg->action = (strcasecmp(arg, "block") == 0) ? DNSBL_ACTION_BLOCK : 
                                                        DNSBL_ACTION_TEST; 
    else if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, message))
        cfg->message = (char *)apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char *
dnsblcheck_iterate_handler(cmd_parms *cmd, void *dv, const char *v)
{
    dnsblcheck_cfg *cfg = (dnsblcheck_cfg *)dv;

    if (cmd->info == (void *)APR_OFFSETOF(dnsblcheck_cfg, dnsblhosts)) {
        *(char **) apr_array_push(cfg->dnsblhosts) = 
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
    AP_INIT_TAKE1("DNSBLCheck", dnsblcheck_command_handler, 
        (void *)APR_OFFSETOF(dnsblcheck_cfg, dnsblcheck), 
        ACCESS_CONF|RSRC_CONF, 
        "Check request with DNSBL"),

    AP_INIT_TAKE1("DNSBLLog", dnsblcheck_command_handler, 
        (void *)APR_OFFSETOF(dnsblcheck_cfg, log), 
        ACCESS_CONF|RSRC_CONF, 
        "Log requests positive to DNSBLs default: On"),

    AP_INIT_TAKE1("DNSBLEnv", dnsblcheck_command_handler, 
        (void *)APR_OFFSETOF(dnsblcheck_cfg, env), 
        ACCESS_CONF|RSRC_CONF, 
        "Set Environment Variables (if action != blocked) default: On"),

    AP_INIT_TAKE1("DNSBLAction", dnsblcheck_command_handler, 
        (void *)APR_OFFSETOF(dnsblcheck_cfg, action), 
        ACCESS_CONF|RSRC_CONF,
        "Action to perform when positive to DNSBL check"),

    AP_INIT_TAKE1("DNSBLMessage", dnsblcheck_command_handler, 
        (void *)APR_OFFSETOF(dnsblcheck_cfg, message), 
        ACCESS_CONF|RSRC_CONF,
        "Message to show when blocked by DNSBL"),

    AP_INIT_ITERATE("DNSBLHosts", dnsblcheck_iterate_handler,
        (void *)APR_OFFSETOF(dnsblcheck_cfg, dnsblhosts), 
        ACCESS_CONF|RSRC_CONF,
        "DNSBL Servers"),

    AP_INIT_ITERATE("DNSBLMethods", dnsblcheck_iterate_handler, 
        (void *)APR_OFFSETOF(dnsblcheck_cfg, methods), 
        ACCESS_CONF|RSRC_CONF, 
        "Check only these methods"),

    AP_INIT_ITERATE("DNSBLWhitelist", dnsblcheck_iterate_handler, 
        (void *)APR_OFFSETOF(dnsblcheck_cfg, whitelist),
        ACCESS_CONF|RSRC_CONF, 
        "IP / domains / env whitelist"),

    {NULL}
};

static void register_hooks(apr_pool_t * p)
{
    ap_hook_access_checker(dnsblcheck_access_handler, NULL, NULL,
        APR_HOOK_MIDDLE);
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
