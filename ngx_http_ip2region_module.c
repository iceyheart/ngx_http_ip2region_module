#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "xdb_api.h"

typedef struct {
    ngx_str_t           db_file;
    xdb_searcher_t      *searcher;
    xdb_content_t       *content;
} ngx_http_ip2region_conf_t;

static void *ngx_http_ip2region_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2region_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2region_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2region_variable(ngx_http_request_t *r, 
                                              ngx_http_variable_value_t *v, 
                                              uintptr_t data);
static void ngx_http_ip2region_cleanup(void *data);

static ngx_command_t ngx_http_ip2region_commands[] = {
    { ngx_string("ip2region_db_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ip2region_conf_t, db_file),
      NULL },
    ngx_null_command
};

static ngx_http_variable_t ngx_http_ip2region_vars[] = {
    { ngx_string("ip2region"), NULL, ngx_http_ip2region_variable, 0, 0, 0 },
    ngx_http_null_variable
};

static ngx_http_module_t ngx_http_ip2region_module_ctx = {
    ngx_http_ip2region_add_variables,
    ngx_http_ip2region_init,
    ngx_http_ip2region_create_conf,
    NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_ip2region_module = {
    NGX_MODULE_V1,
    &ngx_http_ip2region_module_ctx,
    ngx_http_ip2region_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_ip2region_variable(ngx_http_request_t *r, 
                           ngx_http_variable_value_t *v, 
                           uintptr_t data)
{
    ngx_http_ip2region_conf_t  *conf;
    struct sockaddr_in         *sin;
    xdb_region_buffer_t         region;
    char                        region_buf[512];
    bytes_ip_t                  ip_bytes[4];
    int                         err;
    size_t                      real_len;
    
    conf = ngx_http_get_module_main_conf(r, ngx_http_ip2region_module);
    
    if (conf == NULL || conf->searcher == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }
    
    // 只支持 IPv4
    if (r->connection->sockaddr->sa_family != AF_INET) {
        v->not_found = 1;
        return NGX_OK;
    }
    
    if (xdb_region_buffer_init(&region, region_buf, sizeof(region_buf)) != 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    memcpy(ip_bytes, &sin->sin_addr.s_addr, 4);
    
    err = xdb_search(conf->searcher, ip_bytes, 4, &region);
    if (err == 0 && region.value != NULL) {
        real_len = ngx_strlen(region.value);
        
        if (real_len > 0) {
            v->len = real_len;
            v->data = ngx_pnalloc(r->pool, v->len);
            if (v->data == NULL) {
                xdb_region_buffer_free(&region);
                return NGX_ERROR;
            }
            ngx_memcpy(v->data, region.value, v->len);
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            xdb_region_buffer_free(&region);
            return NGX_OK;
        }
    }
    
    xdb_region_buffer_free(&region);
    v->not_found = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_http_ip2region_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;
    
    for (v = ngx_http_ip2region_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_ip2region_init(ngx_conf_t *cf)
{
    ngx_http_ip2region_conf_t *conf;
    ngx_pool_cleanup_t *cln;
    int err;
    
    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2region_module);
    
    if (conf->db_file.len == 0) {
        return NGX_OK;
    }
    
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                 "ip2region: loading IPv4 db file: %V", &conf->db_file);
    
    conf->content = xdb_load_content_from_file((char *)conf->db_file.data);
    if (conf->content == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                     "ip2region: failed to load db file: %V", &conf->db_file);
        return NGX_ERROR;
    }
    
    conf->searcher = ngx_palloc(cf->pool, sizeof(xdb_searcher_t));
    if (conf->searcher == NULL) {
        xdb_free_content(conf->content);
        return NGX_ERROR;
    }
    
    err = xdb_new_with_buffer(XDB_IPv4, conf->searcher, conf->content);
    if (err != 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                     "ip2region: xdb_new_with_buffer failed: %d", err);
        xdb_free_content(conf->content);
        return NGX_ERROR;
    }
    
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                 "ip2region: module initialized successfully (IPv4 only)");
    
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        xdb_close(conf->searcher);
        xdb_free_content(conf->content);
        return NGX_ERROR;
    }
    
    cln->handler = ngx_http_ip2region_cleanup;
    cln->data = conf;
    
    return NGX_OK;
}

static void
ngx_http_ip2region_cleanup(void *data)
{
    ngx_http_ip2region_conf_t *conf = data;
    
    if (conf->searcher != NULL) {
        xdb_close(conf->searcher);
    }
    
    if (conf->content != NULL) {
        xdb_free_content(conf->content);
    }
}

static void *
ngx_http_ip2region_create_conf(ngx_conf_t *cf)
{
    ngx_http_ip2region_conf_t *conf;
    
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2region_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    return conf;
}
