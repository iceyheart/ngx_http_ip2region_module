#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "xdb_api.h"

/* --- 字段索引定义 ---
 * 新版 xdb 数据格式: 国家|省份|城市|ISP|iso-3166-alpha2-code
 * 字段索引:            0    1    2    3    4
 */
#define IP2REGION_FIELD_COUNTRY 0
#define IP2REGION_FIELD_PROVINCE 1
#define IP2REGION_FIELD_CITY 2
#define IP2REGION_FIELD_ISP 3
#define IP2REGION_FIELD_COUNTRY_CODE 4
#define IP2REGION_FIELD_COUNT 5

typedef struct {
  ngx_str_t db_file;           /* IPv4 xdb 文件路径 */
  ngx_str_t db_file_v6;        /* IPv6 xdb 文件路径 */
  xdb_searcher_t *searcher;    /* IPv4 搜索器 */
  xdb_searcher_t *searcher_v6; /* IPv6 搜索器 */
  xdb_content_t *content;      /* IPv4 文件内容缓存 */
  xdb_content_t *content_v6;   /* IPv6 文件内容缓存 */
} ngx_http_ip2region_conf_t;

static void *ngx_http_ip2region_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2region_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2region_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2region_variable(ngx_http_request_t *r,
                                             ngx_http_variable_value_t *v,
                                             uintptr_t data);
static ngx_int_t ngx_http_ip2region_field_variable(ngx_http_request_t *r,
                                                   ngx_http_variable_value_t *v,
                                                   uintptr_t data);
static void ngx_http_ip2region_cleanup(void *data);

/* 内部辅助函数 */
static ngx_int_t ngx_http_ip2region_lookup(ngx_http_request_t *r,
                                           u_char **result, size_t *result_len);
static ngx_int_t ngx_http_ip2region_extract_field(ngx_http_request_t *r,
                                                  u_char *region,
                                                  size_t region_len,
                                                  int field_index, u_char **out,
                                                  size_t *out_len);

static ngx_command_t ngx_http_ip2region_commands[] = {
    {ngx_string("ip2region_db_file"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_ip2region_conf_t, db_file), NULL},

    {ngx_string("ip2region_db_file_v6"), NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_ip2region_conf_t, db_file_v6), NULL},

    ngx_null_command};

static ngx_http_variable_t ngx_http_ip2region_vars[] = {
    /* 完整地理信息字符串 */
    {ngx_string("ip2region"), NULL, ngx_http_ip2region_variable, 0, 0, 0},

    /* 独立字段变量 */
    {ngx_string("ip2region_country"), NULL, ngx_http_ip2region_field_variable,
     IP2REGION_FIELD_COUNTRY, 0, 0},

    {ngx_string("ip2region_province"), NULL, ngx_http_ip2region_field_variable,
     IP2REGION_FIELD_PROVINCE, 0, 0},

    {ngx_string("ip2region_city"), NULL, ngx_http_ip2region_field_variable,
     IP2REGION_FIELD_CITY, 0, 0},

    {ngx_string("ip2region_isp"), NULL, ngx_http_ip2region_field_variable,
     IP2REGION_FIELD_ISP, 0, 0},

    {ngx_string("ip2region_country_code"), NULL,
     ngx_http_ip2region_field_variable, IP2REGION_FIELD_COUNTRY_CODE, 0, 0},

    ngx_http_null_variable};

static ngx_http_module_t ngx_http_ip2region_module_ctx = {
    ngx_http_ip2region_add_variables,
    ngx_http_ip2region_init,
    ngx_http_ip2region_create_conf,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL};

ngx_module_t ngx_http_ip2region_module = {NGX_MODULE_V1,
                                          &ngx_http_ip2region_module_ctx,
                                          ngx_http_ip2region_commands,
                                          NGX_HTTP_MODULE,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NGX_MODULE_V1_PADDING};

/*
 * 核心查找函数：根据客户端 IP 地址族（IPv4/IPv6）选择对应搜索器进行查询
 * 返回 NGX_OK 表示成功，result 和 result_len 包含结果
 * 返回 NGX_DECLINED 表示未找到或不支持
 */
static ngx_int_t ngx_http_ip2region_lookup(ngx_http_request_t *r,
                                           u_char **result,
                                           size_t *result_len) {
  ngx_http_ip2region_conf_t *conf;
  xdb_region_buffer_t region;
  char region_buf[1024];
  int err;
  size_t real_len;
  xdb_searcher_t *searcher;

  conf = ngx_http_get_module_main_conf(r, ngx_http_ip2region_module);

  if (conf == NULL) {
    return NGX_DECLINED;
  }

  if (xdb_region_buffer_init(&region, region_buf, sizeof(region_buf)) != 0) {
    return NGX_DECLINED;
  }

  if (r->connection->sockaddr->sa_family == AF_INET) {
    /* IPv4 查询 */
    struct sockaddr_in *sin;
    bytes_ip_t ip_bytes[4];

    searcher = conf->searcher;
    if (searcher == NULL) {
      xdb_region_buffer_free(&region);
      return NGX_DECLINED;
    }

    sin = (struct sockaddr_in *)r->connection->sockaddr;
    memcpy(ip_bytes, &sin->sin_addr.s_addr, 4);

    err = xdb_search(searcher, ip_bytes, 4, &region);

  } else if (r->connection->sockaddr->sa_family == AF_INET6) {
    /* IPv6 查询 */
    struct sockaddr_in6 *sin6;
    bytes_ip_t ip_bytes[16];

    searcher = conf->searcher_v6;
    if (searcher == NULL) {
      xdb_region_buffer_free(&region);
      return NGX_DECLINED;
    }

    sin6 = (struct sockaddr_in6 *)r->connection->sockaddr;
    memcpy(ip_bytes, sin6->sin6_addr.s6_addr, 16);

    err = xdb_search(searcher, ip_bytes, 16, &region);

  } else {
    /* 不支持的地址族 */
    xdb_region_buffer_free(&region);
    return NGX_DECLINED;
  }

  if (err == 0 && region.value != NULL) {
    real_len = ngx_strlen(region.value);

    if (real_len > 0) {
      *result = ngx_pnalloc(r->pool, real_len);
      if (*result == NULL) {
        xdb_region_buffer_free(&region);
        return NGX_ERROR;
      }
      ngx_memcpy(*result, region.value, real_len);
      *result_len = real_len;
      xdb_region_buffer_free(&region);
      return NGX_OK;
    }
  }

  xdb_region_buffer_free(&region);
  return NGX_DECLINED;
}

/*
 * 从完整 region 字符串中提取指定字段
 * region 格式: 国家|省份|城市|ISP|iso-3166-alpha2-code
 */
static ngx_int_t ngx_http_ip2region_extract_field(ngx_http_request_t *r,
                                                  u_char *region,
                                                  size_t region_len,
                                                  int field_index, u_char **out,
                                                  size_t *out_len) {
  u_char *p, *start, *end;
  int current_field;

  if (region == NULL || region_len == 0 || field_index < 0 ||
      field_index >= IP2REGION_FIELD_COUNT) {
    return NGX_DECLINED;
  }

  p = region;
  end = region + region_len;
  start = p;
  current_field = 0;

  while (p <= end) {
    if (p == end || *p == '|') {
      if (current_field == field_index) {
        *out_len = p - start;

        if (*out_len == 0) {
          return NGX_DECLINED;
        }

        *out = ngx_pnalloc(r->pool, *out_len);
        if (*out == NULL) {
          return NGX_ERROR;
        }
        ngx_memcpy(*out, start, *out_len);
        return NGX_OK;
      }
      current_field++;
      start = p + 1;
    }
    p++;
  }

  return NGX_DECLINED;
}

/*
 * $ip2region 变量处理函数 - 返回完整的地理信息字符串
 */
static ngx_int_t ngx_http_ip2region_variable(ngx_http_request_t *r,
                                             ngx_http_variable_value_t *v,
                                             uintptr_t data) {
  u_char *result;
  size_t result_len;
  ngx_int_t rc;

  rc = ngx_http_ip2region_lookup(r, &result, &result_len);

  if (rc == NGX_OK) {
    v->len = result_len;
    v->data = result;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
  }

  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  v->not_found = 1;
  return NGX_OK;
}

/*
 * $ip2region_country 等独立字段变量处理函数
 * data 参数为字段索引（IP2REGION_FIELD_*）
 */
static ngx_int_t ngx_http_ip2region_field_variable(ngx_http_request_t *r,
                                                   ngx_http_variable_value_t *v,
                                                   uintptr_t data) {
  u_char *result, *field;
  size_t result_len, field_len;
  ngx_int_t rc;

  rc = ngx_http_ip2region_lookup(r, &result, &result_len);

  if (rc == NGX_OK) {
    rc = ngx_http_ip2region_extract_field(r, result, result_len, (int)data,
                                          &field, &field_len);
    if (rc == NGX_OK) {
      v->len = field_len;
      v->data = field;
      v->valid = 1;
      v->no_cacheable = 0;
      v->not_found = 0;
      return NGX_OK;
    }

    if (rc == NGX_ERROR) {
      return NGX_ERROR;
    }
  }

  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  v->not_found = 1;
  return NGX_OK;
}

static ngx_int_t ngx_http_ip2region_add_variables(ngx_conf_t *cf) {
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

static ngx_int_t ngx_http_ip2region_init(ngx_conf_t *cf) {
  ngx_http_ip2region_conf_t *conf;
  ngx_pool_cleanup_t *cln;
  int err;

  conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2region_module);

  if (conf->db_file.len == 0 && conf->db_file_v6.len == 0) {
    return NGX_OK;
  }

  /* --- 加载 IPv4 数据库 --- */
  if (conf->db_file.len > 0) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "ip2region: loading IPv4 db file: %V", &conf->db_file);

    conf->content = xdb_load_content_from_file((char *)conf->db_file.data);
    if (conf->content == NULL) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "ip2region: failed to load IPv4 db file: %V",
                    &conf->db_file);
      return NGX_ERROR;
    }

    conf->searcher = ngx_palloc(cf->pool, sizeof(xdb_searcher_t));
    if (conf->searcher == NULL) {
      xdb_free_content(conf->content);
      conf->content = NULL;
      return NGX_ERROR;
    }

    err = xdb_new_with_buffer(XDB_IPv4, conf->searcher, conf->content);
    if (err != 0) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "ip2region: xdb_new_with_buffer (IPv4) failed: %d", err);
      xdb_free_content(conf->content);
      conf->content = NULL;
      return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "ip2region: IPv4 searcher initialized successfully");
  }

  /* --- 加载 IPv6 数据库 --- */
  if (conf->db_file_v6.len > 0) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "ip2region: loading IPv6 db file: %V", &conf->db_file_v6);

    conf->content_v6 =
        xdb_load_content_from_file((char *)conf->db_file_v6.data);
    if (conf->content_v6 == NULL) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "ip2region: failed to load IPv6 db file: %V",
                    &conf->db_file_v6);
      return NGX_ERROR;
    }

    conf->searcher_v6 = ngx_palloc(cf->pool, sizeof(xdb_searcher_t));
    if (conf->searcher_v6 == NULL) {
      xdb_free_content(conf->content_v6);
      conf->content_v6 = NULL;
      return NGX_ERROR;
    }

    err = xdb_new_with_buffer(XDB_IPv6, conf->searcher_v6, conf->content_v6);
    if (err != 0) {
      ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "ip2region: xdb_new_with_buffer (IPv6) failed: %d", err);
      xdb_free_content(conf->content_v6);
      conf->content_v6 = NULL;
      return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "ip2region: IPv6 searcher initialized successfully");
  }

  /* 日志汇总 */
  ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                "ip2region: module initialized (IPv4: %s, IPv6: %s)",
                conf->searcher != NULL ? "enabled" : "disabled",
                conf->searcher_v6 != NULL ? "enabled" : "disabled");

  /* 注册清理回调 */
  cln = ngx_pool_cleanup_add(cf->pool, 0);
  if (cln == NULL) {
    if (conf->searcher != NULL) {
      xdb_close(conf->searcher);
    }
    if (conf->content != NULL) {
      xdb_free_content(conf->content);
    }
    if (conf->searcher_v6 != NULL) {
      xdb_close(conf->searcher_v6);
    }
    if (conf->content_v6 != NULL) {
      xdb_free_content(conf->content_v6);
    }
    return NGX_ERROR;
  }

  cln->handler = ngx_http_ip2region_cleanup;
  cln->data = conf;

  return NGX_OK;
}

static void ngx_http_ip2region_cleanup(void *data) {
  ngx_http_ip2region_conf_t *conf = data;

  if (conf->searcher != NULL) {
    xdb_close(conf->searcher);
  }

  if (conf->content != NULL) {
    xdb_free_content(conf->content);
  }

  if (conf->searcher_v6 != NULL) {
    xdb_close(conf->searcher_v6);
  }

  if (conf->content_v6 != NULL) {
    xdb_free_content(conf->content_v6);
  }
}

static void *ngx_http_ip2region_create_conf(ngx_conf_t *cf) {
  ngx_http_ip2region_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2region_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  return conf;
}
