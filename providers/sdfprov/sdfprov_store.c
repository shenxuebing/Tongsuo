/*
 * SDF Provider STORE - 从 SDF 设备加载硬件密钥
 *
 * URI 格式（兼容老 Engine）:
 *   "sdf:<algo>:<index>:<type>[:<pwd>]"
 *   例如: "sdf:sm2:0:sign"             - SM2 索引0 签名密钥
 *         "sdf:sm2:0:enc:11111111"      - SM2 索引0 加密密钥，口令 11111111
 *         "sdf:rsa:1:sign:mypwd"        - RSA  索引1 签名密钥，口令 mypwd
 *
 * URI 格式（key=value 风格）:
 *   "sdf:key=<index>;type=<sign|enc>[;algo=<sm2|rsa>][;pwd=<password>]"
 *   例如: "sdf:key=0;type=sign"
 *         "sdf:key=0;type=enc;algo=sm2;pwd=11111111"
 *
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/ec.h>
#include <openssl/sdf.h>
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "sdfprov_utils.h"
#include "sdfprov_ctx.h"

typedef struct {
    void *provctx;
    OSSL_LIB_CTX *libctx;
    char *uri;
    int loaded;
    unsigned int key_index;
    int key_type;               /* 0=sign, 1=enc */
    int algo;                   /* SDF_ALGO_SM2 / SDF_ALGO_RSA */
    char *key_password;         /* 私钥访问控制码 */
} SDFPROV_STORE_CTX;

/*
 * 解析老 Engine 格式: "sdf:sm2:0:sign[:pwd]"
 */
static int parse_sdf_uri_oldfmt(const char *p, unsigned int *key_index,
                                 int *key_type, int *algo, char **key_password)
{
    char *endp;

    /* 解析算法: sm2 或 rsa */
    if (strncmp(p, "sm2:", 4) == 0) {
        *algo = SDF_ALGO_SM2;
        p += 4;
    } else if (strncmp(p, "rsa:", 4) == 0) {
        *algo = SDF_ALGO_RSA;
        p += 4;
    } else {
        return 0;
    }

    /* 解析索引 */
    *key_index = (unsigned int)strtoul(p, &endp, 10);
    if (*endp != ':')
        return 0;
    p = endp + 1;

    /* 解析类型: sign 或 enc */
    if (strncmp(p, "sign", 4) == 0) {
        *key_type = 0;
        p += 4;
    } else if (strncmp(p, "enc", 3) == 0) {
        *key_type = 1;
        p += 3;
    } else {
        return 0;
    }

    /* 解析可选的口令 */
    if (*p == ':') {
        p++;
        if (*p != '\0')
            *key_password = OPENSSL_strdup(p);
    }

    return 1;
}

/*
 * 解析 key=value 格式: "key=0;type=sign[;algo=sm2][;pwd=xxx]"
 */
static int parse_sdf_uri_kvfmt(const char *p, unsigned int *key_index,
                                int *key_type, int *algo, char **key_password)
{
    *algo = SDF_ALGO_SM2;  /* 默认 SM2 */
    *key_type = 0;
    *key_password = NULL;

    /* 解析 key=<index> */
    if (strncmp(p, "key=", 4) != 0)
        return 0;

    {
        char *endp;
        *key_index = (unsigned int)strtoul(p + 4, &endp, 10);
        p = endp;
    }

    /* 解析后续参数 */
    while (*p == ';' || *p == '&') {
        p++;
        if (strncmp(p, "type=", 5) == 0) {
            p += 5;
            if (strncmp(p, "sign", 4) == 0 || strncmp(p, "0", 1) == 0) {
                *key_type = 0;
                p += (strncmp(p, "sign", 4) == 0) ? 4 : 1;
            } else if (strncmp(p, "enc", 3) == 0 || strncmp(p, "1", 1) == 0) {
                *key_type = 1;
                p += (strncmp(p, "enc", 3) == 0) ? 3 : 1;
            } else {
                return 0;
            }
        } else if (strncmp(p, "algo=", 5) == 0) {
            p += 5;
            if (strncmp(p, "sm2", 3) == 0) {
                *algo = SDF_ALGO_SM2;
                p += 3;
            } else if (strncmp(p, "rsa", 3) == 0) {
                *algo = SDF_ALGO_RSA;
                p += 3;
            } else {
                return 0;
            }
        } else if (strncmp(p, "pwd=", 4) == 0) {
            const char *start = p + 4;
            const char *end = start;
            while (*end != '\0' && *end != ';' && *end != '&')
                end++;
            *key_password = OPENSSL_strndup(start, end - start);
            p = end;
        } else {
            while (*p != '\0' && *p != ';' && *p != '&')
                p++;
        }
    }

    return (*p == '\0');
}

/*
 * 解析 URI，自动检测格式
 * 老格式: "sdf:sm2:0:sign[:pwd]"
 * 新格式: "sdf:key=0;type=sign[;algo=sm2][;pwd=xxx]"
 */
static int parse_sdf_uri(const char *uri, unsigned int *key_index,
                          int *key_type, int *algo, char **key_password)
{
    if (uri == NULL)
        return 0;

    /* 跳过 "sdf:" 前缀 */
    if (strncmp(uri, "sdf:", 4) != 0)
        return 0;

    *key_password = NULL;

    /* 检测格式：老格式以算法名开头(sm2: / rsa:)，新格式以 key= 开头 */
    if (strncmp(uri + 4, "sm2:", 4) == 0 || strncmp(uri + 4, "rsa:", 4) == 0) {
        return parse_sdf_uri_oldfmt(uri + 4, key_index, key_type,
                                     algo, key_password);
    } else if (strncmp(uri + 4, "key=", 4) == 0) {
        return parse_sdf_uri_kvfmt(uri + 4, key_index, key_type,
                                    algo, key_password);
    }

    return 0;
}

static void *sdfprov_store_open(void *provctx, const char *uri)
{
    SDFPROV_STORE_CTX *ctx;
    unsigned int key_index;
    int key_type, algo;
    char *key_password = NULL;

    if (uri == NULL)
        return NULL;

    if (!parse_sdf_uri(uri, &key_index, &key_type, &algo, &key_password))
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        OPENSSL_free(key_password);
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->uri = OPENSSL_strdup(uri);
    if (ctx->uri == NULL) {
        OPENSSL_free(key_password);
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->key_index = key_index;
    ctx->key_type = key_type;
    ctx->algo = algo;
    ctx->key_password = key_password;
    ctx->loaded = 0;

    return ctx;
}

static int sdfprov_store_load(void *loaderctx,
                               OSSL_CALLBACK *object_cb, void *object_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    SDFPROV_STORE_CTX *ctx = loaderctx;
    OSSL_PARAM params[4];
    int n = 0;
    int obj_type = OSSL_OBJECT_PKEY;
    char reference[256];
    int reference_len;
    const char *algo_name;

    if (ctx == NULL || object_cb == NULL)
        return 0;

    /* 每次只返回一个密钥对象 */
    if (ctx->loaded)
        return 0;

    algo_name = (ctx->algo == SDF_ALGO_RSA) ? "rsa" : "sm2";

    /*
     * 构造 reference 字符串 "sdf:<algo>:<index>:<type>[:<pwd>]"
     * 交给 KEYMGMT 的 load() 函数处理
     */
    if (ctx->key_password != NULL) {
        reference_len = snprintf(reference, sizeof(reference),
                                 "sdf:%s:%u:%s:%s", algo_name, ctx->key_index,
                                 ctx->key_type == 0 ? "sign" : "enc",
                                 ctx->key_password);
    } else {
        reference_len = snprintf(reference, sizeof(reference),
                                 "sdf:%s:%u:%s", algo_name, ctx->key_index,
                                 ctx->key_type == 0 ? "sign" : "enc");
    }
    if (reference_len <= 0 || reference_len >= (int)sizeof(reference))
        return 0;

    /* 构造返回参数 */
    params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type);
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     (char *)algo_name, 0);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                     reference,
                                                     (size_t)reference_len + 1);
    params[n] = OSSL_PARAM_construct_end();

    if (!object_cb(params, object_cbarg))
        return 0;

    ctx->loaded = 1;
    return 1;
}

static int sdfprov_store_eof(void *loaderctx)
{
    SDFPROV_STORE_CTX *ctx = loaderctx;

    if (ctx == NULL)
        return 1;

    return ctx->loaded;
}

static int sdfprov_store_close(void *loaderctx)
{
    SDFPROV_STORE_CTX *ctx = loaderctx;

    if (ctx == NULL)
        return 1;

    OPENSSL_free(ctx->key_password);
    OPENSSL_free(ctx->uri);
    OPENSSL_free(ctx);
    return 1;
}

const OSSL_DISPATCH sdfprov_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))sdfprov_store_open },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))sdfprov_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))sdfprov_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))sdfprov_store_close },
    OSSL_DISPATCH_END
};
