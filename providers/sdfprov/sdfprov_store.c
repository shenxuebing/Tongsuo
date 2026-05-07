/*
 * SDF Provider STORE - 从 SDF 设备加载硬件密钥
 * URI 格式: "sdf:key=<index>;type=<sign|enc>"
 *   例如: "sdf:key=0;type=sign"  - 加载索引 0 的签名密钥
 *         "sdf:key=0;type=enc"   - 加载索引 0 的加密密钥
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
    int loaded;                 /* 已加载标记（仅返回一次） */
    unsigned int key_index;
    int key_type;               /* 0=sign, 1=enc */
} SDFPROV_STORE_CTX;

/*
 * 解析 URI: "sdf:key=0;type=sign" 或 "sdf:key=0;type=enc"
 */
static int parse_sdf_uri(const char *uri, unsigned int *key_index, int *key_type)
{
    const char *p;
    char *endp;

    if (uri == NULL)
        return 0;

    /* 跳过 "sdf:" 前缀 */
    if (strncmp(uri, "sdf:", 4) != 0)
        return 0;

    p = uri + 4;

    /* 解析 key=<index> */
    if (strncmp(p, "key=", 4) != 0)
        return 0;

    *key_index = (unsigned int)strtoul(p + 4, &endp, 10);
    p = endp;

    /* 跳过分隔符 */
    if (*p == ';' || *p == '&')
        p++;

    /* 解析 type=<sign|enc> */
    if (strncmp(p, "type=", 5) != 0)
        return 0;

    p += 5;
    if (strcmp(p, "sign") == 0 || strcmp(p, "0") == 0)
        *key_type = 0;
    else if (strcmp(p, "enc") == 0 || strcmp(p, "1") == 0)
        *key_type = 1;
    else
        return 0;

    return 1;
}

static void *sdfprov_store_open(void *provctx, const char *uri)
{
    SDFPROV_STORE_CTX *ctx;
    unsigned int key_index;
    int key_type;

    if (uri == NULL)
        return NULL;

    if (!parse_sdf_uri(uri, &key_index, &key_type))
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->uri = OPENSSL_strdup(uri);
    if (ctx->uri == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->key_index = key_index;
    ctx->key_type = key_type;
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
    char reference[64];
    int reference_len;

    if (ctx == NULL || object_cb == NULL)
        return 0;

    /* 每次只返回一个密钥对象 */
    if (ctx->loaded)
        return 0;

    /*
     * 构造 reference 字符串 "sdf:<index>:<type>"
     * 交给 KEYMGMT 的 load() 函数处理: 创建 SDF_SM2_KEY, 导出公钥等
     */
    reference_len = snprintf(reference, sizeof(reference),
                             "sdf:%u:%s", ctx->key_index,
                             ctx->key_type == 0 ? "sign" : "enc");
    if (reference_len <= 0 || reference_len >= (int)sizeof(reference))
        return 0;

    /* 构造返回参数 */
    params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type);
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     "SM2", 0);
    /* 传递 reference 字符串给 KEYMGMT load(), 包含 null 终止符以便 strcmp 正常工作 */
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                     reference,
                                                     (size_t)reference_len + 1);
    params[n] = OSSL_PARAM_construct_end();

    /* 回调通知上层，KEYMGMT load() 会被调用 */
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
