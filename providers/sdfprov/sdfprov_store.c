/*
 * SDF Provider STORE - 从 SDF 设备加载硬件密钥
 *
 * 支持的 URI 格式：
 *
 * 1. 兼容老 Engine 的位置参数格式
 *    "sdf:<algo>:<index>:<type>[:<pwd>]"
 *    例如：
 *      "sdf:sm2:0:sign"
 *      "sdf:sm2:0:enc:11111111"
 *      "sdf:rsa:1:sign:mypwd"
 *
 * 2. key=value 风格
 *    "sdf:key=<index>;type=<sign|enc>[;algo=<sm2|rsa>][;pwd=<password>][;session=<addr>]"
 *    例如：
 *      "sdf:key=0;type=sign"
 *      "sdf:key=0;type=enc;algo=sm2;pwd=11111111"
 *      "sdf:key=1;type=sign;algo=rsa;session=0x12345678"
 *
 * 3. 外部 session 兼容写法
 *    "sdf:key=1;type=sign;algo=rsa;session=session:12345678"
 *    "sdf:rsa:1:sign:mypwd:session:12345678"
 *
 * 说明：
 *   - STORE 只负责解析 URI 并向 KEYMGMT 透传 reference
 *   - 传入 session 后，后续密钥对象会直接复用外部会话句柄
 *
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/store.h>
#include "prov/provider_ctx.h"
#include "internal/tlog.h"
#include "sdfprov_internal.h"
#include "sdfprov_ctx.h"
#include "sdfprov_utils.h"

typedef struct {
    void *provctx;
    OSSL_LIB_CTX *libctx;
    char *uri;
    int loaded;
    SDFPROV_KEY_URI key_uri;
} SDFPROV_STORE_CTX;

static void *sdfprov_store_open(void *provctx, const char *uri)
{
    SDFPROV_STORE_CTX *ctx = NULL;

    if (uri == NULL)
        return NULL;

    TLOG_DEBUG("Opening URI: %s", uri);

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    if (!sdfprov_parse_key_uri(uri, &ctx->key_uri)) {
        TLOG_ERROR("Failed to parse URI: %s", uri);
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->provctx = provctx;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->uri = OPENSSL_strdup(uri);
    if (ctx->uri == NULL) {
        sdfprov_key_uri_cleanup(&ctx->key_uri);
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

static int sdfprov_store_load(void *loaderctx,
                              OSSL_CALLBACK *object_cb, void *object_cbarg,
                              OSSL_PASSPHRASE_CALLBACK *pw_cb,
                              void *pw_cbarg)
{
    SDFPROV_STORE_CTX *ctx = loaderctx;
    OSSL_PARAM params[4];
    char reference[512];
    int obj_type = OSSL_OBJECT_PKEY;
    int n = 0;
    const char *algo_name;
    size_t reference_len;

    (void)pw_cb;
    (void)pw_cbarg;

    if (ctx == NULL || object_cb == NULL || ctx->loaded)
        return 0;

    algo_name = ctx->key_uri.algo == SDF_ALGO_RSA ? "rsa" : "sm2";
    if (!sdfprov_format_key_reference(reference, sizeof(reference),
                                      &ctx->key_uri))
        return 0;
    reference_len = strlen(reference) + 1;

    params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type);
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                   (char *)algo_name, 0);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                    reference, reference_len);
    params[n] = OSSL_PARAM_construct_end();

    ctx->loaded = 1;
    return object_cb(params, object_cbarg);
}

static int sdfprov_store_eof(void *loaderctx)
{
    SDFPROV_STORE_CTX *ctx = loaderctx;

    return ctx == NULL || ctx->loaded;
}

static int sdfprov_store_close(void *loaderctx)
{
    SDFPROV_STORE_CTX *ctx = loaderctx;

    if (ctx == NULL)
        return 1;

    sdfprov_key_uri_cleanup(&ctx->key_uri);
    OPENSSL_free(ctx->uri);
    OPENSSL_free(ctx);
    return 1;
}

static int sdfprov_store_set_ctx_params(void *loaderctx,
                                        const OSSL_PARAM params[])
{
    (void)loaderctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *sdfprov_store_settable_ctx_params(
        ossl_unused void *loaderctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

const OSSL_DISPATCH sdfprov_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))sdfprov_store_open },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))sdfprov_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))sdfprov_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))sdfprov_store_close },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS,
      (void (*)(void))sdfprov_store_set_ctx_params },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
      (void (*)(void))sdfprov_store_settable_ctx_params },
    OSSL_DISPATCH_END
};
