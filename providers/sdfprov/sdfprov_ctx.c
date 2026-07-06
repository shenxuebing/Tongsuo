/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/sdf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/sdf.h"
#include "internal/tlog.h"
#include "sdfprov_ctx.h"

SDFPROV_CTX *sdfprov_ctx_new(OSSL_LIB_CTX *libctx,
                             const OSSL_CORE_HANDLE *handle)
{
    SDFPROV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->libctx = libctx;
    ctx->handle = handle;
    ctx->lock = CRYPTO_THREAD_lock_new();
    if (ctx->lock == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

void sdfprov_ctx_free(SDFPROV_CTX *ctx)
{
    if (ctx == NULL)
        return;

    sdfprov_ctx_teardown_device(ctx);
    OPENSSL_free(ctx->sdf_lib_path);
    OPENSSL_free(ctx->device_name);
    OPENSSL_free(ctx->password);
    CRYPTO_THREAD_lock_free(ctx->lock);
    OPENSSL_free(ctx);
}

int sdfprov_ctx_init_device(SDFPROV_CTX *ctx)
{
    int ret;

    if (ctx == NULL)
        return 0;

    if (ctx->initialized)
        return 1;

    if (CRYPTO_THREAD_write_lock(ctx->lock) == 0)
        return 0;

    if (ctx->initialized) {
        CRYPTO_THREAD_unlock(ctx->lock);
        return 1;
    }

    if (!ctx->module_loaded) {
        const char *pwd = ctx->password != NULL ? ctx->password : "88888888";

        if (!ossl_sdf_lib_preload(ctx->sdf_lib_path, pwd,
                                  ctx->use_load_module)) {
            CRYPTO_THREAD_unlock(ctx->lock);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                           "SDF module preload failed");
            return 0;
        }

        ctx->module_loaded = 1;
    }

    ret = TSAPI_SDF_OpenDevice(&ctx->hDevice);
    if (ret != 0) {
        CRYPTO_THREAD_unlock(ctx->lock);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                       "SDF_OpenDevice failed: 0x%08x", ret);
        return 0;
    }

    ret = TSAPI_SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    if (ret != 0) {
        TSAPI_SDF_CloseDevice(ctx->hDevice);
        ctx->hDevice = NULL;
        CRYPTO_THREAD_unlock(ctx->lock);
        return 0;
    }

    ctx->initialized = 1;
    /* 复用 TSAPI 层的 SDF_METHOD 函数指针表（ts_sdf_meth 已由 ossl_sdf_lib_preload 加载） */
    ctx->sdfList = &ts_sdf_meth;
    CRYPTO_THREAD_unlock(ctx->lock);
    return 1;
}

void sdfprov_ctx_teardown_device(SDFPROV_CTX *ctx)
{
    if (ctx == NULL || !ctx->initialized)
        return;

    TSAPI_SDF_CloseSession(ctx->hSession);
    TSAPI_SDF_CloseDevice(ctx->hDevice);
    ctx->hSession = NULL;
    ctx->hDevice = NULL;
    ctx->initialized = 0;
}

void *sdfprov_ctx_get_session(SDFPROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    if (!ctx->initialized && !sdfprov_ctx_init_device(ctx))
        return NULL;

    return ctx->hSession;
}
