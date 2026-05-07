/*
 * SDF Provider RAND - hardware random via SDF
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sdf.h>
#include "prov/provider_ctx.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    void *hSession;
    int use_hw;                 /* 1=使用硬件随机数, 0=软件回退 */
} SDFPROV_RAND_CTX;

static void *sdfprov_rand_newctx(void *provctx, void *parent,
                                 const OSSL_PARAM params[])
{
    SDFPROV_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    /* 默认使用硬件随机数，如果没有设备则回退到软件 */
    ctx->use_hw = 1;
    return ctx;
}

static void sdfprov_rand_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int sdfprov_rand_instantiate(void *vctx, unsigned int strength,
                                    int prediction_resistance,
                                    const unsigned char *pstr,
                                    size_t pstr_len,
                                    const OSSL_PARAM params[])
{
    return 1;
}

static int sdfprov_rand_uninstantiate(void *vctx)
{
    return 1;
}

static int sdfprov_rand_generate(void *vctx, unsigned char *out,
                                 size_t outlen, unsigned int strength,
                                 int prediction_resistance,
                                 const unsigned char *adin, size_t adin_len)
{
    SDFPROV_RAND_CTX *ctx = vctx;

    if (out == NULL)
        return 0;

    /* 尝试硬件随机数 */
    if (ctx != NULL && ctx->use_hw && ctx->hSession != NULL) {
        if (TSAPI_SDF_GenerateRandom(ctx->hSession,
                                      (unsigned int)outlen, out) == OSSL_SDR_OK)
            return 1;
        /* 硬件失败，回退到软件 */
        ctx->use_hw = 0;
    }

    /* 软件回退 */
    return RAND_bytes_ex(ctx != NULL ? ctx->libctx : NULL,
                          out, outlen, strength) == 1;
}

static int sdfprov_rand_enable_locking(void *vctx)
{
    return 1;
}

const OSSL_DISPATCH sdfprov_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))sdfprov_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))sdfprov_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))sdfprov_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))sdfprov_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))sdfprov_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))sdfprov_rand_enable_locking },
    OSSL_DISPATCH_END
};
