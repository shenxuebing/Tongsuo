/*
 * SDF Provider - Random Number Implementation
 *
 * 通过 SDF_GenerateRandom 从密码卡获取随机数。
 */

#include "prov_sdf_rand.h"
#include "prov_sdf.h"
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

typedef struct sdf_rand_ctx_st {
    SDF_PROV_CTX *provctx;
    int instantiated;
} SDF_RAND_CTX;

const OSSL_ALGORITHM sdf_rand[] = {
    { "SDF-RAND", "provider=sdfprov", sdf_rand_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};

const OSSL_DISPATCH sdf_rand_dispatch[] = {
    { OSSL_FUNC_RAND_NEWCTX,                (void (*)(void))sdf_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX,               (void (*)(void))sdf_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE,           (void (*)(void))sdf_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE,         (void (*)(void))sdf_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE,              (void (*)(void))sdf_rand_generate },
    { OSSL_FUNC_RAND_RESEED,                (void (*)(void))sdf_rand_reseed },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,        (void (*)(void))sdf_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK,                  (void (*)(void))sdf_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK,                (void (*)(void))sdf_rand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,   (void (*)(void))sdf_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,   (void (*)(void))sdf_rand_settable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,        (void (*)(void))sdf_rand_get_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS,        (void (*)(void))sdf_rand_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_PARAMS,       (void (*)(void))sdf_rand_gettable_params },
    { OSSL_FUNC_RAND_GET_PARAMS,            (void (*)(void))sdf_rand_get_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,    (void (*)(void))sdf_rand_verify_zeroization },
    { OSSL_FUNC_RAND_NONCE,                 (void (*)(void))sdf_rand_nonce },
    { 0, NULL }
};

static const OSSL_PARAM sdf_rand_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_rand_known_gettable_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_rand_known_settable_ctx_params[] = {
    OSSL_PARAM_END
};

void *sdf_rand_newctx(void *provctx, const OSSL_PARAM params[])
{
    SDF_RAND_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx) {
        ctx->provctx = (SDF_PROV_CTX *)provctx;
        ctx->instantiated = 1; /* SDF 不需要实例化步骤 */
    }
    return ctx;
}

void sdf_rand_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

int sdf_rand_instantiate(void *vctx, int prediction_resistance,
                          const unsigned char *personalization_string,
                          size_t personalization_string_len)
{
    /* SDF 密码卡始终就绪 */
    return 1;
}

int sdf_rand_uninstantiate(void *vctx)
{
    return 1;
}

int sdf_rand_generate(void *vctx, unsigned char *out, size_t outlen,
                       unsigned int strength, int prediction_resistance,
                       const unsigned char *additional_input,
                       size_t additional_input_len)
{
    SDF_RAND_CTX *ctx = (SDF_RAND_CTX *)vctx;

    if (ctx == NULL || out == NULL || outlen == 0)
        return 0;

    if (ctx->provctx == NULL || !ctx->provctx->card_available) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    if (SDF_CALL(ctx->provctx, SDF_GenerateRandom,ctx->provctx->hSession,
                                  (unsigned int)outlen, out) != SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    return 1;
}

int sdf_rand_reseed(void *vctx, int prediction_resistance,
                     const unsigned char *entropy, size_t entropy_len,
                     const unsigned char *additional_input,
                     size_t additional_input_len)
{
    /* SDF 卡自带熵源，不需要外部 reseed */
    return 1;
}

int sdf_rand_enable_locking(void *vctx) { return 1; }
int sdf_rand_lock(void *vctx) { return 1; }
void sdf_rand_unlock(void *vctx) { }

int sdf_rand_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p) OSSL_PARAM_set_uint(p, 1);
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p) OSSL_PARAM_set_uint(p, 256);
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p) OSSL_PARAM_set_uint(p, INT_MAX);
    return 1;
}

const OSSL_PARAM *sdf_rand_gettable_ctx_params(void *vctx, void *provctx)
{
    return sdf_rand_known_gettable_ctx_params;
}

int sdf_rand_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{ return 1; }

const OSSL_PARAM *sdf_rand_settable_ctx_params(void *vctx, void *provctx)
{
    return sdf_rand_known_settable_ctx_params;
}

int sdf_rand_get_params(OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p) OSSL_PARAM_set_uint(p, INT_MAX);
    return 1;
}

const OSSL_PARAM *sdf_rand_gettable_params(void *provctx)
{
    return sdf_rand_known_gettable_params;
}

int sdf_rand_verify_zeroization(void *vctx) { return 1; }

int sdf_rand_nonce(void *vctx, unsigned char *out, size_t outlen)
{
    return sdf_rand_generate(vctx, out, outlen, 0, 0, NULL, 0);
}
