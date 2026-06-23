/*
 * SDF Provider - SM3 Digest Implementation
 */

#include "prov_sdf_digest.h"
#include <openssl/sm3.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <string.h>

typedef struct sdf_sm3_ctx_st {
    SM3_CTX sm3_ctx;
} SDF_SM3_DIGEST_CTX;

const OSSL_ALGORITHM sdf_digest_sm3[] = {
    { "SM3", "provider=sdfprov", sdf_sm3_digest_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};

const OSSL_DISPATCH sdf_sm3_digest_dispatch[] = {
    { OSSL_FUNC_DIGEST_NEWCTX,              (void (*)(void))sdf_sm3_digest_newctx },
    { OSSL_FUNC_DIGEST_FREECTX,             (void (*)(void))sdf_sm3_digest_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX,              (void (*)(void))sdf_sm3_digest_dupctx },
    { OSSL_FUNC_DIGEST_INIT,                (void (*)(void))sdf_sm3_digest_init },
    { OSSL_FUNC_DIGEST_UPDATE,              (void (*)(void))sdf_sm3_digest_update },
    { OSSL_FUNC_DIGEST_FINAL,               (void (*)(void))sdf_sm3_digest_final },
    { OSSL_FUNC_DIGEST_DIGEST,              (void (*)(void))sdf_sm3_digest },
    { OSSL_FUNC_DIGEST_GET_PARAMS,          (void (*)(void))sdf_sm3_digest_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS,     (void (*)(void))sdf_sm3_digest_gettable_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS,      (void (*)(void))sdf_sm3_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm3_digest_settable_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS,      (void (*)(void))sdf_sm3_digest_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm3_digest_gettable_ctx_params },
    { 0, NULL }
};

static const OSSL_PARAM sdf_sm3_digest_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_sm3_digest_known_settable_ctx_params[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_sm3_digest_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END
};

void *sdf_sm3_digest_newctx(void *provctx)
{
    SDF_SM3_DIGEST_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    return ctx;
}

void sdf_sm3_digest_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

void *sdf_sm3_digest_dupctx(void *vctx)
{
    SDF_SM3_DIGEST_CTX *in = (SDF_SM3_DIGEST_CTX *)vctx;
    SDF_SM3_DIGEST_CTX *out;

    if (in == NULL)
        return NULL;

    out = OPENSSL_malloc(sizeof(*out));
    if (out == NULL)
        return NULL;

    *out = *in;
    return out;
}

int sdf_sm3_digest_init(void *vctx)
{
    SDF_SM3_DIGEST_CTX *ctx = (SDF_SM3_DIGEST_CTX *)vctx;
    if (ctx == NULL)
        return 0;
    return SM3_Init(&ctx->sm3_ctx);
}

int sdf_sm3_digest_update(void *vctx, const unsigned char *data, size_t datalen)
{
    SDF_SM3_DIGEST_CTX *ctx = (SDF_SM3_DIGEST_CTX *)vctx;
    if (ctx == NULL)
        return 0;
    return SM3_Update(&ctx->sm3_ctx, data, datalen);
}

int sdf_sm3_digest_final(void *vctx, unsigned char *out, size_t *outlen,
                          size_t outsize)
{
    SDF_SM3_DIGEST_CTX *ctx = (SDF_SM3_DIGEST_CTX *)vctx;
    if (ctx == NULL || outsize < SM3_DIGEST_LENGTH)
        return 0;
    *outlen = SM3_DIGEST_LENGTH;
    return SM3_Final(out, &ctx->sm3_ctx);
}

int sdf_sm3_digest(void *provctx, const unsigned char *in, size_t inlen,
                    unsigned char *out, size_t *outlen, size_t outsize)
{
    SM3_CTX sm3_ctx;
    if (outsize < SM3_DIGEST_LENGTH)
        return 0;
    *outlen = SM3_DIGEST_LENGTH;
    if (!SM3_Init(&sm3_ctx))
        return 0;
    if (!SM3_Update(&sm3_ctx, in, inlen))
        return 0;
    return SM3_Final(out, &sm3_ctx);
}

int sdf_sm3_digest_get_params(OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SM3_CBLOCK))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SM3_DIGEST_LENGTH))
        return 0;
    return 1;
}

const OSSL_PARAM *sdf_sm3_digest_gettable_params(void *ctx, void *provctx)
{
    return sdf_sm3_digest_known_gettable_params;
}

int sdf_sm3_digest_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return 1;
}

const OSSL_PARAM *sdf_sm3_digest_settable_ctx_params(void *ctx, void *provctx)
{
    return sdf_sm3_digest_known_settable_ctx_params;
}

int sdf_sm3_digest_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SM3_DIGEST_LENGTH))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, SM3_CBLOCK))
        return 0;
    return 1;
}

const OSSL_PARAM *sdf_sm3_digest_gettable_ctx_params(void *ctx, void *provctx)
{
    return sdf_sm3_digest_known_gettable_ctx_params;
}
