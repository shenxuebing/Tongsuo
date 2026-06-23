/*
 * SDF Provider - MAC Implementation
 *
 * CMAC-SM4: 通过 SDF_CalculateMAC 在密码卡上完成
 *   - SDF_CalculateMAC 是单次调用接口
 *   - update 时缓存数据，final 时一次性计算
 *
 * HMAC-SM3: 本地计算
 */

#include "prov_sdf_mac.h"
#include "prov_sdf.h"
#include <openssl/evp.h>
#include <openssl/sm3.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <string.h>

#define SM4_KEY_SIZE    16
#define SM3_DIGEST_LEN  32

#ifndef SGD_SM4_CBC
#define SGD_SM4_CBC     0x00000402
#endif

#ifndef SGD_SM4_MAC
#define SGD_SM4_MAC     0x00000410
#endif

/* ==========================================================================
 * CMAC-SM4 (密码卡)
 * 
 * SDF_CalculateMAC(session, hKeyHandle, uiAlgID, pucIV,
 *                   pucData, uiDataLength, pucMac, puiMACLength)
 *
 * 注意: SDF_CalculateMAC 对输入数据长度有上限(通常 8KB~64KB)。
 * 如果数据量较大，需要分块计算。但 CMAC 标准不支持分块，
 * 所以这里将所有 update 数据缓存，在 final 时一次性调用。
 * ========================================================================== */

#define SDF_CMAC_MAX_DATA   (64 * 1024)  /* 64KB 上限 */

typedef struct sdf_cmac_sm4_ctx_st {
    SDF_PROV_CTX *provctx;
    unsigned char key[SM4_KEY_SIZE];
    size_t key_len;
    void *key_handle;
    int key_initialized;

    /* 数据缓存: update 累积，final 一次性计算 */
    unsigned char *data_buf;
    size_t data_len;
    size_t data_cap;

    /* 计算结果 */
    unsigned char mac[SM3_DIGEST_LEN];
    int mac_computed;
} SDF_CMAC_SM4_CTX;

static int sdf_cmac_sm4_ensure_key(SDF_CMAC_SM4_CTX *ctx)
{
    if (ctx->key_initialized && ctx->key_handle != NULL)
        return 1;
    if (ctx->provctx == NULL || !ctx->provctx->card_available)
        return 0;
    if (SDF_CALL(ctx->provctx, SDF_ImportKey,
             ctx->provctx->hSession,
                             ctx->key, (unsigned int)ctx->key_len,
                             &ctx->key_handle) != SDR_OK)
        return 0;
    ctx->key_initialized = 1;
    return 1;
}

static void sdf_cmac_sm4_destroy_key(SDF_CMAC_SM4_CTX *ctx)
{
    if (ctx && ctx->key_handle && ctx->provctx && ctx->provctx->card_available) {
        SDF_CALL(ctx->provctx, SDF_DestroyKey,
             ctx->provctx->hSession, ctx->key_handle);
        ctx->key_handle = NULL;
        ctx->key_initialized = 0;
    }
}

void *sdf_cmac_sm4_newctx(void *provctx)
{
    SDF_CMAC_SM4_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx) {
        ctx->provctx = (SDF_PROV_CTX *)provctx;
        ctx->data_cap = 256;
        ctx->data_buf = OPENSSL_malloc(ctx->data_cap);
        if (ctx->data_buf == NULL) {
            OPENSSL_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

void sdf_cmac_sm4_freectx(void *vctx)
{
    SDF_CMAC_SM4_CTX *ctx = vctx;
    if (!ctx) return;
    sdf_cmac_sm4_destroy_key(ctx);
    OPENSSL_clear_free(ctx->data_buf, ctx->data_cap);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

void *sdf_cmac_sm4_dupctx(void *vctx)
{
    SDF_CMAC_SM4_CTX *src = vctx, *dst;
    if (!src) return NULL;
    dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst) return NULL;
    *dst = *src;
    dst->key_handle = NULL;
    dst->key_initialized = 0;
    if (src->data_buf && src->data_len > 0) {
        dst->data_buf = OPENSSL_memdup(src->data_buf, src->data_len);
        dst->data_cap = src->data_len;
    } else {
        dst->data_buf = OPENSSL_malloc(256);
        dst->data_cap = 256;
        dst->data_len = 0;
    }
    if (!dst->data_buf) {
        OPENSSL_free(dst);
        return NULL;
    }
    return dst;
}

int sdf_cmac_sm4_init(void *vctx, const unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[])
{
    SDF_CMAC_SM4_CTX *ctx = vctx;
    if (!ctx || keylen != SM4_KEY_SIZE) return 0;
    memcpy(ctx->key, key, SM4_KEY_SIZE);
    ctx->key_len = keylen;
    ctx->data_len = 0;
    ctx->mac_computed = 0;
    sdf_cmac_sm4_destroy_key(ctx);
    return 1;
}

int sdf_cmac_sm4_update(void *vctx, const unsigned char *data, size_t datalen)
{
    SDF_CMAC_SM4_CTX *ctx = vctx;

    if (!ctx || !data || datalen == 0)
        return 1;

    if (ctx->mac_computed) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        return 0;
    }

    /* 扩展缓存 */
    if (ctx->data_len + datalen > ctx->data_cap) {
        size_t new_cap = ctx->data_cap * 2;
        unsigned char *new_buf;

        while (new_cap < ctx->data_len + datalen)
            new_cap *= 2;

        new_buf = OPENSSL_realloc(ctx->data_buf, new_cap);
        if (!new_buf) return 0;
        ctx->data_buf = new_buf;
        ctx->data_cap = new_cap;
    }

    memcpy(ctx->data_buf + ctx->data_len, data, datalen);
    ctx->data_len += datalen;

    return 1;
}

int sdf_cmac_sm4_final(void *vctx, unsigned char *out, size_t *outlen,
                         size_t outsize)
{
    SDF_CMAC_SM4_CTX *ctx = vctx;
    unsigned int mac_len = 0;
    int ret;

    if (!ctx) return 0;

    /* 大小查询 */
    if (out == NULL) {
        if (outlen) *outlen = SM3_DIGEST_LEN;
        return 1;
    }

    if (outsize < SM3_DIGEST_LEN) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return 0;
    }

    if (ctx->mac_computed) {
        memcpy(out, ctx->mac, SM3_DIGEST_LEN);
        if (outlen) *outlen = SM3_DIGEST_LEN;
        return 1;
    }

    /* 确保密钥可用 */
    if (!sdf_cmac_sm4_ensure_key(ctx)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    if (ctx->data_len > SDF_CMAC_MAX_DATA) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return 0;
    }

    /* 一次性计算 MAC (使用 SGD_SM4_MAC 作为 SDFID) */
    ret = SDF_CALL(ctx->provctx, SDF_CalculateMAC,
             ctx->provctx->hSession, ctx->key_handle,
                                  SGD_SM4_MAC, NULL,
                                  ctx->data_buf, (unsigned int)ctx->data_len,
                                  ctx->mac, &mac_len);

    if (ret != SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    ctx->mac_computed = 1;
    memcpy(out, ctx->mac, SM3_DIGEST_LEN);
    if (outlen) *outlen = SM3_DIGEST_LEN;

    /* 清除缓存数据 */
    OPENSSL_cleanse(ctx->data_buf, ctx->data_len);
    ctx->data_len = 0;

    return 1;
}

int sdf_cmac_sm4_get_params(OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (p) OSSL_PARAM_set_size_t(p, SM4_KEY_SIZE);
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p) OSSL_PARAM_set_size_t(p, SM3_DIGEST_LEN);
    return 1;
}

const OSSL_PARAM *sdf_cmac_sm4_gettable_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM t[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return t;
}

int sdf_cmac_sm4_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{ return 1; }

const OSSL_PARAM *sdf_cmac_sm4_settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM t[] = { OSSL_PARAM_END };
    return t;
}

int sdf_cmac_sm4_get_ctx_params(void *vctx, OSSL_PARAM *params)
{ return 1; }

const OSSL_PARAM *sdf_cmac_sm4_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM t[] = { OSSL_PARAM_END };
    return t;
}

const OSSL_DISPATCH sdf_cmac_sm4_dispatch[] = {
    { OSSL_FUNC_MAC_NEWCTX,              (void (*)(void))sdf_cmac_sm4_newctx },
    { OSSL_FUNC_MAC_FREECTX,             (void (*)(void))sdf_cmac_sm4_freectx },
    { OSSL_FUNC_MAC_DUPCTX,              (void (*)(void))sdf_cmac_sm4_dupctx },
    { OSSL_FUNC_MAC_INIT,                (void (*)(void))sdf_cmac_sm4_init },
    { OSSL_FUNC_MAC_UPDATE,              (void (*)(void))sdf_cmac_sm4_update },
    { OSSL_FUNC_MAC_FINAL,               (void (*)(void))sdf_cmac_sm4_final },
    { OSSL_FUNC_MAC_GET_PARAMS,          (void (*)(void))sdf_cmac_sm4_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,     (void (*)(void))sdf_cmac_sm4_gettable_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void (*)(void))sdf_cmac_sm4_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_cmac_sm4_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (void (*)(void))sdf_cmac_sm4_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_cmac_sm4_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_ALGORITHM sdf_mac_cmac_sm4[] = {
    { "CMAC-SM4", "provider=sdfprov", sdf_cmac_sm4_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};

/* ==========================================================================
 * HMAC-SM3 (本地计算)
 * ========================================================================== */

typedef struct sdf_hmac_sm3_ctx_st {
    EVP_MAC *mac;
    EVP_MAC_CTX *mctx;
} SDF_HMAC_SM3_CTX;

void *sdf_hmac_sm3_newctx(void *provctx)
{
    SDF_HMAC_SM3_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!ctx->mac) { OPENSSL_free(ctx); return NULL; }
    return ctx;
}

void sdf_hmac_sm3_freectx(void *vctx)
{
    SDF_HMAC_SM3_CTX *ctx = vctx;
    if (!ctx) return;
    EVP_MAC_CTX_free(ctx->mctx);
    EVP_MAC_free(ctx->mac);
    OPENSSL_free(ctx);
}

void *sdf_hmac_sm3_dupctx(void *vctx)
{
    SDF_HMAC_SM3_CTX *src = vctx, *dst;
    if (!src) return NULL;
    dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst) return NULL;
    dst->mac = src->mac;
    if (src->mctx) {
        dst->mctx = EVP_MAC_CTX_dup(src->mctx);
        if (!dst->mctx) { OPENSSL_free(dst); return NULL; }
    }
    EVP_MAC_up_ref(dst->mac);
    return dst;
}

int sdf_hmac_sm3_init(void *vctx, const unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[])
{
    SDF_HMAC_SM3_CTX *ctx = vctx;
    OSSL_PARAM p[2];

    if (!ctx || !ctx->mac) return 0;
    EVP_MAC_CTX_free(ctx->mctx);
    ctx->mctx = EVP_MAC_CTX_new(ctx->mac);
    if (!ctx->mctx) return 0;

    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SM3", 0);
    p[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx->mctx, key, keylen, p)) return 0;
    return 1;
}

int sdf_hmac_sm3_update(void *vctx, const unsigned char *data, size_t datalen)
{
    SDF_HMAC_SM3_CTX *ctx = vctx;
    if (!ctx || !ctx->mctx) return 0;
    return EVP_MAC_update(ctx->mctx, data, datalen);
}

int sdf_hmac_sm3_final(void *vctx, unsigned char *out, size_t *outlen,
                         size_t outsize)
{
    SDF_HMAC_SM3_CTX *ctx = vctx;
    if (!ctx || !ctx->mctx) return 0;
    return EVP_MAC_final(ctx->mctx, out, outlen, outsize);
}

int sdf_hmac_sm3_get_params(OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p) OSSL_PARAM_set_size_t(p, SM3_DIGEST_LEN);
    return 1;
}

const OSSL_PARAM *sdf_hmac_sm3_gettable_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM t[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return t;
}

int sdf_hmac_sm3_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{ return 1; }

const OSSL_PARAM *sdf_hmac_sm3_settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM t[] = { OSSL_PARAM_END };
    return t;
}

int sdf_hmac_sm3_get_ctx_params(void *vctx, OSSL_PARAM *params)
{ return 1; }

const OSSL_PARAM *sdf_hmac_sm3_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM t[] = { OSSL_PARAM_END };
    return t;
}

const OSSL_DISPATCH sdf_hmac_sm3_dispatch[] = {
    { OSSL_FUNC_MAC_NEWCTX,              (void (*)(void))sdf_hmac_sm3_newctx },
    { OSSL_FUNC_MAC_FREECTX,             (void (*)(void))sdf_hmac_sm3_freectx },
    { OSSL_FUNC_MAC_DUPCTX,              (void (*)(void))sdf_hmac_sm3_dupctx },
    { OSSL_FUNC_MAC_INIT,                (void (*)(void))sdf_hmac_sm3_init },
    { OSSL_FUNC_MAC_UPDATE,              (void (*)(void))sdf_hmac_sm3_update },
    { OSSL_FUNC_MAC_FINAL,               (void (*)(void))sdf_hmac_sm3_final },
    { OSSL_FUNC_MAC_GET_PARAMS,          (void (*)(void))sdf_hmac_sm3_get_params },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,     (void (*)(void))sdf_hmac_sm3_gettable_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void (*)(void))sdf_hmac_sm3_set_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_hmac_sm3_settable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (void (*)(void))sdf_hmac_sm3_get_ctx_params },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_hmac_sm3_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_ALGORITHM sdf_mac_hmac_sm3[] = {
    { "HMAC-SM3", "provider=sdfprov", sdf_hmac_sm3_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};
