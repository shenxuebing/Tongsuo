/*
 * SDF Provider SM2DH KEYEXCH
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sdf.h>
#include <openssl/proverr.h>
#include <openssl/sm3.h>
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "crypto/sm2.h"
#include "sdfprov_utils.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    SDF_SM2_KEY *k;             /* 自身临时密钥 */
    SDF_SM2_KEY *peerk;         /* 对端临时公钥 */
    EVP_PKEY *enc_k;            /* 自身加密证书密钥 (EVP_PKEY*) */
    EVP_PKEY *enc_peerk;        /* 对端加密证书公钥 (EVP_PKEY*) */
    unsigned char *id;
    size_t id_len;
    unsigned char *peer_id;
    size_t peer_id_len;
    int initiator;
    size_t outlen;
} SDFPROV_SM2DH_CTX;

static void *sdfprov_sm2dh_newctx(void *provctx);
static int sdfprov_sm2dh_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static void *sdfprov_sm2dh_newctx(void *provctx)
{
    SDFPROV_SM2DH_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
}

static int sdfprov_sm2dh_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    SDFPROV_SM2DH_CTX *ctx = vctx;
    if (ctx == NULL || vkey == NULL)
        return 0;
    fprintf(stderr, "  [SDFPROV] sm2dh_init: key=%p\n", vkey);
    ctx->k = vkey;
    if (params != NULL)
        return sdfprov_sm2dh_set_ctx_params(vctx, params);
    return 1;
}

static int sdfprov_sm2dh_set_peer(void *vctx, void *vpeerk)
{
    SDFPROV_SM2DH_CTX *ctx = vctx;
    fprintf(stderr, "  [SDFPROV] sm2dh_set_peer: ctx=%p peerk=%p\n", vctx, vpeerk);
    if (ctx == NULL || vpeerk == NULL)
        return 0;
    ctx->peerk = vpeerk;
    return 1;
}

/* 从 EVP_PKEY 提取 EC_KEY */
static EC_KEY *evp_pkey_to_ec_key(EVP_PKEY *pkey)
{
    if (pkey == NULL)
        return NULL;
    return (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
}

static int sdfprov_sm2dh_derive(void *vctx, unsigned char *secret,
                                 size_t *psecretlen, size_t outlen)
{
    SDFPROV_SM2DH_CTX *ctx = vctx;

    if (ctx == NULL || ctx->k == NULL || ctx->peerk == NULL)
        return 0;

    if (secret == NULL) {
        *psecretlen = 32;
        return 1;
    }

    if (ctx->k->ec_key == NULL || ctx->peerk->ec_key == NULL)
        return 0;

    /* 完整 SM2DH 4 密钥协商模式 */
    if (ctx->enc_k != NULL && ctx->enc_peerk != NULL) {
        EC_KEY *self_enc = evp_pkey_to_ec_key(ctx->enc_k);
        EC_KEY *peer_enc = evp_pkey_to_ec_key(ctx->enc_peerk);

        fprintf(stderr, "  [SDFPROV] sm2dh_derive: 4-key mode\n");

        if (self_enc == NULL || peer_enc == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }

        size_t len = SM2_compute_key(secret, outlen, ctx->initiator,
                                      ctx->peer_id, ctx->peer_id_len,
                                      ctx->id, ctx->id_len,
                                      ctx->peerk->ec_key,
                                      ctx->k->ec_key,
                                      peer_enc,
                                      self_enc,
                                      EVP_sm3(), ctx->libctx, NULL);
        if (len == 0)
            return 0;
        *psecretlen = len;
        return 1;
    }

    /* 简化模式: 仅临时密钥 ECDH */
    {
        const EC_POINT *pub = EC_KEY_get0_public_key(ctx->peerk->ec_key);
        const EC_GROUP *group = EC_KEY_get0_group(ctx->k->ec_key);
        int field_size, len;

        if (pub == NULL || group == NULL)
            return 0;

        field_size = EC_GROUP_get_degree(group);
        len = (field_size + 7) / 8;

        if (outlen < (size_t)len) {
            *psecretlen = (size_t)len;
            return 0;
        }

        len = ECDH_compute_key(secret, outlen, pub, ctx->k->ec_key, NULL);
        if (len <= 0)
            return 0;

        *psecretlen = (size_t)len;
        return 1;
    }
}

static void sdfprov_sm2dh_freectx(void *vctx)
{
    SDFPROV_SM2DH_CTX *ctx = vctx;
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx->id);
    OPENSSL_free(ctx->peer_id);
    EVP_PKEY_free(ctx->enc_k);
    EVP_PKEY_free(ctx->enc_peerk);
    OPENSSL_free(ctx);
}

static int sdfprov_sm2dh_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SDFPROV_SM2DH_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    if (params == NULL)
        return 1;

    fprintf(stderr, "  [SDFPROV] sm2dh_set_ctx_params called\n");

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_INITIATOR);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &ctx->initiator))
            return 0;
        fprintf(stderr, "  [SDFPROV] sm2dh: initiator=%d\n", ctx->initiator);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_SELF_ID);
    if (p != NULL) {
        OPENSSL_free(ctx->id);
        ctx->id = NULL;
        ctx->id_len = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->id, 0, &ctx->id_len))
            return 0;
        fprintf(stderr, "  [SDFPROV] sm2dh: self_id len=%zu\n", ctx->id_len);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PEER_ID);
    if (p != NULL) {
        OPENSSL_free(ctx->peer_id);
        ctx->peer_id = NULL;
        ctx->peer_id_len = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->peer_id, 0, &ctx->peer_id_len))
            return 0;
        fprintf(stderr, "  [SDFPROV] sm2dh: peer_id len=%zu\n", ctx->peer_id_len);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_SELF_ENC_KEY);
    if (p != NULL) {
        EVP_PKEY *enc_key = NULL;
        size_t enc_key_sz = 0;
        if (!OSSL_PARAM_get_octet_ptr(p, (const void **)&enc_key, &enc_key_sz))
            return 0;
        fprintf(stderr, "  [SDFPROV] sm2dh: self_enc_key=%p sz=%zu\n", (void*)enc_key, enc_key_sz);
        EVP_PKEY_free(ctx->enc_k);
        ctx->enc_k = enc_key;
        EVP_PKEY_up_ref(ctx->enc_k);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PEER_ENC_KEY);
    if (p != NULL) {
        EVP_PKEY *enc_peer = NULL;
        size_t enc_peer_sz = 0;
        if (!OSSL_PARAM_get_octet_ptr(p, (const void **)&enc_peer, &enc_peer_sz))
            return 0;
        fprintf(stderr, "  [SDFPROV] sm2dh: peer_enc_key=%p sz=%zu\n", (void*)enc_peer, enc_peer_sz);
        EVP_PKEY_free(ctx->enc_peerk);
        ctx->enc_peerk = enc_peer;
        EVP_PKEY_up_ref(ctx->enc_peerk);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_OUTLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->outlen))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_sm2dh_settable_ctx_params(
        ossl_unused void *vctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_INITIATOR, NULL),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_SELF_ID, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_PEER_ID, NULL, 0),
        OSSL_PARAM_octet_ptr(OSSL_EXCHANGE_PARAM_SELF_ENC_KEY, NULL, 0),
        OSSL_PARAM_octet_ptr(OSSL_EXCHANGE_PARAM_PEER_ENC_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_OUTLEN, NULL),
        OSSL_PARAM_END
    };
    return params;
}

const OSSL_DISPATCH sdfprov_sm2dh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))sdfprov_sm2dh_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))sdfprov_sm2dh_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))sdfprov_sm2dh_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))sdfprov_sm2dh_derive },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))sdfprov_sm2dh_freectx },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
      (void (*)(void))sdfprov_sm2dh_set_ctx_params },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
      (void (*)(void))sdfprov_sm2dh_settable_ctx_params },
    OSSL_DISPATCH_END
};
