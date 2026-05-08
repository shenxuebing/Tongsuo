/*
 * SDF Provider SM2 SIGNATURE
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/sdf.h>
#include "prov/provider_ctx.h"
#include "crypto/sm2.h"
#include "sdfprov_internal.h"
#include "sdfprov_utils.h"
#include "sdfprov_ctx.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    SDF_SM2_KEY *skey;
    char mdname[50];
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    unsigned char *id;
    size_t id_len;
    int flag_compute_z_digest; /* 首次 update 时计算 ZA */
} SDFPROV_SM2_SIG_CTX;

static void *sdfprov_sm2_sig_newctx(void *provctx)
{
    SDFPROV_SM2_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
}

static int sdfprov_sm2_sig_sign_init(void *vctx, void *vkey,
                                      const OSSL_PARAM params[])
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;
    SDF_SM2_KEY *key = vkey;

    if (ctx == NULL || vkey == NULL)
        return 0;

    /* 验证密钥是本 Provider 的 SDF_SM2_KEY 类型 */
    if (key->ec_key == NULL)
        return 0;

    ctx->skey = vkey;

    /* 设置默认 SM2 ID */
    if (ctx->id == NULL) {
        const char default_id[] = "1234567812345678";
        ctx->id = OPENSSL_memdup(default_id, sizeof(default_id));
        if (ctx->id == NULL)
            return 0;
        ctx->id_len = sizeof(default_id) - 1;
    }

    /* 标记需要在首次 update 时计算 ZA */
    ctx->flag_compute_z_digest = 1;

    return 1;
}

static int sdfprov_sm2_sig_sign(void *vctx, unsigned char *sig,
                                 size_t *siglen, size_t sigsize,
                                 const unsigned char *tbs, size_t tbslen)
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;
    SDF_SM2_KEY *key;
    OSSL_ECCSignature sdf_sig;
    unsigned char *der = NULL;
    size_t der_len = 0;
    int ret = 0;

    if (ctx == NULL || ctx->skey == NULL)
        return 0;

    key = ctx->skey;

    if (!key->is_hardware_key) {
        /* 软件路径: 使用 ossl_sm2_internal_sign */
        int sltmp;
        unsigned int siglen_tmp;
        const BIGNUM *priv = NULL;
        if (sig == NULL) {
            *siglen = 256;
            return 1;
        }

        /* 需要私钥才能签名 */
        if (key->ec_key == NULL) {
            return 0;
        }
        priv = EC_KEY_get0_private_key(key->ec_key);
        if (priv == NULL) {
            return 0;
        }

        if (sigsize > UINT_MAX)
            return 0;

        siglen_tmp = (unsigned int)sigsize;
        sltmp = ossl_sm2_internal_sign(tbs, (int)tbslen, sig, &siglen_tmp,
                                       key->ec_key);
        if (sltmp <= 0)
            return 0;
        *siglen = (size_t)siglen_tmp;
        return 1;
    }

    /* 硬件签名路径 */
    if (sig == NULL) {
        *siglen = 256;
        return 1;
    }

    if (key->hSession == NULL) {
        /* 尝试从全局上下文获取会话 */
        SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();
        if (sdfctx == NULL || !sdfctx->initialized)
            return 0;
        key->hSession = sdfctx->hSession;
    }

    if (key->hSession == NULL)
        return 0;

    memset(&sdf_sig, 0, sizeof(sdf_sig));
    if (TSAPI_SDF_InternalSign_ECC(key->hSession, key->key_index,
                                    (unsigned char *)tbs, (unsigned int)tbslen,
                                    &sdf_sig) != OSSL_SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        return 0;
    }

    /* 转换 OSSL_ECCSignature -> DER */
    if (!sdfprov_eccsig_to_der(&sdf_sig, &der, &der_len))
        return 0;

    if (der_len > sigsize) {
        OPENSSL_free(der);
        return 0;
    }

    memcpy(sig, der, der_len);
    *siglen = der_len;
    OPENSSL_free(der);
    ret = 1;

    return ret;
}

static int sdfprov_sm2_sig_verify_init(void *vctx, void *vkey,
                                        const OSSL_PARAM params[])
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;
    SDF_SM2_KEY *key = vkey;

    if (ctx == NULL || vkey == NULL)
        return 0;

    /* 验证密钥是本 Provider 的 SDF_SM2_KEY 类型 */
    if (key->ec_key == NULL)
        return 0;

    ctx->skey = vkey;

    /* 设置默认 SM2 ID */
    if (ctx->id == NULL) {
        const char default_id[] = "1234567812345678";
        ctx->id = OPENSSL_memdup(default_id, sizeof(default_id));
        if (ctx->id == NULL)
            return 0;
        ctx->id_len = sizeof(default_id) - 1;
    }

    /* 标记需要在首次 update 时计算 ZA */
    ctx->flag_compute_z_digest = 1;

    return 1;
}

static int sdfprov_sm2_sig_verify(void *vctx, const unsigned char *sig,
                                   size_t siglen, const unsigned char *tbs,
                                   size_t tbslen)
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;
    SDF_SM2_KEY *key;

    if (ctx == NULL || ctx->skey == NULL)
        return 0;

    key = ctx->skey;

    /* 验签始终使用软件路径（公钥已导出到 EC_KEY） */
    if (key->ec_key == NULL || EC_KEY_get0_public_key(key->ec_key) == NULL)
        return 0;

    return ossl_sm2_internal_verify(tbs, (int)tbslen,
                                     (unsigned char *)sig, (int)siglen,
                                     key->ec_key) > 0;
}

static int sdfprov_sm2_sig_digest_sign_init(void *vctx, const char *mdname,
                                              void *vkey, const OSSL_PARAM params[])
{
    if (!sdfprov_sm2_sig_sign_init(vctx, vkey, params))
        return 0;

    if (mdname != NULL) {
        SDFPROV_SM2_SIG_CTX *ctx = vctx;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }

    return 1;
}

static int sdfprov_sm2_sig_digest_verify_init(void *vctx, const char *mdname,
                                                void *vkey, const OSSL_PARAM params[])
{
    if (!sdfprov_sm2_sig_verify_init(vctx, vkey, params))
        return 0;

    if (mdname != NULL) {
        SDFPROV_SM2_SIG_CTX *ctx = vctx;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }

    return 1;
}

static int sdfprov_sm2_sig_digest_sign_update(void *vctx,
                                               const unsigned char *data,
                                               size_t datalen)
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;

    if (ctx == NULL)
        return 0;

    if (ctx->mdctx == NULL) {
        /* 创建消息摘要上下文，使用 SM3 */
        ctx->md = EVP_MD_fetch(ctx->libctx, "SM3", NULL);
        if (ctx->md == NULL)
            return 0;

        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            return 0;

        if (!EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL))
            return 0;
    }

    /* 首次 update 时计算 ZA 并注入摘要上下文 */
    if (ctx->flag_compute_z_digest) {
        uint8_t z[EVP_MAX_MD_SIZE];
        int mdsize;

        ctx->flag_compute_z_digest = 0;

        mdsize = EVP_MD_get_size(ctx->md);
        if (mdsize <= 0)
            return 0;

        if (ctx->skey == NULL || ctx->skey->ec_key == NULL)
            return 0;

        /* 计算 ZA = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA) */
        if (!ossl_sm2_compute_z_digest(z, ctx->md,
                                        ctx->id, ctx->id_len,
                                        ctx->skey->ec_key))
            return 0;

        /* 将 ZA 注入到摘要上下文 */
        if (!EVP_DigestUpdate(ctx->mdctx, z, (size_t)mdsize))
            return 0;
    }

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static int sdfprov_sm2_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                              size_t *siglen, size_t sigsize)
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;
    unsigned char digest[64]; /* SM3 输出 32 字节 */
    unsigned int dlen = 0;

    if (ctx == NULL)
        return 0;

    /*
     * 当 sig == NULL 时，只需要返回最大签名长度。
     */
    if (sig == NULL) {
        return sdfprov_sm2_sig_sign(vctx, NULL, siglen, sigsize, NULL, 0);
    }

    if (ctx->mdctx == NULL) {
        /* 没有消息数据但 sig != NULL，无法签名 */
        return 0;
    }

    /* 如果 ZA 还没计算，先计算并注入 */
    if (ctx->flag_compute_z_digest) {
        uint8_t z[EVP_MAX_MD_SIZE];
        int mdsize;

        ctx->flag_compute_z_digest = 0;
        mdsize = EVP_MD_get_size(ctx->md);
        if (mdsize <= 0)
            return 0;

        if (ctx->skey == NULL || ctx->skey->ec_key == NULL)
            return 0;

        if (!ossl_sm2_compute_z_digest(z, ctx->md,
                                        ctx->id, ctx->id_len,
                                        ctx->skey->ec_key))
            return 0;

        if (!EVP_DigestUpdate(ctx->mdctx, z, (size_t)mdsize))
            return 0;
    }

    /* 计算消息摘要 SM3(ZA || M) */
    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    /* 用摘要作为 tbs 进行签名 */
    return sdfprov_sm2_sig_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int sdfprov_sm2_sig_digest_verify_update(void *vctx,
                                                 const unsigned char *data,
                                                 size_t datalen)
{
    return sdfprov_sm2_sig_digest_sign_update(vctx, data, datalen);
}

static int sdfprov_sm2_sig_digest_verify_final(void *vctx,
                                                const unsigned char *sig,
                                                size_t siglen)
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;
    unsigned char digest[64];
    unsigned int dlen = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /* 如果 ZA 还没计算，先计算并注入 */
    if (ctx->flag_compute_z_digest) {
        uint8_t z[EVP_MAX_MD_SIZE];
        int mdsize;

        ctx->flag_compute_z_digest = 0;
        mdsize = EVP_MD_get_size(ctx->md);
        if (mdsize <= 0)
            return 0;

        if (ctx->skey == NULL || ctx->skey->ec_key == NULL)
            return 0;

        if (!ossl_sm2_compute_z_digest(z, ctx->md,
                                        ctx->id, ctx->id_len,
                                        ctx->skey->ec_key))
            return 0;

        if (!EVP_DigestUpdate(ctx->mdctx, z, (size_t)mdsize))
            return 0;
    }

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    return sdfprov_sm2_sig_verify(vctx, sig, siglen, digest, (size_t)dlen);
}

static void sdfprov_sm2_sig_freectx(void *vctx)
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;

    if (ctx == NULL)
        return;

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->id);
    OPENSSL_free(ctx);
}

static int sdfprov_sm2_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SDFPROV_SM2_SIG_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_UTF8_STRING)
            OPENSSL_strlcpy(ctx->mdname, p->data, sizeof(ctx->mdname));
    }

    /* 处理 SM2 用户 ID (NTLS 通过 EVP_PKEY_CTX_set1_id 设置) */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p != NULL) {
        OPENSSL_free(ctx->id);
        ctx->id = NULL;
        ctx->id_len = 0;
        if (p->data_type == OSSL_PARAM_OCTET_STRING && p->data != NULL) {
            ctx->id = OPENSSL_memdup(p->data, p->data_size);
            if (ctx->id != NULL)
                ctx->id_len = p->data_size;
        }
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_sm2_sig_settable_ctx_params(void *vctx,
                                                              ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

const OSSL_DISPATCH sdfprov_sm2_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sdfprov_sm2_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sdfprov_sm2_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sdfprov_sm2_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
      (void (*)(void))sdfprov_sm2_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sdfprov_sm2_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))sdfprov_sm2_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))sdfprov_sm2_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))sdfprov_sm2_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))sdfprov_sm2_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))sdfprov_sm2_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))sdfprov_sm2_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sdfprov_sm2_sig_freectx },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
      (void (*)(void))sdfprov_sm2_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))sdfprov_sm2_sig_settable_ctx_params },
    OSSL_DISPATCH_END
};
