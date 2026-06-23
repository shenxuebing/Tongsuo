/*
 * SDF Provider for Tongsuo - SM2 Signature Module Implementation
 *
 * 基于 GM/T 0018 SDF 接口的 SM2 签名实现
 * 签名在密码卡上完成，验签可以用公钥本地完成
 * 集成 SDF_GetPrivateKeyAccessRight 私钥访问控制
 */

#include "prov_sdf_sig.h"
#include "prov_sdf_keys.h"
#include <openssl/evp.h>
#include <openssl/sm3.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <crypto/sm2.h>
#include <openssl/x509.h>
#include <string.h>

/* SM2 默认用户 ID: "1234567812345678" */
static const unsigned char default_sm2_id[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

/*============================================================================
 * 算法定义和分发表
 *===========================================================================*/

const OSSL_ALGORITHM sdf_signature_sm2[] = {
    { "SM2", "provider=sdfprov", sdf_sm2_sig_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};

const OSSL_DISPATCH sdf_sm2_sig_dispatch[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,                (void (*)(void))sdf_sm2_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,               (void (*)(void))sdf_sm2_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,                (void (*)(void))sdf_sm2_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,             (void (*)(void))sdf_sm2_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                  (void (*)(void))sdf_sm2_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,           (void (*)(void))sdf_sm2_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,                (void (*)(void))sdf_sm2_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,      (void (*)(void))sdf_sm2_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,    (void (*)(void))sdf_sm2_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,     (void (*)(void))sdf_sm2_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,    (void (*)(void))sdf_sm2_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,  (void (*)(void))sdf_sm2_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,   (void (*)(void))sdf_sm2_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,        (void (*)(void))sdf_sm2_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,   (void (*)(void))sdf_sm2_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,        (void (*)(void))sdf_sm2_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,   (void (*)(void))sdf_sm2_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,     (void (*)(void))sdf_sm2_sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
                                                (void (*)(void))sdf_sm2_sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,     (void (*)(void))sdf_sm2_sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
                                                (void (*)(void))sdf_sm2_sig_settable_ctx_md_params },
    { 0, NULL }
};

/*============================================================================
 * 参数表
 *===========================================================================*/

static const OSSL_PARAM sdf_sig_known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_sig_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_sig_known_gettable_ctx_md_params[] = {
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_sig_known_settable_ctx_md_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

/*============================================================================
 * 上下文管理
 *============================================================================*/

void *sdf_sm2_sig_newctx(void *provctx, const char *propq)
{
    SDF_SM2_SIG_CTX *ctx;

    (void)propq;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = (SDF_PROV_CTX *)provctx;
    ctx->key = NULL;
    ctx->mdsize = SM3_DIGEST_LENGTH;
    strcpy(ctx->mdname, "SM3");
    ctx->md = NULL;
    ctx->mdctx = NULL;
    ctx->flag_compute_z_digest = 1;
    ctx->access_granted = 0;
    ctx->password = NULL;
    ctx->password_len = 0;
    ctx->aid = NULL;
    ctx->aid_len = 0;

    /* 设置默认 SM2 ID */
    ctx->id = OPENSSL_memdup(default_sm2_id, sizeof(default_sm2_id));
    if (ctx->id == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->id_len = sizeof(default_sm2_id);

    return ctx;
}

void sdf_sm2_sig_freectx(void *vctx)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;

    if (ctx == NULL)
        return;

    /* 释放私钥访问权限 */
    if (ctx->access_granted && ctx->key != NULL &&
        ctx->key->key_index > 0 && ctx->provctx != NULL &&
        ctx->provctx->card_available) {
        SDF_CALL(ctx->provctx, SDF_ReleasePrivateKeyAccessRight,
            ctx->provctx->hSession,
            (unsigned int)ctx->key->key_index);
    }

    /* 释放密钥引用 */
    if (ctx->key != NULL)
        sdf_sm2_keymgmt_free(ctx->key);

    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->id);
    OPENSSL_free(ctx->password);
    OPENSSL_free(ctx);
}

void *sdf_sm2_sig_dupctx(void *vctx)
{
    SDF_SM2_SIG_CTX *src = (SDF_SM2_SIG_CTX *)vctx;
    SDF_SM2_SIG_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*src));
    if (dst == NULL)
        return NULL;

    *dst = *src;
    memset(&dst->md, 0, sizeof(dst->md));
    dst->mdctx = NULL;
    dst->aid = NULL;
    dst->aid_len = 0;
    dst->access_granted = 0;

    /* 增加密钥引用 */
    if (src->key != NULL) {
        CRYPTO_atomic_add(&src->key->refcnt, 1, NULL, NULL);
    }

    /* 复制 ID */
    if (src->id != NULL && src->id_len > 0) {
        dst->id = OPENSSL_memdup(src->id, src->id_len);
        if (dst->id == NULL)
            goto err;
    }

    /* 复制密码 */
    if (src->password != NULL && src->password_len > 0) {
        dst->password = OPENSSL_memdup(src->password, src->password_len);
        if (dst->password == NULL)
            goto err;
    }

    /* 复制摘要 */
    if (src->md != NULL) {
        dst->md = EVP_MD_fetch(NULL, src->mdname, NULL);
        if (dst->md == NULL)
            goto err;
    }

    /* 复制摘要上下文 */
    if (src->mdctx != NULL) {
        dst->mdctx = EVP_MD_CTX_new();
        if (dst->mdctx == NULL)
            goto err;
        if (!EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx))
            goto err;
    }

    return dst;

err:
    if (dst->key != NULL)
        CRYPTO_atomic_add(&dst->key->refcnt, -1, NULL, NULL);
    EVP_MD_CTX_free(dst->mdctx);
    EVP_MD_free(dst->md);
    OPENSSL_free(dst->id);
    OPENSSL_free(dst->password);
    OPENSSL_free(dst);
    return NULL;
}

/*============================================================================
 * 私钥访问控制
 *============================================================================*/

int sdf_sm2_acquire_private_key(SDF_SM2_SIG_CTX *ctx)
{
    int ret;

    if (ctx == NULL || ctx->key == NULL || ctx->provctx == NULL)
        return 0;

    if (ctx->provctx->card_available && ctx->key->key_index > 0) {
        /*
         * 调用 SDF_GetPrivateKeyAccessRight 获取私钥使用权
         * 如果没有设置密码，password 为 NULL，由设备决定是否允许
         */
        ret = SDF_CALL(ctx->provctx, SDF_GetPrivateKeyAccessRight,
            ctx->provctx->hSession,
            (unsigned int)ctx->key->key_index,
            ctx->password,
            (unsigned int)ctx->password_len);

        if (ret == SDR_OK) {
            ctx->access_granted = 1;
            return 1;
        }

        /* 获取失败，可能是密码错误 */
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    /* 密码卡不可用 */
    ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
    return 0;
}

void sdf_sm2_release_private_key(SDF_SM2_SIG_CTX *ctx)
{
    if (ctx == NULL || ctx->provctx == NULL || !ctx->access_granted)
        return;

    if (ctx->key != NULL && ctx->key->key_index > 0 &&
        ctx->provctx->card_available) {
        SDF_CALL(ctx->provctx, SDF_ReleasePrivateKeyAccessRight,
            ctx->provctx->hSession,
            (unsigned int)ctx->key->key_index);
    }

    ctx->access_granted = 0;
}

/*============================================================================
 * Z 值计算
 *============================================================================*/

int sdf_sm2_compute_z_digest(SDF_SM2_SIG_CTX *ctx)
{
    unsigned char *z = NULL;
    int ret = 1;

    if (!ctx->flag_compute_z_digest)
        return 1;

    ctx->flag_compute_z_digest = 0;

    if (ctx->key == NULL || ctx->key->ec_key == NULL) {
        /* 尝试从设备导出公钥 */
        if (ctx->key != NULL && ctx->key->key_index > 0) {
            if (!sdf_sm2_export_pubkey_from_device(ctx->key)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
                return 0;
            }
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
            return 0;
        }
    }

    if (ctx->md == NULL) {
        ctx->md = EVP_MD_fetch(NULL, ctx->mdname, NULL);
        if (ctx->md == NULL)
            return 0;
    }

    z = OPENSSL_zalloc(ctx->mdsize);
    if (z == NULL)
        return 0;

    /*
     * 计算 Z = SM3(ENTL || ID || a || b || xG || yA)
     * 使用 Tongsuo 的 ossl_sm2_compute_z_digest
     */
    if (!ossl_sm2_compute_z_digest(z, ctx->md, ctx->id, ctx->id_len,
                                    ctx->key->ec_key)) {
        ret = 0;
        goto err;
    }

    /* 将 Z 值喂给摘要上下文 */
    if (ctx->mdctx != NULL) {
        if (!EVP_DigestUpdate(ctx->mdctx, z, ctx->mdsize))
            ret = 0;
    }

err:
    OPENSSL_free(z);
    return ret;
}

/*============================================================================
 * 签名操作
 *============================================================================*/

int sdf_sm2_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)vkey;

    if (ctx == NULL)
        return 0;

    if (key == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (key != NULL) {
        /* 增加引用 */
        CRYPTO_atomic_add(&key->refcnt, 1, NULL, NULL);

        /* 释放旧密钥 */
        if (ctx->key != NULL)
            sdf_sm2_keymgmt_free(ctx->key);

        ctx->key = key;
        ctx->flag_compute_z_digest = 1;

        /* 重置访问控制状态 */
        if (ctx->access_granted)
            sdf_sm2_release_private_key(ctx);
    }

    return sdf_sm2_sig_set_ctx_params(ctx, params);
}

int sdf_sm2_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    OSSL_ECCSignature ecc_sig;
    int sig_byte_len = 32; /* SM2 r and s are 32 bytes each */
    int ret = 0;
    int sdf_ret;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    /* 检查摘要长度 */
    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    /* 签名大小查询 */
    if (sig == NULL) {
        /* SM2 签名: r(32) || s(32) = 64 bytes, DER 编码约 72 bytes */
        *siglen = 2 * 32; /* raw r||s */
        return 1;
    }

    /* 获取私钥访问权限 */
    if (!ctx->access_granted) {
        if (!sdf_sm2_acquire_private_key(ctx))
            return 0;
    }

    /* 调用 SDF_InternalSign_ECC 进行签名 */
    sdf_ret = SDF_CALL(ctx->provctx, SDF_InternalSign_ECC,
        ctx->provctx->hSession,
        (unsigned int)ctx->key->key_index,
        (unsigned char *)tbs, (unsigned int)tbslen,
        &ecc_sig);

    if (sdf_ret != SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        return 0;
    }

    /* 将 r||s 转为 DER 编码 (标准 SM2 签名格式) */
    {
        BIGNUM *bn_r = NULL, *bn_s = NULL;
        ECDSA_SIG *ecdsa_sig = NULL;
        int sig_len;

        int byte_len = sig_byte_len; /* SM2: 32 bytes */

        bn_r = BN_bin2bn(ecc_sig.r, byte_len, NULL);
        bn_s = BN_bin2bn(ecc_sig.s, byte_len, NULL);
        if (bn_r == NULL || bn_s == NULL)
            goto cleanup;

        ecdsa_sig = ECDSA_SIG_new();
        if (ecdsa_sig == NULL)
            goto cleanup;

        if (!ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s))
            goto cleanup;
        bn_r = NULL;
        bn_s = NULL;

        sig_len = i2d_ECDSA_SIG(ecdsa_sig, &sig);
        if (sig_len < 0)
            goto cleanup;

        *siglen = (size_t)sig_len;
        ret = 1;

cleanup:
        BN_free(bn_r);
        BN_free(bn_s);
        ECDSA_SIG_free(ecdsa_sig);
    }

    return ret;
}

/*============================================================================
 * 验签操作
 *============================================================================*/

int sdf_sm2_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)vkey;

    if (ctx == NULL)
        return 0;

    if (key == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (key != NULL) {
        CRYPTO_atomic_add(&key->refcnt, 1, NULL, NULL);
        if (ctx->key != NULL)
            sdf_sm2_keymgmt_free(ctx->key);
        ctx->key = key;
        ctx->flag_compute_z_digest = 1;
    }

    return sdf_sm2_sig_set_ctx_params(ctx, params);
}

int sdf_sm2_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    ECDSA_SIG *ecdsa_sig = NULL;
    const BIGNUM *bn_r = NULL, *bn_s = NULL;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    /* 确保有公钥 */
    if (ctx->key->ec_key == NULL || EC_KEY_get0_public_key(ctx->key->ec_key) == NULL) {
        if (ctx->key->key_index > 0 && ctx->provctx->card_available) {
            if (!sdf_sm2_export_pubkey_from_device(ctx->key))
                return 0;
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }
    }

    /* 解析 DER 编码的签名 */
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &sig, siglen);
    if (ecdsa_sig == NULL)
        return 0;

    ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);

    /* 使用 Tongsuo 的 SM2 内部验签 (本地用公钥) */
    ret = ossl_sm2_internal_verify(tbs, tbslen, sig, siglen, ctx->key->ec_key);

    ECDSA_SIG_free(ecdsa_sig);
    return ret;
}

/*============================================================================
 * 摘要签名/验签
 *============================================================================*/

int sdf_sm2_sig_digest_sign_init(void *vctx, const char *mdname,
                                  void *vkey, const OSSL_PARAM params[])
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;

    /* 设置默认值 */
    ctx->flag_compute_z_digest = 1;

    if (!sdf_sm2_sig_sign_init(vctx, vkey, params))
        return 0;

    /* 设置摘要算法 */
    if (mdname != NULL) {
        if (strlen(mdname) >= sizeof(ctx->mdname))
            return 0;
        strcpy(ctx->mdname, mdname);
    }

    /* 获取摘要 */
    if (ctx->md == NULL) {
        ctx->md = EVP_MD_fetch(NULL, ctx->mdname, NULL);
        if (ctx->md == NULL)
            return 0;
    }
    ctx->mdsize = EVP_MD_get_size(ctx->md);

    /* 初始化摘要上下文 */
    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            return 0;
    }

    if (!EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL))
        return 0;

    return 1;
}

int sdf_sm2_sig_digest_sign_update(void *vctx, const unsigned char *data,
                                    size_t datalen)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /* 首次 update 时计算 Z 值并喂入摘要 */
    if (!sdf_sm2_compute_z_digest(ctx))
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

int sdf_sm2_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                   size_t *siglen, size_t sigsize)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /* 查询大小 */
    if (sig == NULL) {
        *siglen = 2 * 32; /* r||s raw, DER 约 72 */
        return 1;
    }

    /* 完成摘要计算 */
    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    /* 用摘要结果进行签名 */
    return sdf_sm2_sig_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

int sdf_sm2_sig_digest_verify_init(void *vctx, const char *mdname,
                                    void *vkey, const OSSL_PARAM params[])
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;

    ctx->flag_compute_z_digest = 1;

    if (!sdf_sm2_sig_verify_init(vctx, vkey, params))
        return 0;

    if (mdname != NULL) {
        if (strlen(mdname) >= sizeof(ctx->mdname))
            return 0;
        strcpy(ctx->mdname, mdname);
    }

    if (ctx->md == NULL) {
        ctx->md = EVP_MD_fetch(NULL, ctx->mdname, NULL);
        if (ctx->md == NULL)
            return 0;
    }
    ctx->mdsize = EVP_MD_get_size(ctx->md);

    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            return 0;
    }

    if (!EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL))
        return 0;

    return 1;
}

int sdf_sm2_sig_digest_verify_update(void *vctx, const unsigned char *data,
                                      size_t datalen)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    if (!sdf_sm2_compute_z_digest(ctx))
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

int sdf_sm2_sig_digest_verify_final(void *vctx, const unsigned char *sig,
                                     size_t siglen)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    return sdf_sm2_sig_verify(vctx, sig, siglen, digest, (size_t)dlen);
}

/*============================================================================
 * 上下文参数
 *============================================================================*/

int sdf_sm2_sig_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        if (!OSSL_PARAM_set_utf8_string(p, ctx->mdname))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->mdsize))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, ctx->id, ctx->id_len))
            return 0;
    }

    return 1;
}

const OSSL_PARAM *sdf_sm2_sig_gettable_ctx_params(void *vctx, void *provctx)
{
    return sdf_sig_known_gettable_ctx_params;
}

int sdf_sm2_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        const char *mdname;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname))
            return 0;
        if (strlen(mdname) >= sizeof(ctx->mdname))
            return 0;
        strcpy(ctx->mdname, mdname);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p != NULL) {
        OPENSSL_free(ctx->id);
        ctx->id = NULL;
        ctx->id_len = 0;
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->id, 0, &ctx->id_len))
            return 0;
    }

    return 1;
}

const OSSL_PARAM *sdf_sm2_sig_settable_ctx_params(void *vctx, void *provctx)
{
    return sdf_sig_known_settable_ctx_params;
}

int sdf_sm2_sig_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    SDF_SM2_SIG_CTX *ctx = (SDF_SM2_SIG_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
        return 0;

    return 1;
}

const OSSL_PARAM *sdf_sm2_sig_gettable_ctx_md_params(void *vctx, void *provctx)
{
    return sdf_sig_known_gettable_ctx_md_params;
}

int sdf_sm2_sig_set_ctx_md_params(void *vctx, const OSSL_PARAM *params)
{
    /* SM2 固定使用 SM3，不接受外部设置 */
    return 1;
}

const OSSL_PARAM *sdf_sm2_sig_settable_ctx_md_params(void *vctx, void *provctx)
{
    /* SM2 固定使用 SM3 */
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    return empty;
}
