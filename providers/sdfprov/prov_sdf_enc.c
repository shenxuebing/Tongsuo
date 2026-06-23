/*
 * SDF Provider for Tongsuo - SM2 Asymmetric Cipher Module Implementation
 *
 * 加密: 使用公钥通过 SDF_InternalEncrypt_ECC 或本地计算
 * 解密: 使用私钥通过 SDF_InternalDecrypt_ECC 在密码卡上完成
 */

#include "prov_sdf_enc.h"
#include "prov_sdf_keys.h"
#include <openssl/evp.h>
#include <openssl/sm3.h>
#include <crypto/sm2.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <crypto/sm2.h>
#include <string.h>

/*============================================================================
 * 算法定义和分发表
 *===========================================================================*/

const OSSL_ALGORITHM sdf_asym_cipher_sm2[] = {
    { "SM2", "provider=sdfprov", sdf_sm2_enc_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};

const OSSL_DISPATCH sdf_sm2_enc_dispatch[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX,              (void (*)(void))sdf_sm2_enc_newctx },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX,             (void (*)(void))sdf_sm2_enc_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX,              (void (*)(void))sdf_sm2_enc_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,        (void (*)(void))sdf_sm2_enc_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT,             (void (*)(void))sdf_sm2_enc_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,        (void (*)(void))sdf_sm2_enc_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT,             (void (*)(void))sdf_sm2_enc_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,      (void (*)(void))sdf_sm2_enc_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm2_enc_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,      (void (*)(void))sdf_sm2_enc_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm2_enc_settable_ctx_params },
    { 0, NULL }
};

/*============================================================================
 * 参数表
 *===========================================================================*/

static const OSSL_PARAM enc_known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM enc_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_int("sm2_encdata_format", NULL),
    OSSL_PARAM_END
};

/*============================================================================
 * 上下文管理
 *============================================================================*/

void *sdf_sm2_enc_newctx(void *provctx)
{
    SDF_SM2_ENC_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = (SDF_PROV_CTX *)provctx;
    ctx->key = NULL;
    ctx->md = EVP_MD_fetch(NULL, "SM3", NULL);
    ctx->encdata_format = 1; /* 默认 C1C3C2 格式 */
    ctx->access_granted = 0;
    ctx->password = NULL;
    ctx->password_len = 0;

    return ctx;
}

void sdf_sm2_enc_freectx(void *vctx)
{
    SDF_SM2_ENC_CTX *ctx = (SDF_SM2_ENC_CTX *)vctx;

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

    if (ctx->key != NULL)
        sdf_sm2_keymgmt_free(ctx->key);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx->password);
    OPENSSL_free(ctx);
}

void *sdf_sm2_enc_dupctx(void *vctx)
{
    SDF_SM2_ENC_CTX *src = (SDF_SM2_ENC_CTX *)vctx;
    SDF_SM2_ENC_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*src));
    if (dst == NULL)
        return NULL;

    *dst = *src;
    dst->access_granted = 0;

    if (src->key != NULL)
        CRYPTO_atomic_add(&src->key->refcnt, 1, NULL, NULL);

    if (src->md != NULL)
        dst->md = EVP_MD_fetch(NULL, "SM3", NULL);

    if (src->password != NULL && src->password_len > 0) {
        dst->password = OPENSSL_memdup(src->password, src->password_len);
        if (dst->password == NULL)
            goto err;
    }

    return dst;

err:
    if (src->key != NULL)
        CRYPTO_atomic_add(&src->key->refcnt, -1, NULL, NULL);
    EVP_MD_free(dst->md);
    OPENSSL_free(dst->password);
    OPENSSL_free(dst);
    return NULL;
}

/*============================================================================
 * 私钥访问控制 (解密时需要)
 *===========================================================================*/

static int sdf_sm2_enc_acquire_private_key(SDF_SM2_ENC_CTX *ctx)
{
    int ret;

    if (ctx == NULL || ctx->key == NULL || ctx->provctx == NULL)
        return 0;

    if (ctx->provctx->card_available && ctx->key->key_index > 0) {
        ret = SDF_CALL(ctx->provctx, SDF_GetPrivateKeyAccessRight,
            ctx->provctx->hSession,
            (unsigned int)ctx->key->key_index,
            ctx->password,
            (unsigned int)ctx->password_len);

        if (ret == SDR_OK) {
            ctx->access_granted = 1;
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
    return 0;
}

/*============================================================================
 * 加密
 *============================================================================*/

int sdf_sm2_enc_encrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    SDF_SM2_ENC_CTX *ctx = (SDF_SM2_ENC_CTX *)vctx;
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)vkey;

    if (ctx == NULL)
        return 0;

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    /* 确保有公钥 */
    if (key->ec_key == NULL || EC_KEY_get0_public_key(key->ec_key) == NULL) {
        if (key->key_index > 0 && ctx->provctx != NULL &&
            ctx->provctx->card_available) {
            if (!sdf_sm2_export_pubkey_from_device(key))
                return 0;
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }
    }

    CRYPTO_atomic_add(&key->refcnt, 1, NULL, NULL);
    if (ctx->key != NULL)
        sdf_sm2_keymgmt_free(ctx->key);
    ctx->key = key;

    return sdf_sm2_enc_set_ctx_params(ctx, params);
}

int sdf_sm2_enc_encrypt(void *vctx, unsigned char *out, size_t *outlen,
                         size_t outsize, const unsigned char *in, size_t inlen)
{
    SDF_SM2_ENC_CTX *ctx = (SDF_SM2_ENC_CTX *)vctx;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ctx->md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }

    /* 大小查询 */
    if (out == NULL) {
        if (!ossl_sm2_ciphertext_size(ctx->key->ec_key, ctx->md,
                                       inlen, outlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }
        return 1;
    }

    /* 加密使用本地公钥 (不需要密码卡参与) */
    return ossl_sm2_encrypt_ex(ctx->key->ec_key, ctx->md, in, inlen,
                               out, outlen, ctx->encdata_format);
}

/*============================================================================
 * 解密 (通过密码卡)
 *============================================================================*/

int sdf_sm2_enc_decrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    SDF_SM2_ENC_CTX *ctx = (SDF_SM2_ENC_CTX *)vctx;
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)vkey;

    if (ctx == NULL)
        return 0;

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    CRYPTO_atomic_add(&key->refcnt, 1, NULL, NULL);
    if (ctx->key != NULL)
        sdf_sm2_keymgmt_free(ctx->key);
    ctx->key = key;

    /* 重置访问控制 */
    if (ctx->access_granted) {
        if (ctx->key->key_index > 0 && ctx->provctx != NULL &&
            ctx->provctx->card_available) {
            SDF_CALL(ctx->provctx, SDF_ReleasePrivateKeyAccessRight,
                ctx->provctx->hSession,
                (unsigned int)ctx->key->key_index);
        }
        ctx->access_granted = 0;
    }

    return sdf_sm2_enc_set_ctx_params(ctx, params);
}

int sdf_sm2_enc_decrypt(void *vctx, unsigned char *out, size_t *outlen,
                         size_t outsize, const unsigned char *in, size_t inlen)
{
    SDF_SM2_ENC_CTX *ctx = (SDF_SM2_ENC_CTX *)vctx;
    OSSL_ECCCipher ecc_cipher = { 0 };
    int sdf_ret;
    unsigned int plain_len = 0;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    /* 大小查询 */
    if (out == NULL) {
        if (!ossl_sm2_plaintext_size_ex(in, inlen, outlen,
                                        ctx->encdata_format))
            return 0;
        return 1;
    }

    /* 获取私钥访问权限 */
    if (!ctx->access_granted) {
        if (!sdf_sm2_enc_acquire_private_key(ctx))
            return 0;
    }

    /*
     * 解密需要将输入数据转换为 OSSL_ECCCipher 格式
     * OSSL_ECCCipher 结构: x(64) || y(64) || M(32) || L(4) || C(N)
     *
     * SM2 密文格式 (C1C3C2):
     * C1 (65 bytes, 未压缩点) || C3 (32 bytes, SM3 hash) || C2 (N bytes, 密文)
     *
     * 这里需要将标准 SM2 密文转换为 SDF 的 ECCCipher 格式
     */
    {
        unsigned char c1[65]; /* 未压缩点 */
        unsigned char *c3 = NULL;
        unsigned char *c2 = NULL;
        size_t c3_len = 32;
        size_t c2_len;
        const unsigned char *p = in;
        EC_POINT *point = NULL;
        BIGNUM *bn_x = NULL, *bn_y = NULL;
        int c1c3c2 = 1; /* C1C3C2 format */
        const EC_GROUP *group = NULL;

        if (ctx->encdata_format == 0) {
            /* ASN1 格式 — 暂不支持通过卡解密，回退到本地 */
            return ossl_sm2_decrypt_ex(ctx->key->ec_key, ctx->md,
                                       in, inlen, out, outlen,
                                       ctx->encdata_format);
        }

        /* C1C3C2 格式: 0x04 || X(32) || Y(32) || C3(32) || C2(N) */
        if (inlen < 97) { /* 65 + 32 至少 */
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return 0;
        }

        /* 解析 C1 */
        if (p[0] != 0x04) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
            return 0;
        }
        memcpy(c1, p, 65);
        p += 65;

        /* C3 */
        c3 = (unsigned char *)p;
        p += c3_len;

        /* C2 */
        c2_len = inlen - 97;
        c2 = (unsigned char *)p;

        /* 转换为 OSSL_ECCCipher */
        if (ctx->key->ec_key != NULL) {
            group = EC_KEY_get0_group(ctx->key->ec_key);
        } else {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            return 0;
        }

        point = EC_POINT_new(group);
        if (point == NULL)
            return 0;

        if (!EC_POINT_oct2point(group, point, c1, 65, NULL)) {
            EC_POINT_free(point);
            return 0;
        }

        bn_x = BN_new();
        bn_y = BN_new();
        if (bn_x == NULL || bn_y == NULL) {
            EC_POINT_free(point);
            BN_free(bn_x);
            BN_free(bn_y);
            return 0;
        }

        if (!EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y, NULL)) {
            EC_POINT_free(point);
            BN_free(bn_x);
            BN_free(bn_y);
            return 0;
        }

        memset(&ecc_cipher, 0, sizeof(ecc_cipher));
        BN_bn2binpad(bn_x, ecc_cipher.x, 32);
        BN_bn2binpad(bn_y, ecc_cipher.y, 32);
        memcpy(ecc_cipher.M, c3, c3_len);
        ecc_cipher.L = (unsigned int)c2_len;
        memcpy(ecc_cipher.C, c2, c2_len);
        /* Note: OSSL_ECCCipher has no bits field - r and s are fixed 32 bytes */

        EC_POINT_free(point);
        BN_free(bn_x);
        BN_free(bn_y);
    }

    /* 调用 SDF_InternalDecrypt_ECC 解密 */
    sdf_ret = SDF_CALL(ctx->provctx, SDF_InternalDecrypt_ECC,
        ctx->provctx->hSession,
        (unsigned int)ctx->key->key_index,
        0x00000201, /* SGD_SM2 */
        &ecc_cipher,
        out, &plain_len);

    if (sdf_ret != SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
        return 0;
    }

    *outlen = plain_len;
    return 1;
}

/*============================================================================
 * 上下文参数
 *============================================================================*/

int sdf_sm2_enc_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    SDF_SM2_ENC_CTX *ctx = (SDF_SM2_ENC_CTX *)vctx;
    OSSL_PARAM *p;

    if (vctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
    if (p != NULL) {
        const char *name = (ctx->md != NULL) ? EVP_MD_get0_name(ctx->md) : "";
        if (!OSSL_PARAM_set_utf8_string(p, name))
            return 0;
    }

    return 1;
}

const OSSL_PARAM *sdf_sm2_enc_gettable_ctx_params(void *vctx, void *provctx)
{
    return enc_known_gettable_ctx_params;
}

int sdf_sm2_enc_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SDF_SM2_ENC_CTX *ctx = (SDF_SM2_ENC_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
    if (p != NULL) {
        const char *mdname;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname))
            return 0;
        /* SM2 加解密固定使用 SM3 */
        if (OPENSSL_strcasecmp(mdname, "SM3") != 0) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST, "digest=%s", mdname);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, "sm2_encdata_format");
    if (p != NULL)
        OSSL_PARAM_get_int(p, &ctx->encdata_format);

    return 1;
}

const OSSL_PARAM *sdf_sm2_enc_settable_ctx_params(void *vctx, void *provctx)
{
    return enc_known_settable_ctx_params;
}
