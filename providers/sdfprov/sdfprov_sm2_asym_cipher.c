/*
 * SDF Provider SM2 ASYM_CIPHER
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/sdf.h>
#include <openssl/sgd.h>
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "sdfprov_utils.h"
#include "sdfprov_ctx.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    SDF_SM2_KEY *key;
    int encdata_format;         /* 0=C1C3C2, 1=C1C2C3 */
} SDFPROV_SM2_ASYM_CTX;

static void *sdfprov_sm2_asym_newctx(void *provctx)
{
    SDFPROV_SM2_ASYM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
}

static int sdfprov_sm2_asym_encrypt_init(void *vctx, void *vkey,
                                          const OSSL_PARAM params[])
{
    SDFPROV_SM2_ASYM_CTX *ctx = vctx;
    if (ctx == NULL || vkey == NULL)
        return 0;
    ctx->key = vkey;
    return 1;
}

static int sdfprov_sm2_asym_encrypt(void *vctx, unsigned char *out,
                                     size_t *outlen, size_t outsize,
                                     const unsigned char *in, size_t inlen)
{
    SDFPROV_SM2_ASYM_CTX *ctx = vctx;
    SDF_SM2_KEY *key;
    OSSL_ECCCipher *cipher = NULL;
    unsigned char *der = NULL;
    size_t der_len = 0;
    size_t cipher_alloc;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    key = ctx->key;

    if (out == NULL) {
        /* 返回所需最大缓冲区大小 */
        *outlen = inlen + 256;
        return 1;
    }

    if (!key->is_hardware_key) {
        /* 软件路径: 未实现（需要软件 SM2 加密支持时使用 default provider） */
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
        return 0;
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

    /* 分配 OSSL_ECCCipher，C 数组足够容纳明文 + 一些余量 */
    cipher_alloc = offsetof(OSSL_ECCCipher, C) + inlen + 64;
    cipher = OPENSSL_zalloc(cipher_alloc);
    if (cipher == NULL)
        return 0;

    if (TSAPI_SDF_InternalEncrypt_ECC(key->hSession, key->key_index,
                                       OSSL_SGD_SM2_3,
                                       (unsigned char *)in,
                                       (unsigned int)inlen,
                                       cipher) != OSSL_SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
        goto end;
    }

    /* 转换 OSSL_ECCCipher -> SM2 密文 DER */
    if (!sdfprov_ecccipher_to_sm2_der(cipher, &der, &der_len,
                                       ctx->encdata_format))
        goto end;

    if (der_len > outsize) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
        goto end;
    }

    memcpy(out, der, der_len);
    *outlen = der_len;
    ret = 1;

end:
    OPENSSL_free(der);
    OPENSSL_free(cipher);
    return ret;
}

static int sdfprov_sm2_asym_decrypt_init(void *vctx, void *vkey,
                                          const OSSL_PARAM params[])
{
    SDFPROV_SM2_ASYM_CTX *ctx = vctx;
    if (ctx == NULL || vkey == NULL)
        return 0;
    ctx->key = vkey;
    return 1;
}

static int sdfprov_sm2_asym_decrypt(void *vctx, unsigned char *out,
                                     size_t *outlen, size_t outsize,
                                     const unsigned char *in, size_t inlen)
{
    SDFPROV_SM2_ASYM_CTX *ctx = vctx;
    SDF_SM2_KEY *key;
    OSSL_ECCCipher *cipher = NULL;
    size_t cipher_alloc;
    unsigned int plaintext_len = 0;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    key = ctx->key;

    if (out == NULL) {
        *outlen = inlen;
        return 1;
    }

    if (!key->is_hardware_key) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
        return 0;
    }

    if (key->hSession == NULL) {
        /* 尝试从全局上下文获取会话 */
        SDFPROV_CTX *sdfctx2 = sdfprov_get_global_ctx();
        if (sdfctx2 == NULL || !sdfctx2->initialized)
            return 0;
        key->hSession = sdfctx2->hSession;
    }

    if (key->hSession == NULL)
        return 0;

    /* 分配 OSSL_ECCCipher */
    cipher_alloc = offsetof(OSSL_ECCCipher, C) + inlen + 64;
    cipher = OPENSSL_zalloc(cipher_alloc);
    if (cipher == NULL)
        return 0;

    /* DER -> OSSL_ECCCipher */
    if (!sdfprov_sm2_der_to_ecccipher(in, inlen, cipher, ctx->encdata_format,
                                       cipher_alloc - offsetof(OSSL_ECCCipher, C))) {
        goto end;
    }

    /* 获取私钥访问权限 */
    {
        const char *pwd = key->key_password;
        int auth_ret = TSAPI_SDF_GetPrivateKeyAccessRight(
            key->hSession, key->key_index,
            (unsigned char *)pwd,
            pwd != NULL ? (unsigned int)strlen(pwd) : 0);
        if (auth_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT,
                           "GetPrivateKeyAccessRight failed: 0x%08x", auth_ret);
            goto end;
        }
    }

    /* 硬件解密 */
    plaintext_len = (unsigned int)outsize;
    int sdf_ret = TSAPI_SDF_InternalDecrypt_ECC(key->hSession, key->key_index,
                                                  OSSL_SGD_SM2_3,
                                                  cipher, out,
                                                  &plaintext_len);
    /* 释放私钥访问权限 */
    TSAPI_SDF_ReleasePrivateKeyAccessRight(key->hSession, key->key_index);

    if (sdf_ret != OSSL_SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
        goto end;
    }

    *outlen = plaintext_len;
    ret = 1;

end:
    OPENSSL_free(cipher);
    return ret;
}

static void sdfprov_sm2_asym_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

const OSSL_DISPATCH sdfprov_sm2_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))sdfprov_sm2_asym_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
      (void (*)(void))sdfprov_sm2_asym_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))sdfprov_sm2_asym_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
      (void (*)(void))sdfprov_sm2_asym_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))sdfprov_sm2_asym_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))sdfprov_sm2_asym_freectx },
    OSSL_DISPATCH_END
};
