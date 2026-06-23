/*
 * SDF Provider RSA ASYM_CIPHER
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"

#define SDFPROV_RSA_KEYTYPE_SIGN 0x00010100
#define SDFPROV_RSA_KEYTYPE_ENC  0x00010200

typedef struct {
    SDF_SM2_KEY *key;
    int pad_mode;
} SDFPROV_RSA_ASYM_CTX;

static void *sdfprov_rsa_asym_newctx(void *provctx)
{
    SDFPROV_RSA_ASYM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    (void)provctx;
    if (ctx != NULL)
        ctx->pad_mode = RSA_PKCS1_PADDING;
    return ctx;
}

static int sdfprov_rsa_asym_encrypt_init(void *vctx, void *vkey,
                                         const OSSL_PARAM params[])
{
    SDFPROV_RSA_ASYM_CTX *ctx = vctx;

    (void)params;
    if (ctx == NULL || vkey == NULL)
        return 0;
    ctx->key = vkey;
    return 1;
}

static int sdfprov_rsa_asym_decrypt_init(void *vctx, void *vkey,
                                         const OSSL_PARAM params[])
{
    return sdfprov_rsa_asym_encrypt_init(vctx, vkey, params);
}

static int sdfprov_rsa_asym_encrypt(void *vctx, unsigned char *out,
                                    size_t *outlen, size_t outsize,
                                    const unsigned char *in, size_t inlen)
{
    SDFPROV_RSA_ASYM_CTX *ctx = vctx;
    unsigned char *buf = NULL;
    unsigned int olen;
    int rsa_size;
    int ret;

    if (ctx == NULL || ctx->key == NULL || ctx->key->rsa == NULL)
        return 0;

    rsa_size = RSA_size(ctx->key->rsa);
    if (out == NULL) {
        *outlen = rsa_size;
        return 1;
    }
    if (outsize < (size_t)rsa_size)
        return 0;

    buf = OPENSSL_malloc((size_t)rsa_size);
    if (buf == NULL)
        return 0;

    if (ctx->pad_mode == RSA_PKCS1_PADDING) {
        /* SDF 内部公钥运算要求输入块已按 PKCS#1 v1.5 组装。 */
        if (RSA_padding_add_PKCS1_type_2(buf, rsa_size, in, (int)inlen) != 1) {
            OPENSSL_free(buf);
            return 0;
        }
    } else if (ctx->pad_mode == RSA_NO_PADDING) {
        if (inlen != (size_t)rsa_size) {
            OPENSSL_free(buf);
            return 0;
        }
        memcpy(buf, in, inlen);
    } else {
        OPENSSL_free(buf);
        return 0;
    }

    olen = (unsigned int)outsize;
    if (RSA_bits(ctx->key->rsa) > OSSL_RSAref_MAX_BITS) {
        /* 扩展接口需要显式给出密钥用途，便于区分 sign/enc 槽位。 */
        ret = TSAPI_SDF_InternalPublicKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    buf, (unsigned int)rsa_size, out, &olen);
    } else {
        ret = TSAPI_SDF_InternalPublicKeyOperation_RSA(ctx->key->hSession,
                    ctx->key->key_index, buf, (unsigned int)rsa_size,
                    out, &olen);
    }

    OPENSSL_clear_free(buf, (size_t)rsa_size);
    if (ret != OSSL_SDR_OK)
        return 0;
    *outlen = olen;
    return 1;
}

static int sdfprov_rsa_asym_decrypt(void *vctx, unsigned char *out,
                                    size_t *outlen, size_t outsize,
                                    const unsigned char *in, size_t inlen)
{
    SDFPROV_RSA_ASYM_CTX *ctx = vctx;
    unsigned char *buf = NULL;
    unsigned int olen;
    int rsa_size;
    int ret;
    int plain_len;

    if (ctx == NULL || ctx->key == NULL || ctx->key->rsa == NULL)
        return 0;

    rsa_size = RSA_size(ctx->key->rsa);
    if (out == NULL) {
        *outlen = rsa_size;
        return 1;
    }

    buf = OPENSSL_malloc((size_t)rsa_size);
    if (buf == NULL)
        return 0;

    if (ctx->key->key_password != NULL) {
        ret = TSAPI_SDF_GetPrivateKeyAccessRight(ctx->key->hSession,
                                                 ctx->key->key_index,
                                                 (unsigned char *)ctx->key->key_password,
                                                 (unsigned int)strlen(ctx->key->key_password));
        if (ret != OSSL_SDR_OK) {
            OPENSSL_free(buf);
            return 0;
        }
    }

    olen = (unsigned int)rsa_size;
    if (RSA_bits(ctx->key->rsa) > OSSL_RSAref_MAX_BITS) {
        /* 3072/4096 位解密走 _Ex 接口。 */
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, buf, &olen);
    } else {
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA(ctx->key->hSession,
                    ctx->key->key_index, (unsigned char *)in,
                    (unsigned int)inlen, buf, &olen);
    }

    if (ctx->key->key_password != NULL)
        TSAPI_SDF_ReleasePrivateKeyAccessRight(ctx->key->hSession, ctx->key->key_index);

    if (ret != OSSL_SDR_OK) {
        OPENSSL_clear_free(buf, (size_t)rsa_size);
        return 0;
    }

    if (ctx->pad_mode == RSA_PKCS1_PADDING)
        plain_len = RSA_padding_check_PKCS1_type_2(out, (int)outsize, buf,
                                                   (int)olen, rsa_size);
    else if (ctx->pad_mode == RSA_NO_PADDING) {
        if (outsize < olen) {
            OPENSSL_clear_free(buf, (size_t)rsa_size);
            return 0;
        }
        memcpy(out, buf, olen);
        plain_len = (int)olen;
    } else {
        OPENSSL_clear_free(buf, (size_t)rsa_size);
        return 0;
    }

    OPENSSL_clear_free(buf, (size_t)rsa_size);
    if (plain_len < 0)
        return 0;
    *outlen = (size_t)plain_len;
    return 1;
}

static void sdfprov_rsa_asym_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

const OSSL_DISPATCH sdfprov_rsa_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))sdfprov_rsa_asym_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
      (void (*)(void))sdfprov_rsa_asym_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))sdfprov_rsa_asym_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
      (void (*)(void))sdfprov_rsa_asym_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))sdfprov_rsa_asym_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))sdfprov_rsa_asym_freectx },
    OSSL_DISPATCH_END
};
