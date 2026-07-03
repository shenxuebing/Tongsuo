/*
 * SDF Provider RSA ASYM_CIPHER
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>
#include "internal/tlog.h"
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "sdfprov_ctx.h"

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
    if (ctx == NULL || vkey == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    ctx->key = vkey;
    TLOG_DEBUG("rsa_asym_init: key_index=%u key_type=%d session=%p external_session=%d",
               ctx->key->key_index, ctx->key->key_type, ctx->key->hSession,
               ctx->key->external_session);
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

    if (ctx == NULL || ctx->key == NULL || ctx->key->rsa == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    rsa_size = RSA_size(ctx->key->rsa);
    if (out == NULL) {
        *outlen = rsa_size;
        return 1;
    }
    if (outsize < (size_t)rsa_size) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "outsize=%zu rsa_size=%d", outsize, rsa_size);
        return 0;
    }

    buf = OPENSSL_malloc((size_t)rsa_size);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (ctx->pad_mode == RSA_PKCS1_PADDING) {
        /* SDF 内部公钥运算要求输入块已按 PKCS#1 v1.5 组装。 */
        if (RSA_padding_add_PKCS1_type_2(buf, rsa_size, in, (int)inlen) != 1) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                           "PKCS1 type 2 padding failed: inlen=%zu rsa_size=%d",
                           inlen, rsa_size);
            OPENSSL_free(buf);
            return 0;
        }
    } else if (ctx->pad_mode == RSA_NO_PADDING) {
        if (inlen != (size_t)rsa_size) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                           "RSA_NO_PADDING requires inlen=%d, got %zu",
                           rsa_size, inlen);
            OPENSSL_free(buf);
            return 0;
        }
        memcpy(buf, in, inlen);
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                       "unsupported pad_mode=%d", ctx->pad_mode);
        OPENSSL_free(buf);
        return 0;
    }

    olen = (unsigned int)outsize;
    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();
    if (sdfctx == NULL) {
        OPENSSL_clear_free(buf, (size_t)rsa_size);
        return 0;
    }

    if (RSA_bits(ctx->key->rsa) > OSSL_RSAref_MAX_BITS) {
        /* 3072/4096 位加密必须走 _Ex 接口（RSAref 结构装不下）。 */
        TLOG_DEBUG("rsa_encrypt: using RSA_Ex key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList.InternalPublicKeyOperation_RSA_Ex == NULL) {
            OPENSSL_clear_free(buf, (size_t)rsa_size);
            return 0;
        }
        ret = sdfctx->sdfList.InternalPublicKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    buf, (unsigned int)rsa_size, out, &olen);
    } else if (sdfctx->sdfList.InternalPublicKeyOperation_RSA_Ex != NULL) {
        /*
         * 2048 位及以下：优先走 _Ex 接口（与 decrypt 对称）。
         * 标准版 InternalPublicKeyOperation_RSA 不带 uiKeyUsage，
         * 设备无法区分 sign/enc 密钥槽位。
         */
        TLOG_DEBUG("rsa_encrypt: using RSA_Ex key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        ret = sdfctx->sdfList.InternalPublicKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    buf, (unsigned int)rsa_size, out, &olen);
    } else {
        /* 回退：厂商库不支持 _Ex，用标准接口（无法区分 sign/enc） */
        TLOG_DEBUG("rsa_encrypt: using RSA(legacy) key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList.InternalPublicKeyOperation_RSA == NULL) {
            OPENSSL_clear_free(buf, (size_t)rsa_size);
            return 0;
        }
        ret = sdfctx->sdfList.InternalPublicKeyOperation_RSA(ctx->key->hSession,
                    ctx->key->key_index, buf, (unsigned int)rsa_size,
                    out, &olen);
    }

    OPENSSL_clear_free(buf, (size_t)rsa_size);
    if (ret != OSSL_SDR_OK) {
        TLOG_ERROR("rsa_encrypt: InternalPublicKeyOperation failed key_index=%u ret=0x%08x",
                   ctx->key->key_index, ret);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED,
                       "rsa internal public op failed: key_index=%u ret=0x%08x",
                       ctx->key->key_index, ret);
        return 0;
    }
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

    if (ctx == NULL || ctx->key == NULL || ctx->key->rsa == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    rsa_size = RSA_size(ctx->key->rsa);
    if (out == NULL) {
        *outlen = rsa_size;
        return 1;
    }

    buf = OPENSSL_malloc((size_t)rsa_size);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();
    if (sdfctx == NULL) {
        OPENSSL_free(buf);
        return 0;
    }

    if (ctx->key->key_password != NULL) {
        if (sdfctx->sdfList.GetPrivateKeyAccessRight == NULL) {
            OPENSSL_free(buf);
            return 0;
        }
        ret = sdfctx->sdfList.GetPrivateKeyAccessRight(ctx->key->hSession,
                                                    ctx->key->key_index,
                                                    (unsigned char *)ctx->key->key_password,
                                                    (unsigned int)strlen(ctx->key->key_password));
        if (ret != OSSL_SDR_OK) {
            TLOG_ERROR("rsa_decrypt: GetPrivateKeyAccessRight failed key_index=%u ret=0x%08x",
                       ctx->key->key_index, ret);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT,
                           "get private key access right failed: key_index=%u ret=0x%08x",
                           ctx->key->key_index, ret);
            OPENSSL_free(buf);
            return 0;
        }
    }

    olen = (unsigned int)rsa_size;
    if (RSA_bits(ctx->key->rsa) > OSSL_RSAref_MAX_BITS) {
        /* 3072/4096 位解密必须走 _Ex 接口（RSAref 结构装不下）。 */
        TLOG_DEBUG("rsa_decrypt: using RSA_Ex key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList.InternalPrivateKeyOperation_RSA_Ex == NULL) {
            if (ctx->key->key_password != NULL && sdfctx->sdfList.ReleasePrivateKeyAccessRight != NULL)
                sdfctx->sdfList.ReleasePrivateKeyAccessRight(ctx->key->hSession, ctx->key->key_index);
            OPENSSL_free(buf);
            return 0;
        }
        ret = sdfctx->sdfList.InternalPrivateKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, buf, &olen);
    } else if (sdfctx->sdfList.InternalPrivateKeyOperation_RSA_Ex != NULL) {
        /*
         * 2048 位及以下：优先走 _Ex 接口。
         * 标准版 InternalPrivateKeyOperation_RSA 不带 uiKeyUsage 参数，
         * 设备无法区分 sign/enc 密钥槽位，会固定使用 sign 私钥；
         * 对于 enc 密钥（key_type=1）的解密会得到错误结果。
         * _Ex 接口通过 uiKeyUsage 显式指定密钥用途，可正确路由。
         */
        TLOG_DEBUG("rsa_decrypt: using RSA_Ex key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        ret = sdfctx->sdfList.InternalPrivateKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, buf, &olen);
    } else {
        /* 回退：厂商库不支持 _Ex，用标准接口（无法区分 sign/enc，仅 sign 密钥可用） */
        TLOG_DEBUG("rsa_decrypt: using RSA(legacy) key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList.InternalPrivateKeyOperation_RSA == NULL) {
            if (ctx->key->key_password != NULL && sdfctx->sdfList.ReleasePrivateKeyAccessRight != NULL)
                sdfctx->sdfList.ReleasePrivateKeyAccessRight(ctx->key->hSession, ctx->key->key_index);
            OPENSSL_free(buf);
            return 0;
        }
        ret = sdfctx->sdfList.InternalPrivateKeyOperation_RSA(ctx->key->hSession,
                    ctx->key->key_index, (unsigned char *)in,
                    (unsigned int)inlen, buf, &olen);
    }

    if (ctx->key->key_password != NULL) {
        if (sdfctx->sdfList.ReleasePrivateKeyAccessRight != NULL)
            sdfctx->sdfList.ReleasePrivateKeyAccessRight(ctx->key->hSession, ctx->key->key_index);
    }

    if (ret != OSSL_SDR_OK) {
        TLOG_ERROR("rsa_decrypt: InternalPrivateKeyOperation failed key_index=%u ret=0x%08x",
                   ctx->key->key_index, ret);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT,
                       "rsa internal private op failed: key_index=%u ret=0x%08x",
                       ctx->key->key_index, ret);
        OPENSSL_clear_free(buf, (size_t)rsa_size);
        return 0;
    }

    TLOG_DEBUG("rsa_decrypt: SDF returned olen=%u pad_mode=%d", olen, ctx->pad_mode);

    if (ctx->pad_mode == RSA_PKCS1_PADDING)
        plain_len = RSA_padding_check_PKCS1_type_2(out, (int)outsize, buf,
                                                   (int)olen, rsa_size);
    else if (ctx->pad_mode == RSA_NO_PADDING) {
        if (outsize < olen) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                           "outsize=%zu plaintext_len=%u", outsize, olen);
            OPENSSL_clear_free(buf, (size_t)rsa_size);
            return 0;
        }
        memcpy(out, buf, olen);
        plain_len = (int)olen;
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_PADDING_MODE,
                       "unsupported pad_mode=%d", ctx->pad_mode);
        OPENSSL_clear_free(buf, (size_t)rsa_size);
        return 0;
    }

    OPENSSL_clear_free(buf, (size_t)rsa_size);
    if (plain_len < 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
        return 0;
    }
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
