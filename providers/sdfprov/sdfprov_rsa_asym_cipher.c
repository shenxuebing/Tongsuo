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
#include <openssl/ssl.h>
#include "internal/tlog.h"
#include "crypto/rsa.h"
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "sdfprov_ctx.h"
#include "sdfprov_utils.h"

#define SDFPROV_RSA_KEYTYPE_SIGN 0x00010100
#define SDFPROV_RSA_KEYTYPE_ENC  0x00010200

typedef struct {
    SDF_SM2_KEY *key;
    int pad_mode;
    unsigned int client_version;
    unsigned int alt_version;
    unsigned int implicit_rejection;
} SDFPROV_RSA_ASYM_CTX;

static int sdfprov_rsa_public_encrypt_hw(SDFPROV_RSA_ASYM_CTX *ctx,
                                         const unsigned char *in, size_t inlen,
                                         unsigned char *out,
                                         unsigned int *outlen)
{
    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();
    int rsa_bits;

    if (ctx == NULL || ctx->key == NULL || ctx->key->rsa == NULL
        || out == NULL || outlen == NULL)
        return OSSL_SDR_INARGERR;

    if (sdfctx == NULL)
        return OSSL_SDR_NOTSUPPORT;

    rsa_bits = RSA_bits(ctx->key->rsa);
    if (rsa_bits > OSSL_RSAref_MAX_BITS) {
        OSSL_RSArefPublicKeyEx pub_ex;

        if (!sdfprov_rsa_to_pubkeyex(ctx->key->rsa, &pub_ex))
            return OSSL_SDR_OUTARGERR;

        if (sdfctx->sdfList->ExternalPublicKeyOperation_RSAEx != NULL)
            return TSAPI_SDF_ExternalPublicKeyOperation_RSAEx(ctx->key->hSession,
                                                              &pub_ex,
                                                              (unsigned char *)in,
                                                              (unsigned int)inlen,
                                                              out, outlen);

        if (sdfctx->sdfList->InternalPublicKeyOperation_RSA_Ex != NULL)
            return TSAPI_SDF_InternalPublicKeyOperation_RSA_Ex(ctx->key->hSession,
                        ctx->key->key_index,
                        ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                                : SDFPROV_RSA_KEYTYPE_ENC,
                        (unsigned char *)in, (unsigned int)inlen, out, outlen);

        return OSSL_SDR_NOTSUPPORT;
    }

    if (sdfctx->sdfList->ExternalPublicKeyOperation_RSA != NULL) {
        OSSL_RSArefPublicKey pub;

        if (!sdfprov_rsa_to_pubkey(ctx->key->rsa, &pub))
            return OSSL_SDR_OUTARGERR;

        return TSAPI_SDF_ExternalPublicKeyOperation_RSA(ctx->key->hSession,
                                                        &pub,
                                                        (unsigned char *)in,
                                                        (unsigned int)inlen,
                                                        out, outlen);
    }

    if (sdfctx->sdfList->ExternalPublicKeyOperation_RSAEx != NULL) {
        OSSL_RSArefPublicKeyEx pub_ex;

        if (!sdfprov_rsa_to_pubkeyex(ctx->key->rsa, &pub_ex))
            return OSSL_SDR_OUTARGERR;

        return TSAPI_SDF_ExternalPublicKeyOperation_RSAEx(ctx->key->hSession,
                                                          &pub_ex,
                                                          (unsigned char *)in,
                                                          (unsigned int)inlen,
                                                          out, outlen);
    }

    if (sdfctx->sdfList->InternalPublicKeyOperation_RSA_Ex != NULL)
        return TSAPI_SDF_InternalPublicKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, out, outlen);

    if (sdfctx->sdfList->InternalPublicKeyOperation_RSA != NULL)
        return TSAPI_SDF_InternalPublicKeyOperation_RSA(ctx->key->hSession,
                                                        ctx->key->key_index,
                                                        (unsigned char *)in,
                                                        (unsigned int)inlen,
                                                        out, outlen);

    return OSSL_SDR_NOTSUPPORT;
}

static void *sdfprov_rsa_asym_newctx(void *provctx)
{
    SDFPROV_RSA_ASYM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    (void)provctx;
    if (ctx != NULL) {
        ctx->pad_mode = RSA_PKCS1_PADDING;
        ctx->implicit_rejection = 1;
    }
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
    if (ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING) {
        if (out == NULL) {
            *outlen = SSL_MAX_MASTER_KEY_LENGTH;
            return 1;
        }
        if (outsize < SSL_MAX_MASTER_KEY_LENGTH) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_LENGTH,
                           "outsize=%zu need=%d",
                           outsize, SSL_MAX_MASTER_KEY_LENGTH);
            return 0;
        }
    } else if (out == NULL) {
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

    TLOG_DEBUG("rsa_encrypt: key_index=%u key_type=%d bits=%d",
               ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
    olen = (unsigned int)outsize;
    ret = sdfprov_rsa_public_encrypt_hw(ctx, buf, (size_t)rsa_size, out, &olen);

    OPENSSL_clear_free(buf, (size_t)rsa_size);
    if (ret != OSSL_SDR_OK) {
        TLOG_ERROR("rsa_encrypt: RSA public operation failed key_index=%u ret=0x%08x",
                   ctx->key->key_index, ret);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED,
                       "rsa public op failed: key_index=%u ret=0x%08x",
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
    SDFPROV_CTX *sdfctx = NULL;

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

    sdfctx = sdfprov_get_global_ctx();
    if (sdfctx == NULL) {
        OPENSSL_free(buf);
        return 0;
    }

    if (ctx->key->key_password != NULL) {
        if (sdfctx->sdfList->GetPrivateKeyAccessRight == NULL) {
            OPENSSL_free(buf);
            return 0;
        }
        ret = TSAPI_SDF_GetPrivateKeyAccessRight(ctx->key->hSession,
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
        TLOG_DEBUG("rsa_decrypt: using RSA_Ex key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList->InternalPrivateKeyOperation_RSA_Ex == NULL) {
            if (ctx->key->key_password != NULL
                && sdfctx->sdfList->ReleasePrivateKeyAccessRight != NULL)
                TSAPI_SDF_ReleasePrivateKeyAccessRight(ctx->key->hSession,
                                                       ctx->key->key_index);
            OPENSSL_free(buf);
            return 0;
        }
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, buf, &olen);
    } else if (sdfctx->sdfList->InternalPrivateKeyOperation_RSA_Ex != NULL) {
        TLOG_DEBUG("rsa_decrypt: using RSA_Ex key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, buf, &olen);
    } else {
        TLOG_DEBUG("rsa_decrypt: using RSA(legacy) key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList->InternalPrivateKeyOperation_RSA == NULL) {
            if (ctx->key->key_password != NULL
                && sdfctx->sdfList->ReleasePrivateKeyAccessRight != NULL)
                TSAPI_SDF_ReleasePrivateKeyAccessRight(ctx->key->hSession,
                                                       ctx->key->key_index);
            OPENSSL_free(buf);
            return 0;
        }
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA(ctx->key->hSession,
                    ctx->key->key_index, (unsigned char *)in,
                    (unsigned int)inlen, buf, &olen);
    }

    if (ctx->key->key_password != NULL
        && sdfctx->sdfList->ReleasePrivateKeyAccessRight != NULL)
        TSAPI_SDF_ReleasePrivateKeyAccessRight(ctx->key->hSession,
                                               ctx->key->key_index);

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

    if (ctx->pad_mode == RSA_PKCS1_WITH_TLS_PADDING) {
        if (ctx->client_version == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_TLS_CLIENT_VERSION);
            OPENSSL_clear_free(buf, (size_t)rsa_size);
            return 0;
        }
        plain_len = ossl_rsa_padding_check_PKCS1_type_2_TLS(ctx->key->libctx,
                                                            out, outsize,
                                                            buf, (size_t)olen,
                                                            (int)ctx->client_version,
                                                            (int)ctx->alt_version);
    } else if (ctx->pad_mode == RSA_PKCS1_PADDING)
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

static int sdfprov_rsa_asym_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    SDFPROV_RSA_ASYM_CTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            if (!OSSL_PARAM_set_int(p, ctx->pad_mode))
                return 0;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            const char *mode = NULL;

            switch (ctx->pad_mode) {
            case RSA_PKCS1_PADDING:
                mode = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
                break;
            case RSA_NO_PADDING:
                mode = OSSL_PKEY_RSA_PAD_MODE_NONE;
                break;
            case RSA_PKCS1_WITH_TLS_PADDING:
                mode = OSSL_PKEY_RSA_PAD_MODE_NONE;
                break;
            default:
                return 0;
            }
            if (!OSSL_PARAM_set_utf8_string(p, mode))
                return 0;
        } else {
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->client_version))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->alt_version))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->implicit_rejection))
        return 0;

    return 1;
}

static const OSSL_PARAM *sdfprov_rsa_asym_gettable_ctx_params(void *vctx,
                                                              void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, NULL),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return gettable;
}

static int sdfprov_rsa_asym_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SDFPROV_RSA_ASYM_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
    if (p != NULL) {
        int pad_mode = 0;

        if (p->data_type == OSSL_PARAM_INTEGER) {
            if (!OSSL_PARAM_get_int(p, &pad_mode))
                return 0;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (p->data == NULL)
                return 0;
            if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
                pad_mode = RSA_PKCS1_PADDING;
            else if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PAD_MODE_NONE) == 0)
                pad_mode = RSA_NO_PADDING;
            else
                return 0;
        } else {
            return 0;
        }

        if (pad_mode == RSA_PKCS1_PSS_PADDING || pad_mode == RSA_PKCS1_OAEP_PADDING)
            return 0;
        ctx->pad_mode = pad_mode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->client_version))
            return 0;
        ctx->pad_mode = RSA_PKCS1_WITH_TLS_PADDING;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->alt_version))
            return 0;
        ctx->pad_mode = RSA_PKCS1_WITH_TLS_PADDING;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &ctx->implicit_rejection))
        return 0;

    return 1;
}

static const OSSL_PARAM *sdfprov_rsa_asym_settable_ctx_params(void *vctx,
                                                              void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, NULL),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return settable;
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
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_asym_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_asym_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_asym_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_asym_settable_ctx_params },
    OSSL_DISPATCH_END
};
