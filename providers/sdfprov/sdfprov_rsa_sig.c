/*
 * SDF Provider RSA SIGNATURE
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/proverr.h>
#include "internal/tlog.h"
#include "crypto/rsa.h"
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "sdfprov_ctx.h"

#define SDFPROV_RSA_KEYTYPE_SIGN 0x00010100
#define SDFPROV_RSA_KEYTYPE_ENC  0x00010200

typedef struct {
    OSSL_LIB_CTX *libctx;
    SDF_SM2_KEY *key;
    EVP_MD *md;
    EVP_MD *mgf1_md;
    EVP_MD_CTX *mdctx;
    char mdname[64];
    char mgf1_mdname[64];
    int pad_mode;
        int saltlen;
} SDFPROV_RSA_SIG_CTX;

static int sdfprov_rsa_pss_compute_saltlen(SDFPROV_RSA_SIG_CTX *ctx)
{
    int mdsize;
    int rsasize;
    int saltlen = ctx->saltlen;

    if (ctx == NULL || ctx->key == NULL || ctx->key->rsa == NULL || ctx->md == NULL)
        return -1;

    mdsize = EVP_MD_get_size(ctx->md);
    rsasize = RSA_size(ctx->key->rsa);
    if (mdsize <= 0 || rsasize <= 0)
        return -1;

    if (saltlen == RSA_PSS_SALTLEN_DIGEST)
        return mdsize;
    if (saltlen == RSA_PSS_SALTLEN_MAX || saltlen == RSA_PSS_SALTLEN_AUTO
        || saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        saltlen = rsasize - mdsize - 2;
        if (RSA_bits(ctx->key->rsa) & 0x7)
            saltlen--;
        if (ctx->saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX && saltlen > mdsize)
            saltlen = mdsize;
    }
    return saltlen;
}

static int sdfprov_rsa_private_op(SDFPROV_RSA_SIG_CTX *ctx,
                                  const unsigned char *in, size_t inlen,
                                  unsigned char *out, unsigned int *outlen)
{
    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();
    int ret;

    if (sdfctx == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN,
                       "SDF context not available");
        return 0;
    }

    if (ctx->key->key_password != NULL) {
        if (sdfctx->sdfList->GetPrivateKeyAccessRight == NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN,
                           "GetPrivateKeyAccessRight not available");
            return 0;
        }
        ret = TSAPI_SDF_GetPrivateKeyAccessRight(ctx->key->hSession,
                                                 ctx->key->key_index,
                                                 (unsigned char *)ctx->key->key_password,
                                                 (unsigned int)strlen(ctx->key->key_password));
        if (ret != OSSL_SDR_OK) {
            TLOG_ERROR("rsa_sign: GetPrivateKeyAccessRight failed key_index=%u ret=0x%08x",
                       ctx->key->key_index, ret);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN,
                           "get private key access right failed: key_index=%u ret=0x%08x",
                           ctx->key->key_index, ret);
            return 0;
        }
    }

    if (RSA_bits(ctx->key->rsa) > OSSL_RSAref_MAX_BITS) {
        TLOG_DEBUG("rsa_sign: using RSA_Ex key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList->InternalPrivateKeyOperation_RSA_Ex == NULL) {
            if (ctx->key->key_password != NULL
                && sdfctx->sdfList->ReleasePrivateKeyAccessRight != NULL)
                TSAPI_SDF_ReleasePrivateKeyAccessRight(ctx->key->hSession,
                                                       ctx->key->key_index);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN,
                           "InternalPrivateKeyOperation_RSA_Ex not available");
            return 0;
        }
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, out, outlen);
    } else if (sdfctx->sdfList->InternalPrivateKeyOperation_RSA != NULL) {
        TLOG_DEBUG("rsa_sign: using RSA(legacy) key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA(ctx->key->hSession,
                    ctx->key->key_index, (unsigned char *)in, (unsigned int)inlen,
                    out, outlen);
    } else {
        TLOG_DEBUG("rsa_sign: using RSA_Ex fallback key_index=%u key_type=%d bits=%d",
                   ctx->key->key_index, ctx->key->key_type, RSA_bits(ctx->key->rsa));
        if (sdfctx->sdfList->InternalPrivateKeyOperation_RSA_Ex == NULL) {
            if (ctx->key->key_password != NULL
                && sdfctx->sdfList->ReleasePrivateKeyAccessRight != NULL)
                TSAPI_SDF_ReleasePrivateKeyAccessRight(ctx->key->hSession,
                                                       ctx->key->key_index);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN,
                           "InternalPrivateKeyOperation_RSA not available");
            return 0;
        }
        ret = TSAPI_SDF_InternalPrivateKeyOperation_RSA_Ex(ctx->key->hSession,
                    ctx->key->key_index,
                    ctx->key->key_type == 0 ? SDFPROV_RSA_KEYTYPE_SIGN
                                            : SDFPROV_RSA_KEYTYPE_ENC,
                    (unsigned char *)in, (unsigned int)inlen, out, outlen);
    }

    if (ctx->key->key_password != NULL
        && sdfctx->sdfList->ReleasePrivateKeyAccessRight != NULL)
        TSAPI_SDF_ReleasePrivateKeyAccessRight(ctx->key->hSession,
                                               ctx->key->key_index);

    if (ret != OSSL_SDR_OK) {
        TLOG_ERROR("rsa_sign: InternalPrivateKeyOperation failed key_index=%u ret=0x%08x",
                   ctx->key->key_index, ret);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN,
                       "rsa internal private op failed: key_index=%u ret=0x%08x",
                       ctx->key->key_index, ret);
        return 0;
    }
    return 1;
}

static int sdfprov_rsa_sig_do_sign(SDFPROV_RSA_SIG_CTX *ctx,
                                   unsigned char *sig, size_t *siglen,
                                   size_t sigsize, const unsigned char *tbs,
                                   size_t tbslen)
{
    unsigned char *encoded = NULL;
    unsigned char *em = NULL;
    size_t encoded_len = 0;
    unsigned int outlen;
    int rsa_size;
    int saltlen;

    if (sig == NULL) {
        *siglen = (size_t)RSA_size(ctx->key->rsa);
        return 1;
    }

    rsa_size = RSA_size(ctx->key->rsa);
    if (sigsize < (size_t)rsa_size) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "sigsize=%zu rsa_size=%d", sigsize, rsa_size);
        return 0;
    }

    if (ctx->pad_mode == RSA_PKCS1_PSS_PADDING) {
        const EVP_MD *mgf1_md = ctx->mgf1_md != NULL ? ctx->mgf1_md : ctx->md;

        if (ctx->md == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
            return 0;
        }
        saltlen = sdfprov_rsa_pss_compute_saltlen(ctx);
        if (saltlen < 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }
        em = OPENSSL_malloc((size_t)rsa_size);
        if (em == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!ossl_rsa_padding_add_PKCS1_PSS_mgf1(ctx->key->rsa, em, tbs,
                                                 ctx->md, mgf1_md, &saltlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
            goto end;
        }
    } else {
        if (ctx->md != NULL) {
            int md_nid = EVP_MD_get_type(ctx->md);
            size_t prefix_len = 0;
            const unsigned char *prefix =
                ossl_rsa_digestinfo_encoding(md_nid, &prefix_len);

            if (prefix == NULL) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                               "unsupported digest nid=%d", md_nid);
                return 0;
            }
            encoded = OPENSSL_malloc(prefix_len + tbslen);
            if (encoded == NULL) {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(encoded, prefix, prefix_len);
            memcpy(encoded + prefix_len, tbs, tbslen);
            encoded_len = prefix_len + tbslen;
        } else {
            encoded = OPENSSL_memdup(tbs, tbslen);
            if (encoded == NULL) {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            encoded_len = tbslen;
        }

        em = OPENSSL_malloc((size_t)rsa_size);
        if (em == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        if (RSA_padding_add_PKCS1_type_1(em, rsa_size, encoded,
                                         (int)encoded_len) != 1) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                           "encoded_len=%zu rsa_size=%d", encoded_len, rsa_size);
            goto end;
        }
    }

    outlen = (unsigned int)sigsize;
    if (!sdfprov_rsa_private_op(ctx, em, (size_t)rsa_size, sig, &outlen))
        goto end;

    *siglen = outlen;
    OPENSSL_clear_free(em, (size_t)rsa_size);
    OPENSSL_clear_free(encoded, encoded_len);
    return 1;

end:
    OPENSSL_clear_free(em, (size_t)rsa_size);
    OPENSSL_clear_free(encoded, encoded_len);
    return 0;
}

static void *sdfprov_rsa_sig_newctx(void *provctx, const char *propq)
{
    SDFPROV_RSA_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    (void)propq;
    if (ctx != NULL) {
        ctx->libctx = PROV_LIBCTX_OF(provctx);
        ctx->pad_mode = RSA_PKCS1_PADDING;
        ctx->saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
    }
    return ctx;
}

static int sdfprov_rsa_sig_sign_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;

    (void)params;
    if (ctx == NULL || vkey == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    ctx->key = vkey;
    if (ctx->key->rsa == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    TLOG_DEBUG("rsa_sign_init: key_index=%u key_type=%d session=%p external_session=%d",
               ctx->key->key_index, ctx->key->key_type, ctx->key->hSession,
               ctx->key->external_session);
    return 1;
}

static int sdfprov_rsa_sig_verify_init(void *vctx, void *vkey,
                                       const OSSL_PARAM params[])
{
    return sdfprov_rsa_sig_sign_init(vctx, vkey, params);
}

static int sdfprov_rsa_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                                size_t sigsize, const unsigned char *tbs,
                                size_t tbslen)
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL || ctx->key->hSession == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }
    return sdfprov_rsa_sig_do_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int sdfprov_rsa_sig_verify(void *vctx, const unsigned char *sig,
                                  size_t siglen, const unsigned char *tbs,
                                  size_t tbslen)
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;
    int md_nid = NID_undef;
    unsigned char *buf = NULL;
    int ret;

    if (ctx == NULL || ctx->key == NULL || ctx->key->rsa == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (ctx->pad_mode == RSA_PKCS1_PSS_PADDING) {
        const EVP_MD *mgf1_md = ctx->mgf1_md != NULL ? ctx->mgf1_md : ctx->md;
        int saltlen = sdfprov_rsa_pss_compute_saltlen(ctx);

        if (ctx->md == NULL || saltlen < 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return 0;
        }
        buf = OPENSSL_malloc(siglen);
        if (buf == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (RSA_public_decrypt((int)siglen, sig, buf, ctx->key->rsa,
                               RSA_NO_PADDING) <= 0) {
            OPENSSL_clear_free(buf, siglen);
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT);
            return 0;
        }
        ret = ossl_rsa_verify_PKCS1_PSS_mgf1(ctx->key->rsa, tbs, ctx->md,
                                             mgf1_md, buf, &saltlen);
        OPENSSL_clear_free(buf, siglen);
        return ret;
    }

    if (ctx->md != NULL)
        md_nid = EVP_MD_get_type(ctx->md);

    if (md_nid != NID_undef) {
        ret = RSA_verify(md_nid, tbs, (unsigned int)tbslen, sig,
                         (unsigned int)siglen, ctx->key->rsa);
        if (ret != 1) {
            TLOG_ERROR("rsa_verify: RSA_verify failed key_index=%u md_nid=%d siglen=%zu",
                       ctx->key->key_index, md_nid, siglen);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                           "rsa verify failed: key_index=%u md_nid=%d siglen=%zu",
                           ctx->key->key_index, md_nid, siglen);
        }
        return ret;
    }

    buf = OPENSSL_malloc(siglen);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = RSA_public_decrypt((int)siglen, sig, buf, ctx->key->rsa,
                             RSA_PKCS1_PADDING);
    if (ret > 0) {
        ret = ret == (int)tbslen && CRYPTO_memcmp(buf, tbs, tbslen) == 0;
        if (!ret) {
            TLOG_ERROR("rsa_verify: decrypted signature mismatch key_index=%u siglen=%zu tbslen=%zu",
                       ctx->key->key_index, siglen, tbslen);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "rsa verify mismatch: key_index=%u tbslen=%zu",
                           ctx->key->key_index, tbslen);
        }
    } else {
        TLOG_ERROR("rsa_verify: RSA_public_decrypt failed key_index=%u siglen=%zu",
                   ctx->key->key_index, siglen);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT,
                       "rsa public decrypt failed during verify: key_index=%u siglen=%zu",
                       ctx->key->key_index, siglen);
    }
    OPENSSL_clear_free(buf, siglen);
    return ret;
}

static int sdfprov_rsa_sig_digest_sign_init(void *vctx, const char *mdname,
                                            void *vkey, const OSSL_PARAM params[])
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;

    if (!sdfprov_rsa_sig_sign_init(vctx, vkey, params))
        return 0;

    if (ctx->mdctx == NULL)
        ctx->mdctx = EVP_MD_CTX_new();
    if (ctx->mdctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    EVP_MD_free(ctx->md);
    ctx->md = EVP_MD_fetch(ctx->libctx, mdname, NULL);
    if (ctx->md == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "digest fetch failed: %s", mdname);
        return 0;
    }

    if (ctx->mgf1_md == NULL) {
        if (!EVP_MD_up_ref(ctx->md))
            return 0;
        ctx->mgf1_md = ctx->md;
        OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
    }

    OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    return EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL);
}

static int sdfprov_rsa_sig_digest_verify_init(void *vctx, const char *mdname,
                                              void *vkey, const OSSL_PARAM params[])
{
    return sdfprov_rsa_sig_digest_sign_init(vctx, mdname, vkey, params);
}

static int sdfprov_rsa_sig_digest_update(void *vctx, const unsigned char *data,
                                         size_t datalen)
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;

    return ctx != NULL && ctx->mdctx != NULL
        && EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static int sdfprov_rsa_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                             size_t *siglen, size_t sigsize)
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL || ctx->mdctx == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (sig == NULL)
        return sdfprov_rsa_sig_sign(vctx, NULL, siglen, sigsize, NULL, 0);
    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SIGN);
        return 0;
    }
    return sdfprov_rsa_sig_do_sign(ctx, sig, siglen, sigsize, digest, dlen);
}

static int sdfprov_rsa_sig_digest_verify_final(void *vctx, const unsigned char *sig,
                                               size_t siglen)
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (ctx == NULL || ctx->mdctx == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }
    return sdfprov_rsa_sig_verify(vctx, sig, siglen, digest, dlen);
}

static int sdfprov_rsa_sig_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
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
            case RSA_PKCS1_PSS_PADDING:
                mode = OSSL_PKEY_RSA_PAD_MODE_PSS;
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

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && ctx->mdname[0] != '\0'
        && !OSSL_PARAM_set_utf8_string(p, ctx->mdname))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL && ctx->mgf1_mdname[0] != '\0'
        && !OSSL_PARAM_set_utf8_string(p, ctx->mgf1_mdname))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            if (!OSSL_PARAM_set_int(p, ctx->saltlen))
                return 0;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (ctx->saltlen == RSA_PSS_SALTLEN_DIGEST) {
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST))
                    return 0;
            } else if (ctx->saltlen == RSA_PSS_SALTLEN_MAX) {
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX))
                    return 0;
            } else if (ctx->saltlen == RSA_PSS_SALTLEN_AUTO) {
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO))
                    return 0;
            } else if (ctx->saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX))
                    return 0;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_rsa_sig_gettable_ctx_params(void *vctx,
                                                             void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return gettable;
}

static int sdfprov_rsa_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;
    const OSSL_PARAM *p;
    char mdname[64];
    char *pmdname = mdname;

    if (ctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
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
            else if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
                pad_mode = RSA_PKCS1_PSS_PADDING;
            else
                return 0;
        } else {
            return 0;
        }

        if (pad_mode != RSA_PKCS1_PADDING && pad_mode != RSA_NO_PADDING
            && pad_mode != RSA_PKCS1_PSS_PADDING)
            return 0;
        ctx->pad_mode = pad_mode;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        EVP_MD *md;

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        md = EVP_MD_fetch(ctx->libctx, mdname, NULL);
        if (md == NULL)
            return 0;

        EVP_MD_free(ctx->md);
        ctx->md = md;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
    if (p != NULL) {
        EVP_MD *mgf1_md;

        pmdname = mdname;
        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        mgf1_md = EVP_MD_fetch(ctx->libctx, mdname, NULL);
        if (mgf1_md == NULL)
            return 0;

        EVP_MD_free(ctx->mgf1_md);
        ctx->mgf1_md = mgf1_md;
        OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
    if (p != NULL) {
        if (p->data_type == OSSL_PARAM_INTEGER) {
            if (!OSSL_PARAM_get_int(p, &ctx->saltlen))
                return 0;
        } else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (p->data == NULL)
                return 0;
            if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                ctx->saltlen = RSA_PSS_SALTLEN_DIGEST;
            else if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                ctx->saltlen = RSA_PSS_SALTLEN_MAX;
            else if (strcmp((const char *)p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                ctx->saltlen = RSA_PSS_SALTLEN_AUTO;
            else if (strcmp((const char *)p->data,
                            OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX) == 0)
                ctx->saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
            else
                return 0;
        } else {
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_rsa_sig_settable_ctx_params(void *vctx,
                                                             void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;
    return settable;
}

static void sdfprov_rsa_sig_freectx(void *vctx)
{
    SDFPROV_RSA_SIG_CTX *ctx = vctx;

    if (ctx == NULL)
        return;

    EVP_MD_free(ctx->md);
    EVP_MD_free(ctx->mgf1_md);
    EVP_MD_CTX_free(ctx->mdctx);
    OPENSSL_free(ctx);
}

const OSSL_DISPATCH sdfprov_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sdfprov_rsa_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sdfprov_rsa_sig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sdfprov_rsa_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sdfprov_rsa_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))sdfprov_rsa_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sdfprov_rsa_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))sdfprov_rsa_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))sdfprov_rsa_sig_digest_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))sdfprov_rsa_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))sdfprov_rsa_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))sdfprov_rsa_sig_digest_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))sdfprov_rsa_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))sdfprov_rsa_sig_settable_ctx_params },
    OSSL_DISPATCH_END
};
