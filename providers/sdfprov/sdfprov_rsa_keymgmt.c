/*
 * SDF Provider RSA KEYMGMT
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/proverr.h>
#include "internal/tlog.h"
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "sdfprov_ctx.h"
#include "sdfprov_utils.h"

static void *sdfprov_rsa_newdata(void *provctx)
{
    SDF_SM2_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key != NULL)
        key->libctx = PROV_LIBCTX_OF(provctx);
    return key;
}

static void sdfprov_rsa_freedata(void *keydata)
{
    SDF_SM2_KEY *key = keydata;

    if (key == NULL)
        return;

    OPENSSL_free(key->key_password);
    RSA_free(key->rsa);
    OPENSSL_free(key);
}

static int sdfprov_rsa_has(const void *keydata, int selection)
{
    const SDF_SM2_KEY *key = keydata;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;

    if (key == NULL || key->rsa == NULL)
        return 0;

    RSA_get0_key(key->rsa, &n, &e, NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && (n == NULL || e == NULL))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && !key->is_hardware_key)
        return 0;

    return 1;
}

static int sdfprov_rsa_get_params(void *keydata, OSSL_PARAM params[])
{
    SDF_SM2_KEY *key = keydata;
    OSSL_PARAM *p;
    int bits;

    if (key == NULL || key->rsa == NULL)
        return 0;

    bits = RSA_bits(key->rsa);

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, RSA_size(key->rsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, bits >= 4096 ? 152 : (bits >= 3072 ? 128 : 112)))
        return 0;

    return 1;
}

static const OSSL_PARAM *sdfprov_rsa_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_END
    };

    return params;
}

static void *sdfprov_rsa_load(const void *reference, size_t reference_sz)
{
    SDF_SM2_KEY *key = NULL;
    SDFPROV_KEY_URI uri_info;
    char *ref = NULL;
    void *hSession;
    OSSL_RSArefPublicKey pub;
    OSSL_RSArefPublicKeyEx pub_ex;
    RSA *rsa = NULL;
    int ret;

    if (reference == NULL || reference_sz == 0)
        return NULL;

    ref = OPENSSL_strndup(reference, reference_sz);
    if (ref == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!sdfprov_parse_key_uri(ref, &uri_info)) {
        TLOG_ERROR("rsa_load: failed to parse reference: %s", ref);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                       "rsa uri parse failed: %s", ref);
        OPENSSL_free(ref);
        return NULL;
    }
    OPENSSL_free(ref);

    if (uri_info.algo != SDF_ALGO_RSA) {
        TLOG_ERROR("rsa_load: unsupported algo=%d for ref", uri_info.algo);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                       "unexpected key algo=%d", uri_info.algo);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    hSession = uri_info.external_session ? uri_info.session
                                         : sdfprov_ctx_get_session(sdfprov_get_global_ctx());
    if (hSession == NULL) {
        TLOG_ERROR("rsa_load: no session available for key_index=%u type=%d",
                   uri_info.key_index, uri_info.key_type);
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }
    TLOG_DEBUG("rsa_load: key_index=%u type=%d external_session=%d session=%p",
               uri_info.key_index, uri_info.key_type,
               uri_info.external_session, hSession);

    memset(&pub, 0, sizeof(pub));
    memset(&pub_ex, 0, sizeof(pub_ex));
    if (uri_info.key_type == 0) {
        ret = TSAPI_SDF_ExportSignPublicKey_RSA(hSession, uri_info.key_index, &pub);
        if (ret == OSSL_SDR_OK)
            ret = sdfprov_rsa_pubkey_to_rsa(&pub, &rsa) ? OSSL_SDR_OK : OSSL_SDR_OUTARGERR;
        if (ret != OSSL_SDR_OK) {
            TLOG_DEBUG("rsa_load: ExportSignPublicKey_RSA failed ret=0x%08x, trying Ex", ret);
            ret = TSAPI_SDF_ExportSignPublicKey_RSAEx(hSession, uri_info.key_index, &pub_ex);
            if (ret == OSSL_SDR_OK && !sdfprov_rsa_pubkeyex_to_rsa(&pub_ex, &rsa))
                ret = OSSL_SDR_OUTARGERR;
        }
    } else {
        ret = TSAPI_SDF_ExportEncPublicKey_RSA(hSession, uri_info.key_index, &pub);
        if (ret == OSSL_SDR_OK)
            ret = sdfprov_rsa_pubkey_to_rsa(&pub, &rsa) ? OSSL_SDR_OK : OSSL_SDR_OUTARGERR;
        if (ret != OSSL_SDR_OK) {
            TLOG_DEBUG("rsa_load: ExportEncPublicKey_RSA failed ret=0x%08x, trying Ex", ret);
            ret = TSAPI_SDF_ExportEncPublicKey_RSAEx(hSession, uri_info.key_index, &pub_ex);
            if (ret == OSSL_SDR_OK && !sdfprov_rsa_pubkeyex_to_rsa(&pub_ex, &rsa))
                ret = OSSL_SDR_OUTARGERR;
        }
    }

    if (ret != OSSL_SDR_OK || rsa == NULL) {
        TLOG_ERROR("rsa_load: export public key failed key_index=%u type=%d ret=0x%08x",
                   uri_info.key_index, uri_info.key_type, ret);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT,
                       "rsa public key export failed: key_index=%u type=%d ret=0x%08x",
                       uri_info.key_index, uri_info.key_type, ret);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        RSA_free(rsa);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    key->libctx = sdfprov_get_global_ctx()->libctx;
    key->rsa = rsa;
    key->algo = SDF_ALGO_RSA;
    key->is_hardware_key = 1;
    key->key_index = uri_info.key_index;
    key->key_type = uri_info.key_type;
    key->hSession = hSession;
    key->external_session = uri_info.external_session;
    key->key_password = uri_info.key_password;
    uri_info.key_password = NULL;

    sdfprov_key_uri_cleanup(&uri_info);
    return key;
}

static int sdfprov_rsa_match(const void *keydata1, const void *keydata2,
                             int selection)
{
    const SDF_SM2_KEY *key1 = keydata1;
    const SDF_SM2_KEY *key2 = keydata2;
    const BIGNUM *n1 = NULL, *e1 = NULL;
    const BIGNUM *n2 = NULL, *e2 = NULL;

    (void)selection;

    if (key1 == NULL || key2 == NULL || key1->rsa == NULL || key2->rsa == NULL)
        return 0;

    RSA_get0_key(key1->rsa, &n1, &e1, NULL);
    RSA_get0_key(key2->rsa, &n2, &e2, NULL);
    return BN_cmp(n1, n2) == 0 && BN_cmp(e1, e2) == 0;
}

static int sdfprov_rsa_validate(const void *keydata, int selection, int checktype)
{
    const SDF_SM2_KEY *key = keydata;

    (void)selection;
    (void)checktype;

    return key != NULL && key->rsa != NULL;
}

static const char *sdfprov_rsa_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return "RSA";
    case OSSL_OP_ASYM_CIPHER:
        return "RSA";
    }
    return NULL;
}

const OSSL_DISPATCH sdfprov_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sdfprov_rsa_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sdfprov_rsa_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sdfprov_rsa_has },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sdfprov_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))sdfprov_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sdfprov_rsa_load },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sdfprov_rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))sdfprov_rsa_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))sdfprov_rsa_query_operation_name },
    OSSL_DISPATCH_END
};
