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
#include <openssl/sdf.h>
#include "internal/tlog.h"
#include "prov/provider_ctx.h"
#include "sdfprov_internal.h"
#include "sdfprov_ctx.h"
#include "sdfprov_utils.h"

/*
 * 获取 RSA 密钥位数（优先从 RSA 对象取，取不到用缓存值）。
 * 缓存值 rsa_bits 在 rsa_load 时赋值，用于 key->rsa==NULL 的场景。
 */
static int sdfprov_rsa_bits(const SDF_SM2_KEY *key)
{
    if (key == NULL)
        return 0;
    if (key->rsa != NULL)
        return RSA_bits(key->rsa);
    return key->rsa_bits;
}

/*
 * 获取 RSA 签名/密文长度（优先从 RSA 对象取，取不到用缓存值）。
 * 缓存值 rsa_size 在 rsa_load 时赋值，用于 key->rsa==NULL 的场景。
 */
static int sdfprov_rsa_size(const SDF_SM2_KEY *key)
{
    if (key == NULL)
        return 0;
    if (key->rsa != NULL)
        return RSA_size(key->rsa);
    return key->rsa_size;
}

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

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (key->rsa == NULL)
            return 0;
        RSA_get0_key(key->rsa, &n, &e, NULL);
        if (n == NULL || e == NULL)
            return 0;
    }

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
    const BIGNUM *n = NULL, *e = NULL;

    if (key == NULL)
        return 0;

    bits = sdfprov_rsa_bits(key);
    if (bits <= 0)
        bits = 2048;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, bits))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, sdfprov_rsa_size(key) > 0
                                  ? sdfprov_rsa_size(key) : 256))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, bits >= 4096 ? 152 : (bits >= 3072 ? 128 : 112)))
        return 0;

    /*
     * 默认摘要：RSA 通常用 sha256（与 default provider 行为一致）。
     * 让 EVP_PKEY_get_default_digest_nid 自动解析，
     * 上层 PKCS7_sign 等无需显式传 md 即可正确签名。
     */
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, SN_sha256))
        return 0;

    /*
     * 暴露 RSA 公钥参数（n, e）：
     * - X509_check_private_key / EVP_PKEY_eq 需要这些参数做跨 provider 比较
     * - PKCS7 数字信封解密前会用证书校验私钥匹配性
     */
    if (key->rsa != NULL) {
        RSA_get0_key(key->rsa, &n, &e, NULL);
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_N)) != NULL
            && !OSSL_PARAM_set_BN(p, n))
            return 0;
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_E)) != NULL
            && !OSSL_PARAM_set_BN(p, e))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_rsa_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

/*
 * RSA KEYMGMT export：把 SDF RSA 公钥（n, e）以 OSSL_PARAM 形式回传给
 * 跨 provider 调用方（如 X509_check_private_key / EVP_PKEY_eq / PKCS7 解密）。
 *
 * 硬件密钥私钥永不出卡，故含 PRIVATE_KEY 的请求统一降级为仅公钥
 * （与 SM2 export 策略一致），让 EVP 框架第二轮 fetch 时仍回退到
 * SDF Provider 用原始 keydata 完成 sign/decrypt。
 */
static int sdfprov_rsa_export(void *keydata, int selection,
                              OSSL_CALLBACK *cb, void *cbarg)
{
    SDF_SM2_KEY *key = keydata;
    const BIGNUM *n = NULL, *e = NULL;
    /*
     * 预分配足够大的本地缓冲区保存 n/e 的 native 编码。
     * RSA-4096 的 n 为 512 字节，e 通常很小，这里取一个充裕的上界。
     */
    unsigned char nbuf[OSSL_RSAref_MAX_LEN_EX];
    unsigned char ebuf[OSSL_RSAref_MAX_LEN_EX];
    int nlen, elen;
    OSSL_PARAM params[3];

    if (key == NULL || key->rsa == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    /*
     * 硬件密钥的私钥永不出卡。
     *
     * 当跨 provider 请求包含私钥（典型场景：EVP_PKEY_decrypt 先把 key
     * 导入 default RSA keymgmt 再操作）时，必须返回失败，迫使 EVP 框架
     * 回退到第二轮流定位——从 SDF Provider 自身 fetch RSA asym_cipher /
     * signature，直接用原始 keydata 完成 sign/decrypt（私钥不离卡）。
     *
     * 若降级为仅公钥导出，default RSA keymgmt 会得到一个只有公钥的 key，
     * 后续私钥操作（decrypt/sign）会因 "missing private key" 失败，
     * 且 EVP 不会再次回退——这正是 PKCS7 数字信封 RSA 解封失败的根因。
     *
     * 仅当请求只含公钥（如 X509_check_private_key 的比较、pkey -pubout
     * 的编码导出）时，才导出 n/e 公钥参数。
     */
    if (key->is_hardware_key
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return 0;

    RSA_get0_key(key->rsa, &n, &e, NULL);
    if (n == NULL || e == NULL)
        return 0;

    nlen = BN_bn2nativepad(n, nbuf, sizeof(nbuf));
    elen = BN_bn2nativepad(e, ebuf, sizeof(ebuf));
    if (nlen <= 0 || elen <= 0)
        return 0;

    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, nbuf, (size_t)nlen);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, ebuf, (size_t)elen);
    params[2] = OSSL_PARAM_construct_end();

    return cb(params, cbarg) > 0;
}

static const OSSL_PARAM *sdfprov_rsa_export_types(int selection)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int sdfprov_rsa_try_export_pubkey(void *hSession, unsigned int key_index,
                                         int key_type, RSA **rsa)
{
    OSSL_RSArefPublicKey pub;
    OSSL_RSArefPublicKeyEx pub_ex;
    int ret;

    memset(&pub, 0, sizeof(pub));
    memset(&pub_ex, 0, sizeof(pub_ex));

    if (key_type == 0) {
        ret = TSAPI_SDF_ExportSignPublicKey_RSAEx(hSession, key_index, &pub_ex);
        if (ret == OSSL_SDR_OK)
            return sdfprov_rsa_pubkeyex_to_rsa(&pub_ex, rsa) ? OSSL_SDR_OK
                                                             : OSSL_SDR_OUTARGERR;

        TLOG_DEBUG("rsa_load: ExportSignPublicKey_RSAEx failed ret=0x%08x, trying legacy", ret);
        ret = TSAPI_SDF_ExportSignPublicKey_RSA(hSession, key_index, &pub);
        if (ret == OSSL_SDR_OK)
            return sdfprov_rsa_pubkey_to_rsa(&pub, rsa) ? OSSL_SDR_OK
                                                        : OSSL_SDR_OUTARGERR;
    } else {
        ret = TSAPI_SDF_ExportEncPublicKey_RSAEx(hSession, key_index, &pub_ex);
        if (ret == OSSL_SDR_OK)
            return sdfprov_rsa_pubkeyex_to_rsa(&pub_ex, rsa) ? OSSL_SDR_OK
                                                             : OSSL_SDR_OUTARGERR;

        TLOG_DEBUG("rsa_load: ExportEncPublicKey_RSAEx failed ret=0x%08x, trying legacy", ret);
        ret = TSAPI_SDF_ExportEncPublicKey_RSA(hSession, key_index, &pub);
        if (ret == OSSL_SDR_OK)
            return sdfprov_rsa_pubkey_to_rsa(&pub, rsa) ? OSSL_SDR_OK
                                                        : OSSL_SDR_OUTARGERR;
    }

    return ret;
}

static void *sdfprov_rsa_load(const void *reference, size_t reference_sz)
{
    SDF_SM2_KEY *key = NULL;
    SDFPROV_CTX *gctx = NULL;
    SDFPROV_KEY_URI uri_info;
    char *ref = NULL;
    void *hSession;
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

    gctx = sdfprov_get_global_ctx();
    hSession = uri_info.external_session ? uri_info.session
                                         : sdfprov_ctx_get_session(gctx);
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

    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();
    if (sdfctx == NULL) {
        return 0;
    }

    ret = sdfprov_rsa_try_export_pubkey(hSession, uri_info.key_index,
                                        uri_info.key_type, &rsa);
    if (ret == OSSL_SDR_KEYNOTEXIST) {
        int alt_key_type = uri_info.key_type == 0 ? 1 : 0;

        TLOG_DEBUG("rsa_load: key_type=%d export returned KEYNOTEXIST, trying alternate key_type=%d",
                   uri_info.key_type, alt_key_type);
        ret = sdfprov_rsa_try_export_pubkey(hSession, uri_info.key_index,
                                            alt_key_type, &rsa);
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        RSA_free(rsa);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    key->libctx = gctx != NULL ? gctx->libctx : NULL;
    key->rsa = rsa;
    key->rsa_bits = rsa != NULL ? RSA_bits(rsa) : 0;
    key->rsa_size = rsa != NULL ? RSA_size(rsa) : 0;
    key->algo = SDF_ALGO_RSA;
    key->is_hardware_key = 1;
    key->key_index = uri_info.key_index;
    key->key_type = uri_info.key_type;
    key->hSession = hSession;
    key->external_session = uri_info.external_session;
    key->key_password = uri_info.key_password;
    uri_info.key_password = NULL;

    if (rsa == NULL) {
        TLOG_DEBUG("rsa_load: continue without exported public key key_index=%u type=%d ret=0x%08x",
                   uri_info.key_index, uri_info.key_type, ret);
    }

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

    if (key1 == NULL || key2 == NULL)
        return 0;

    if (key1->rsa == NULL || key2->rsa == NULL) {
        if (key1->is_hardware_key || key2->is_hardware_key)
            return 1;
        return 0;
    }

    RSA_get0_key(key1->rsa, &n1, &e1, NULL);
    RSA_get0_key(key2->rsa, &n2, &e2, NULL);
    return BN_cmp(n1, n2) == 0 && BN_cmp(e1, e2) == 0;
}

static int sdfprov_rsa_validate(const void *keydata, int selection, int checktype)
{
    const SDF_SM2_KEY *key = keydata;

    (void)selection;
    (void)checktype;

    return key != NULL && (key->rsa != NULL || key->is_hardware_key);
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
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sdfprov_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))sdfprov_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))sdfprov_rsa_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))sdfprov_rsa_query_operation_name },
    OSSL_DISPATCH_END
};
