/*
 * SDF Provider SM2 KEYMGMT
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sdf.h>
#include <openssl/proverr.h>
#include "prov/provider_ctx.h"
#include "crypto/sm2.h"
#include "crypto/ec.h"
#include "sdfprov_internal.h"
#include "sdfprov_utils.h"
#include "sdfprov_ctx.h"
#include "internal/param_build_set.h"
#include "internal/tlog.h"

/* 从全局 SDF 上下文获取设备会话并初始化设备（如果未初始化） */
static void *sdfprov_get_session(void)
{
    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();

    if (sdfctx == NULL)
        return NULL;

    return sdfprov_ctx_get_session(sdfctx);
}

static void *sdfprov_sm2_newdata(void *provctx)
{
    SDF_SM2_KEY *key;
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;

    key->libctx = libctx;
    key->ec_key = EC_KEY_new_by_curve_name_ex(libctx, NULL, NID_sm2);
    if (key->ec_key == NULL) {
        OPENSSL_free(key);
        return NULL;
    }

    return key;
}

static void sdfprov_sm2_freedata(void *keydata)
{
    SDF_SM2_KEY *key = keydata;

    if (key == NULL)
        return;

    /* 释放 SDF 协商句柄 */
    if (key->agreement_handle != NULL && key->hSession != NULL) {
        TSAPI_SDF_DestroyKey(key->hSession, key->agreement_handle);
        key->agreement_handle = NULL;
    }

    OPENSSL_free(key->key_password);
    RSA_free(key->rsa);
    EC_KEY_free(key->ec_key);
    OPENSSL_free(key);
}

static int sdfprov_sm2_has(const void *keydata, int selection)
{
    const SDF_SM2_KEY *key = keydata;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && EC_KEY_get0_public_key(key->ec_key) == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /* 硬件密钥有私钥（在设备中），软件密钥需要检查 EC_KEY */
        if (!key->is_hardware_key
            && !EC_KEY_get0_private_key(key->ec_key))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_sm2_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        /*
         * 默认摘要：SM2 强制使用 SM3。
         * 通过 OSSL_PKEY_PARAM_MANDATORY_DIGEST 声明，使上层
         * EVP_PKEY_get_default_digest_nid/name 能自动解析出 SM3，
         * 让 PKCS7_sign / PKCS7_sign_add_signer 传 NULL md 时能
         * 自动选择 SM3（与软件层 set_alias_type(SM2) 后的行为一致）。
         */
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int sdfprov_sm2_get_params(void *keydata, OSSL_PARAM params[])
{
    SDF_SM2_KEY *key = keydata;
    OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 128))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        unsigned char *buf = NULL;
        int blen;
        if (key->ec_key == NULL)
            return 0;
        blen = EC_KEY_key2buf(key->ec_key, POINT_CONVERSION_UNCOMPRESSED,
                               &buf, NULL);
        if (blen <= 0)
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, buf, (size_t)blen)) {
            OPENSSL_free(buf);
            return 0;
        }
        OPENSSL_free(buf);
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        unsigned char *buf = NULL;
        int blen;

        if (key->ec_key == NULL)
            return 0;
        blen = EC_KEY_key2buf(key->ec_key, POINT_CONVERSION_UNCOMPRESSED,
                              &buf, NULL);
        if (blen <= 0)
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, buf, (size_t)blen)) {
            OPENSSL_free(buf);
            return 0;
        }
        OPENSSL_free(buf);
    }

    /*
     * 默认/强制摘要：SM2 必须用 SM3。
     * 让 EVP_PKEY_get_default_digest_nid 自动解析为 SM3，
     * 上层 PKCS7_sign 等无需显式传 md 即可正确签名。
     */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, OSSL_DIGEST_NAME_SM3))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, OSSL_DIGEST_NAME_SM3))
        return 0;

    return 1;
}

/* 生成上下文 - 用于 keygen 操作 */
typedef struct sdfprov_gen_ctx_st {
    OSSL_LIB_CTX *libctx;
    int selection;
    unsigned int key_index;
    int key_type;
    void *hSession;
    char *key_password;
} SDFPROV_GEN_CTX;

static void *sdfprov_sm2_gen_init(void *provctx, int selection)
{
    SDFPROV_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;
    gctx->libctx = PROV_LIBCTX_OF(provctx);
    gctx->selection = selection;
    return gctx;
}

static int sdfprov_sm2_gen_set_template(void *genctx, void *templ)
{
    SDFPROV_GEN_CTX *gctx = genctx;
    SDF_SM2_KEY *tkey = templ;

    if (gctx == NULL)
        return 0;
    if (tkey == NULL)
        return 1;

    gctx->key_index = tkey->key_index;
    gctx->key_type = tkey->key_type;
    gctx->hSession = tkey->hSession;

    OPENSSL_free(gctx->key_password);
    gctx->key_password = NULL;
    if (tkey->key_password != NULL) {
        gctx->key_password = OPENSSL_strdup(tkey->key_password);
        if (gctx->key_password == NULL)
            return 0;
    }

    return 1;
}

static void *sdfprov_sm2_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    SDFPROV_GEN_CTX *gctx = genctx;
    SDFPROV_CTX *sdfctx;
    SDF_SM2_KEY *key;
    void *hSession;
    OSSL_ECCrefPublicKey sponsor_pub;
    OSSL_ECCrefPublicKey sponsor_tmp_pub;
    const EC_GROUP *group;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    void *agreement_handle = NULL;
    unsigned int key_index = 0;
    int ret;
    static unsigned char sm2_default_id[] = "1234567812345678";

    if (gctx == NULL)
        return NULL;

    (void)cb;
    (void)cbarg;

    sdfctx = sdfprov_get_global_ctx();
    if (gctx->key_index != 0)
        key_index = gctx->key_index;
    else if (sdfctx != NULL)
        key_index = sdfctx->enc_key_index;

    /* 创建新密钥 */
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;

    key->libctx = gctx->libctx;
    key->ec_key = EC_KEY_new_by_curve_name_ex(gctx->libctx, NULL, NID_sm2);
    if (key->ec_key == NULL) {
        OPENSSL_free(key);
        return NULL;
    }

    /* 生成密钥对 */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        hSession = gctx->hSession != NULL ? gctx->hSession : sdfprov_get_session();

        if (hSession != NULL) {
            memset(&sponsor_pub, 0, sizeof(sponsor_pub));
            memset(&sponsor_tmp_pub, 0, sizeof(sponsor_tmp_pub));

            if (sdfctx == NULL) {
                EC_KEY_free(key->ec_key);
                OPENSSL_free(key);
                return NULL;
            }

            ret = TSAPI_SDF_GenerateAgreementDataWithECCEx(
                hSession,
                key_index,
                384,
                sm2_default_id,
                (unsigned int)(sizeof(sm2_default_id) - 1),
                &sponsor_pub,
                &sponsor_tmp_pub,
                &agreement_handle);

            if (ret == OSSL_SDR_OK) {
                group = EC_KEY_get0_group(key->ec_key);
                if (group != NULL) {
                    x = BN_bin2bn(sponsor_tmp_pub.x + OSSL_ECCref_MAX_LEN - 32,
                                  32, NULL);
                    y = BN_bin2bn(sponsor_tmp_pub.y + OSSL_ECCref_MAX_LEN - 32,
                                  32, NULL);
                    point = EC_POINT_new(group);
                }

                if (group != NULL && x != NULL && y != NULL && point != NULL
                        && EC_POINT_set_affine_coordinates(group, point, x, y, NULL)
                        && EC_KEY_set_public_key(key->ec_key, point)) {
                    BIGNUM *priv = BN_new();
                    if (priv != NULL) {
                        BN_one(priv);
                        EC_KEY_set_private_key(key->ec_key, priv);
                        BN_free(priv);
                    }

                    key->algo = SDF_ALGO_SM2;
                    key->is_hardware_key = 1;
                    key->hSession = hSession;
                    key->key_index = key_index;
                    key->key_type = gctx->key_type;
                    key->agreement_handle = agreement_handle;
                    key->has_agreement = 1;
                    key->is_initiator = 1;
                    key->cached_pubkey = sponsor_pub;
                    if (gctx->key_password != NULL) {
                        key->key_password = OPENSSL_strdup(gctx->key_password);
                        if (key->key_password == NULL) {
                            TSAPI_SDF_DestroyKey(hSession, agreement_handle);
                            BN_free(x);
                            BN_free(y);
                            EC_POINT_free(point);
                            EC_KEY_free(key->ec_key);
                            OPENSSL_free(key);
                            return NULL;
                        }
                    }

                    BN_free(x);
                    BN_free(y);
                    EC_POINT_free(point);
                    return key;
                }

                BN_free(x);
                BN_free(y);
                EC_POINT_free(point);
                x = y = NULL;
                point = NULL;

                if (sdfprov_eccrefpub_to_ec_key(&sponsor_tmp_pub,
                                                  key->ec_key)) {
                    BIGNUM *priv = BN_new();
                    if (priv != NULL) {
                        BN_one(priv);
                        EC_KEY_set_private_key(key->ec_key, priv);
                        BN_free(priv);
                    }

                    key->algo = SDF_ALGO_SM2;
                    key->is_hardware_key = 1;
                    key->hSession = hSession;
                    key->key_index = key_index;
                    key->key_type = gctx->key_type;
                    key->agreement_handle = agreement_handle;
                    key->has_agreement = 1;
                    key->is_initiator = 1;
                    key->cached_pubkey = sponsor_pub;
                    if (gctx->key_password != NULL) {
                        key->key_password = OPENSSL_strdup(gctx->key_password);
                        if (key->key_password == NULL) {
                            TSAPI_SDF_DestroyKey(hSession, agreement_handle);
                            EC_KEY_free(key->ec_key);
                            OPENSSL_free(key);
                            return NULL;
                        }
                    }

                    return key;
                }

                /* 硬件路径全部失败，释放协商句柄 */
                if (agreement_handle != NULL && hSession != NULL) {
                    TSAPI_SDF_DestroyKey(hSession, agreement_handle);
                }
            }
        }

        if (!EC_KEY_generate_key(key->ec_key)) {
            EC_KEY_free(key->ec_key);
            OPENSSL_free(key);
            return NULL;
        }

    }

    key->algo = SDF_ALGO_SM2;
    key->is_hardware_key = 0;
    return key;
}

static int sdfprov_sm2_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    SDFPROV_GEN_CTX *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        char name[64] = {0};
        char *namep = name;
        if (!OSSL_PARAM_get_utf8_string(p, &namep, sizeof(name)))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_sm2_gen_settable_params(
        ossl_unused void *genctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_END
    };
    return params;
}

static void sdfprov_sm2_gen_cleanup(void *genctx)
{
    SDFPROV_GEN_CTX *gctx = genctx;

    if (gctx != NULL)
        OPENSSL_free(gctx->key_password);
    OPENSSL_free(genctx);
}

/*
 * 导入密钥参数 - 支持公钥和私钥
 * 用于 OpenSSL 框架在 Provider 之间导出/导入密钥
 */
static int sdfprov_sm2_import(void *keydata, int selection,
                              const OSSL_PARAM params[])
{
    SDF_SM2_KEY *key = keydata;
    const OSSL_PARAM *p;
    unsigned char *pub = NULL;
    size_t pub_len;

    if (key == NULL)
        return 0;

    /* 导入公钥 */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, (void **)&pub, 0, &pub_len)) {
            return 0;
        }
        if (!EC_KEY_oct2key(key->ec_key, pub, pub_len, NULL)) {
            OPENSSL_free(pub);
            return 0;
        }
        OPENSSL_free(pub);
        pub = NULL;
        key->is_hardware_key = 0;
    }

    /* 导入私钥（用于软件密钥回退路径） */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            BIGNUM *priv = NULL;

            if (!OSSL_PARAM_get_BN(p, &priv))
                return 0;
            if (!EC_KEY_set_private_key(key->ec_key, priv)) {
                BN_free(priv);
                return 0;
            }
            BN_free(priv);
            key->is_hardware_key = 0;
        }
    }

    return 1;
}

/* 导出公钥到 OSSL_PARAM */
static int sdfprov_sm2_export(void *keydata, int selection,
                               OSSL_CALLBACK *cb, void *cbarg)
{
    SDF_SM2_KEY *key = keydata;
    unsigned char *pub = NULL;
    int pub_len;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    TLOG_DEBUG("sm2_export: keydata=%p, selection=0x%x, cb=%p", keydata, selection, (void *)cb);

    if (key == NULL || key->ec_key == NULL)
        return 0;

    /*
     * OpenSSL KEYMGMT export 要求：
     * 1. 必须导出 domain parameters（曲线参数）
     * 2. 如果请求私钥，必须同时请求公钥
     */
    if ((selection & (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                      | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                      | OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    /*
     * 硬件密钥私钥永不出卡。凡是请求 PRIVATE_KEY 的 export，统一返回失败，
     * 让 EVP 框架回退到第 2 轮，从 sdfprov 自身 fetch 对应 operation。
     *
     * 这对 NTLS ECDHE 也同样必须如此：如果临时硬件密钥在第 1 轮被成功导出到
     * default provider，default SM2DH 会继续处理 SELF_ENC_KEY / PEER_ENC_KEY，
     * 并在 provider-export 路径中把 EVP_PKEY * 当作 EC_KEY * 使用，触发
     * refcount error。强制回到 sdfprov 后，SELF_ENC_KEY 仅作为 EVP_PKEY * 透传，
     * 由 sdfprov_sm2dh_exch 自己取公钥即可。
     */
    if (key->is_hardware_key
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return 0;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    /* 导出曲线参数 */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        const EC_GROUP *group = EC_KEY_get0_group(key->ec_key);

        if (group == NULL)
            goto err;

        /* 导出曲线名称 */
        const char *curve_name = OSSL_EC_curve_nid2name(EC_GROUP_get_curve_name(group));
        if (curve_name == NULL)
            goto err;

        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0))
            goto err;
    }

    /* 导出公钥 */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        pub_len = EC_KEY_key2buf(key->ec_key, POINT_CONVERSION_UNCOMPRESSED,
                                 &pub, NULL);
        if (pub_len <= 0)
            goto err;

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                               pub, (size_t)pub_len))
            goto err;
    }

    /* 导出私钥 */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && EC_KEY_get0_private_key(key->ec_key) != NULL) {
        const EC_GROUP *group = EC_KEY_get0_group(key->ec_key);
        int ecbits;
        size_t sz;
        const BIGNUM *priv_key = EC_KEY_get0_private_key(key->ec_key);

        if (group == NULL)
            goto err;
        ecbits = EC_GROUP_order_bits(group);
        if (ecbits <= 0)
            goto err;
        sz = (ecbits + 7) / 8;

        if (!OSSL_PARAM_BLD_push_BN_pad(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                        priv_key, sz))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;

    ret = cb(params, cbarg);
    ret = (ret > 0);
err:
    OPENSSL_free(pub);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

static const OSSL_PARAM *sdfprov_sm2_import_types(int selection)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *sdfprov_sm2_export_types(int selection)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

/*
 * 从 SDF 设备加载密钥 - 按密钥索引导出公钥
 * 通过 OSSL_PARAM 设置 key_index 和 key_type
 */
static int sdfprov_sm2_set_params(void *keydata, const OSSL_PARAM params[])
{
    SDF_SM2_KEY *key = keydata;
    const OSSL_PARAM *p;
    const void *pub = NULL;
    size_t publen = 0;

    if (key == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, "sdf-key-index");
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &key->key_index))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, "sdf-key-type");
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &key->key_type))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, "sdf-is-hardware");
    if (p != NULL) {
        int val;
        if (!OSSL_PARAM_get_int(p, &val))
            return 0;
        key->is_hardware_key = val;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        pub = p->data;
        publen = p->data_size;
        if (pub == NULL || publen == 0)
            return 0;
        if (!EC_KEY_oct2key(key->ec_key, pub, publen, NULL))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        pub = p->data;
        publen = p->data_size;
        if (pub == NULL || publen == 0)
            return 0;
        if (!EC_KEY_oct2key(key->ec_key, pub, publen, NULL))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *sdfprov_sm2_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_uint("sdf-key-index", NULL),
        OSSL_PARAM_int("sdf-key-type", NULL),
        OSSL_PARAM_int("sdf-is-hardware", NULL),
        OSSL_PARAM_END
    };
    return params;
}

/*
 * KEYMGMT "load" 操作: 从对象识别信息加载密钥
 * object_reference 格式: "sdf:<algo>:<index>:<type>[:<pwd>]"
 *   algo: "sm2" 或 "rsa"
 *   key_type: "sign" (0) 或 "enc" (1)
 *   pwd: 私钥访问控制码 (可选)
 * 这个函数供 STORE 操作或应用层使用
 */
static void *sdfprov_sm2_load(const void *reference, size_t reference_sz)
{
    SDF_SM2_KEY *key = NULL;
    void *hSession;
    OSSL_ECCrefPublicKey sdf_pub;
    int ret;
    unsigned int key_index;
    int key_type = 0;
    int algo = SDF_ALGO_SM2;
    const char *ref_str;
    char *endp;
    const char *p;
    const char *pwd = NULL;

    if (reference == NULL || reference_sz == 0)
        return NULL;

    ref_str = (const char *)reference;

    /* 解析 "sdf:<algo>:<index>:<type>[:<pwd>]" 格式 */
    if (strncmp(ref_str, "sdf:", 4) != 0)
        return NULL;

    p = ref_str + 4;

    /* 解析算法 */
    if (strncmp(p, "sm2:", 4) == 0) {
        algo = SDF_ALGO_SM2;
        p += 4;
    } else if (strncmp(p, "rsa:", 4) == 0) {
        algo = SDF_ALGO_RSA;
        p += 4;
    } else {
        return NULL;
    }

    /* 解析索引 */
    key_index = (unsigned int)strtoul(p, &endp, 10);
    if (*endp != ':')
        return NULL;
    p = endp + 1;

    /* 解析类型 */
    {
        const char *type_end = p;
        while (*type_end != '\0' && *type_end != ':')
            type_end++;

        size_t type_len = type_end - p;
        if ((type_len == 4 && strncmp(p, "sign", 4) == 0)
            || (type_len == 1 && p[0] == '0'))
            key_type = 0;
        else if ((type_len == 3 && strncmp(p, "enc", 3) == 0)
                 || (type_len == 1 && p[0] == '1'))
            key_type = 1;
        else
            return NULL;

        /* 检查 pwd 参数 */
        if (*type_end == ':') {
            pwd = type_end + 1;
            if (*pwd == '\0')
                pwd = NULL;
        }
    }

    /* 目前仅实现 SM2 */
    if (algo != SDF_ALGO_SM2)
        return NULL;

    /* 获取 SDF 会话 */
    hSession = sdfprov_get_session();
    if (hSession == NULL)
        return NULL;

    /* 创建密钥对象 */
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;

    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();
    key->libctx = sdfctx->libctx;
    key->algo = algo;
    key->ec_key = EC_KEY_new_by_curve_name_ex(key->libctx, NULL, NID_sm2);
    if (key->ec_key == NULL) {
        OPENSSL_free(key);
        return NULL;
    }

    key->is_hardware_key = 1;
    key->key_index = key_index;
    key->key_type = key_type;
    key->hSession = hSession;

    /* 保存私钥访问控制码 */
    if (pwd != NULL)
        key->key_password = OPENSSL_strdup(pwd);

    /* 从设备导出公钥 */
    memset(&sdf_pub, 0, sizeof(sdf_pub));
    if (sdfctx == NULL) {
        OPENSSL_free(key->key_password);
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key);
        return NULL;
    }
    if (key_type == 0) {
        ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSession, key_index, &sdf_pub);
        if (ret != OSSL_SDR_OK) {
            OPENSSL_free(key->key_password);
            EC_KEY_free(key->ec_key);
            OPENSSL_free(key);
            return NULL;
        }
    } else {
        ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSession, key_index, &sdf_pub);
        if (ret != OSSL_SDR_OK) {
            OPENSSL_free(key->key_password);
            EC_KEY_free(key->ec_key);
            OPENSSL_free(key);
            return NULL;
        }
    }

    if (ret != OSSL_SDR_OK) {
        OPENSSL_free(key->key_password);
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key);
        return NULL;
    }

    /* 转换 ECCrefPublicKey -> EC_KEY 公钥点 */
    if (!sdfprov_eccrefpub_to_ec_key(&sdf_pub, key->ec_key)) {
        OPENSSL_free(key->key_password);
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key);
        return NULL;
    }

    /* 缓存公钥原始数据 */
    memcpy(&key->cached_pubkey, &sdf_pub, sizeof(sdf_pub));

    return key;
}

/*
 * KEYMGMT "load" 操作（key=value URI 风格）：从 STORE 传入的 reference 加载 SM2 硬件密钥
 * reference 格式: "sdf:key=<index>;type=<sign|enc>;algo=sm2[;pwd=<password>]"
 * 通过 SDF_ExportSignPublicKey_ECC / SDF_ExportEncPublicKey_ECC 导出公钥，
 * 构造 SDF_SM2_KEY 返回（私钥不出卡，通过 key_index + hSession 标识）。
 */
static void *sdfprov_sm2_load_ex(const void *reference, size_t reference_sz)
{
    SDF_SM2_KEY *key = NULL;
    OSSL_ECCrefPublicKey sdf_pub;
    SDFPROV_KEY_URI uri_info;
    SDFPROV_CTX *sdfctx = NULL;
    void *hSession = NULL;
    char *ref_str = NULL;
    int ret;

    if (reference == NULL || reference_sz == 0)
        return NULL;

    ref_str = OPENSSL_strndup(reference, reference_sz);
    if (ref_str == NULL)
        return NULL;

    if (!sdfprov_parse_key_uri(ref_str, &uri_info)) {
        OPENSSL_free(ref_str);
        return NULL;
    }
    OPENSSL_free(ref_str);

    if (uri_info.algo != SDF_ALGO_SM2) {
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    hSession = uri_info.external_session ? uri_info.session : sdfprov_get_session();
    if (hSession == NULL) {
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    sdfctx = sdfprov_get_global_ctx();
    key->libctx = sdfctx->libctx;
    key->algo = uri_info.algo;
    key->ec_key = EC_KEY_new_by_curve_name_ex(key->libctx, NULL, NID_sm2);
    if (key->ec_key == NULL) {
        OPENSSL_free(key);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    key->is_hardware_key = 1;
    key->key_index = uri_info.key_index;
    key->key_type = uri_info.key_type;
    key->hSession = hSession;
    key->external_session = uri_info.external_session;
    key->key_password = uri_info.key_password;
    uri_info.key_password = NULL;

    memset(&sdf_pub, 0, sizeof(sdf_pub));
    if (sdfctx == NULL) {
        OPENSSL_free(key->key_password);
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }
    if (key->key_type == 0) {
        ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSession, key->key_index, &sdf_pub);
    } else {
        ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSession, key->key_index, &sdf_pub);
    }

    if (ret != OSSL_SDR_OK
        || !sdfprov_eccrefpub_to_ec_key(&sdf_pub, key->ec_key)) {
        OPENSSL_free(key->key_password);
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key);
        sdfprov_key_uri_cleanup(&uri_info);
        return NULL;
    }

    memcpy(&key->cached_pubkey, &sdf_pub, sizeof(sdf_pub));
    sdfprov_key_uri_cleanup(&uri_info);
    return key;
}

/* match 操作 - 比较两个密钥是否匹配 */
static int sdfprov_sm2_match(const void *keydata1, const void *keydata2,
                              int selection)
{
    const SDF_SM2_KEY *key1 = keydata1;
    const SDF_SM2_KEY *key2 = keydata2;

    if (key1 == NULL || key2 == NULL)
        return 0;

    /* 硬件密钥按索引匹配 */
    if (key1->is_hardware_key && key2->is_hardware_key) {
        if (key1->key_index != key2->key_index)
            return 0;
        if (key1->key_type != key2->key_type)
            return 0;
        return 1;
    }

    /* 硬件+软件混合：按公钥点比较 */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        const EC_POINT *p1 = EC_KEY_get0_public_key(key1->ec_key);
        const EC_POINT *p2 = EC_KEY_get0_public_key(key2->ec_key);
        const EC_GROUP *g1 = EC_KEY_get0_group(key1->ec_key);

        if (p1 == NULL || p2 == NULL || g1 == NULL)
            return 0;

        return EC_POINT_cmp(g1, p1, p2, NULL) == 0;
    }

    return 1;
}

/* validate 操作 - 验证密钥有效性 */
static int sdfprov_sm2_validate(const void *keydata, int selection,
                                 int checktype)
{
    const SDF_SM2_KEY *key = keydata;
    const EC_POINT *pub_point;

    if (key == NULL)
        return 0;

    /* 硬件密钥总是有效的 */
    if (key->is_hardware_key)
        return 1;

    /* 软件密钥验证 */
    if (key->ec_key == NULL)
        return 0;

    pub_point = EC_KEY_get0_public_key(key->ec_key);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && pub_point == NULL)
        return 0;

    return 1;
}

/* dup 操作 - 复制密钥，绕过跨 Provider export/import 问题 */
static void *sdfprov_sm2_dup(const void *keydata_from, int selection)
{
    SDF_SM2_KEY *from = (SDF_SM2_KEY *)keydata_from;
    SDF_SM2_KEY *dup_key = NULL;
    const EC_KEY *dup_ec;

    if (from == NULL)
        return NULL;

    /* 使用 ossl_ec_key_dup 复制 EC_KEY */
    dup_ec = ossl_ec_key_dup(from->ec_key, selection);
    if (dup_ec == NULL)
        return NULL;

    dup_key = OPENSSL_malloc(sizeof(*dup_key));
    if (dup_key == NULL) {
        EC_KEY_free((EC_KEY *)dup_ec);
        return NULL;
    }

    memcpy(dup_key, from, sizeof(*dup_key));
    dup_key->ec_key = (EC_KEY *)dup_ec;
    dup_key->key_password = NULL;
    dup_key->agreement_handle = NULL;  /* 不共享 SDF 协商句柄 */
    dup_key->has_agreement = 0;

    /* 复制私钥访问控制码 */
    if (from->key_password != NULL) {
        dup_key->key_password = OPENSSL_strdup(from->key_password);
        if (dup_key->key_password == NULL) {
            EC_KEY_free(dup_key->ec_key);
            OPENSSL_free(dup_key);
            return NULL;
        }
    }

    return dup_key;
}

/* KEYMGMT query_operation_name - 使 EVP_PKEY_derive_init_ex 能找到 SM2DH KEYEXCH */
static const char *sdfprov_sm2_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "SM2DH";
    case OSSL_OP_SIGNATURE:
        return "SM2";
    case OSSL_OP_ASYM_CIPHER:
        return "SM2";
    }
    return NULL;
}

const OSSL_DISPATCH sdfprov_sm2_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sdfprov_sm2_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))sdfprov_sm2_freedata },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))sdfprov_sm2_has },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))sdfprov_sm2_gettable_params },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))sdfprov_sm2_get_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sdfprov_sm2_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sdfprov_sm2_gen },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
      (void (*)(void))sdfprov_sm2_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))sdfprov_sm2_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))sdfprov_sm2_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
      (void (*)(void))sdfprov_sm2_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sdfprov_sm2_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))sdfprov_sm2_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))sdfprov_sm2_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))sdfprov_sm2_export_types },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))sdfprov_sm2_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (void (*)(void))sdfprov_sm2_settable_params },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sdfprov_sm2_load_ex },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sdfprov_sm2_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))sdfprov_sm2_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))sdfprov_sm2_query_operation_name },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))sdfprov_sm2_dup },
    OSSL_DISPATCH_END
};
