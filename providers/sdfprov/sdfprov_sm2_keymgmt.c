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

/* 从全局 SDF 上下文获取设备会话并初始化设备（如果未初始化） */
static void *sdfprov_get_session(void)
{
    SDFPROV_CTX *sdfctx = sdfprov_get_global_ctx();

    if (sdfctx == NULL)
        return NULL;

    if (!sdfctx->initialized) {
        if (!sdfprov_ctx_init_device(sdfctx))
            return NULL;
    }

    return sdfctx->hSession;
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

    fprintf(stderr, "  [SDFPROV] sm2_newdata: key=%p ec_key=%p\n", (void*)key, (void*)key->ec_key);
    return key;
}

static void sdfprov_sm2_freedata(void *keydata)
{
    SDF_SM2_KEY *key = keydata;

    fprintf(stderr, "  [SDFPROV] sm2_freedata: key=%p ec_key=%p\n",
            keydata, key ? (void*)key->ec_key : NULL);

    if (key == NULL)
        return;

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
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
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

    return 1;
}

/* 生成上下文 - 用于 keygen 操作 */
typedef struct sdfprov_gen_ctx_st {
    OSSL_LIB_CTX *libctx;
    int selection;
} SDFPROV_GEN_CTX;

static void *sdfprov_sm2_gen_init(void *provctx, int selection)
{
    SDFPROV_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;
    gctx->libctx = PROV_LIBCTX_OF(provctx);
    gctx->selection = selection;
    fprintf(stderr, "  [SDFPROV] sm2_gen_init: gctx=%p\n", (void*)gctx);
    return gctx;
}

static void *sdfprov_sm2_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    SDFPROV_GEN_CTX *gctx = genctx;
    SDF_SM2_KEY *key;

    if (gctx == NULL)
        return NULL;

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
        if (!EC_KEY_generate_key(key->ec_key)) {
            EC_KEY_free(key->ec_key);
            OPENSSL_free(key);
            return NULL;
        }
    }

    key->is_hardware_key = 0;
    fprintf(stderr, "  [SDFPROV] sm2_gen: gctx=%p -> key=%p ec_key=%p\n",
            (void*)gctx, (void*)key, (void*)key->ec_key);
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
        /* Accept SM2 curve name, ignore others */
        char name[64] = {0};
        if (!OSSL_PARAM_get_utf8_string(p, &name, sizeof(name) - 1))
            return 0;
        fprintf(stderr, "  [SDFPROV] sm2_gen_set_params: group=%s\n", name);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) {
        int bits = 0;
        if (!OSSL_PARAM_get_int(p, &bits))
            return 0;
        fprintf(stderr, "  [SDFPROV] sm2_gen_set_params: bits=%d\n", bits);
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
    fprintf(stderr, "  [SDFPROV] sm2_gen_cleanup: gctx=%p\n", (void*)gctx);
    OPENSSL_free(gctx);
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

    fprintf(stderr, "  [SDFPROV] sm2_import: key=%p ec_key=%p selection=%d pub_point=%p\n",
            keydata, key ? (void*)key->ec_key : NULL, selection,
            key && key->ec_key ? (void*)EC_KEY_get0_public_key(key->ec_key) : NULL);

    if (key == NULL) {
        fprintf(stderr, "  [SDFPROV] sm2_import: key=NULL -> fail\n");
        return 0;
    }

    /* 导入公钥 */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, (void **)&pub, 0, &pub_len)) {
            fprintf(stderr, "  [SDFPROV] sm2_import: get_octet_string failed\n");
            return 0;
        }
        fprintf(stderr, "  [SDFPROV] sm2_import: pub_len=%zu\n", pub_len);
        if (!EC_KEY_oct2key(key->ec_key, pub, pub_len, NULL)) {
            fprintf(stderr, "  [SDFPROV] sm2_import: EC_KEY_oct2key failed\n");
            return 0;
        }
        key->is_hardware_key = 0;
        fprintf(stderr, "  [SDFPROV] sm2_import: imported pub_key, ec_key=%p pub_point=%p\n",
                (void*)key->ec_key, (void*)EC_KEY_get0_public_key(key->ec_key));
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
                               int param_cb_type, void *cbarg,
                               OSSL_CALLBACK *cb)
{
    SDF_SM2_KEY *key = keydata;
    unsigned char *pub = NULL;
    int pub_len;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;
    BN_CTX *bnctx = NULL;

    fprintf(stderr, "  [SDFPROV] sm2_export: key=%p selection=%d\n",
            keydata, selection);

    if (key == NULL || key->ec_key == NULL)
        return 0;

    /*
     * OpenSSL KEYMGMT export 要求：
     * 1. 必须导出 domain parameters（曲线参数）
     * 2. 如果请求私钥，必须同时请求公钥
     */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    /*
     * 硬件密钥无法导出私钥。如果请求方需要私钥，必须返回失败，
     * 以便 OpenSSL 框架回退到密钥自身 Provider 的 ASYM_CIPHER 操作。
     */
    if (key->is_hardware_key
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        fprintf(stderr, "  [SDFPROV] sm2_export: hardware key, refusing private export\n");
        return 0;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    bnctx = BN_CTX_new_ex(key->libctx);
    if (bnctx == NULL)
        goto err;

    /* 导出曲线参数 - 只导出组名称 */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        const EC_GROUP *group = EC_KEY_get0_group(key->ec_key);

        if (group == NULL)
            goto err;

        /* 导出曲线名称 */
        const char *curve_name = OSSL_EC_curve_nid2name(EC_GROUP_get_curve_name(group));
        if (curve_name == NULL) {
            fprintf(stderr, "  [SDFPROV] sm2_export: unknown curve\n");
            goto err;
        }

        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0)) {
            fprintf(stderr, "  [SDFPROV] sm2_export: push group name failed\n");
            goto err;
        }
    }

    /* 导出公钥 */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        pub_len = EC_KEY_key2buf(key->ec_key, POINT_CONVERSION_UNCOMPRESSED,
                                 &pub, NULL);
        if (pub_len <= 0) {
            fprintf(stderr, "  [SDFPROV] sm2_export: EC_KEY_key2buf failed\n");
            goto err;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                               pub, (size_t)pub_len)) {
            fprintf(stderr, "  [SDFPROV] sm2_export: push pub_key failed\n");
            goto err;
        }
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
                                        priv_key, sz)) {
            fprintf(stderr, "  [SDFPROV] sm2_export: push priv_key failed\n");
            goto err;
        }
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        fprintf(stderr, "  [SDFPROV] sm2_export: OSSL_PARAM_BLD_to_param failed\n");
        goto err;
    }

    /*
     * 跨 Provider export cb 在当前实现中会 crash（ec_kmgmt import 无法处理
     * sdfprov 导出的 params）。让 export 返回失败，EVP 会回退到使用原始
     * provider 的密钥（通过 query_operation_name 路由到同 provider 的 KEYEXCH）。
     * DUP 操作也可用于同 provider 内的密钥复制。
     */
    ret = 0;
    goto err;

    ret = cb(params, cbarg);
    ret = 1;
err:
    OPENSSL_free(pub);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_CTX_free(bnctx);
    return ret;
}

static const OSSL_PARAM *sdfprov_sm2_import_types(int selection)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static const OSSL_PARAM *sdfprov_sm2_export_types(int selection)
{
    static const OSSL_PARAM params[] = {
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

    return 1;
}

static const OSSL_PARAM *sdfprov_sm2_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_uint("sdf-key-index", NULL),
        OSSL_PARAM_int("sdf-key-type", NULL),
        OSSL_PARAM_int("sdf-is-hardware", NULL),
        OSSL_PARAM_END
    };
    return params;
}

/*
 * KEYMGMT "load" 操作: 从对象识别信息加载密钥
 * object_reference 格式: "sdf:<key_index>:<key_type>"
 *   key_type: "sign" (0) 或 "enc" (1)
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
    const char *ref_str;
    const char *colon;
    char *endp;

    if (reference == NULL || reference_sz == 0)
        return NULL;

    ref_str = (const char *)reference;

    /* 解析 "sdf:<index>:<type>" 格式 */
    if (strncmp(ref_str, "sdf:", 4) != 0)
        return NULL;

    key_index = (unsigned int)strtoul(ref_str + 4, &endp, 10);
    if (*endp != ':')
        return NULL;

    colon = endp + 1;
    if (strcmp(colon, "sign") == 0 || strcmp(colon, "0") == 0)
        key_type = 0;
    else if (strcmp(colon, "enc") == 0 || strcmp(colon, "1") == 0)
        key_type = 1;
    else
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
    key->ec_key = EC_KEY_new_by_curve_name_ex(key->libctx, NULL, NID_sm2);
    if (key->ec_key == NULL) {
        OPENSSL_free(key);
        return NULL;
    }

    key->is_hardware_key = 1;
    key->key_index = key_index;
    key->key_type = key_type;
    key->hSession = hSession;

    /* 从设备导出公钥 */
    memset(&sdf_pub, 0, sizeof(sdf_pub));
    if (key_type == 0) {
        ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSession, key_index, &sdf_pub);
    } else {
        ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSession, key_index, &sdf_pub);
    }

    if (ret != OSSL_SDR_OK) {
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key);
        return NULL;
    }

    /* 转换 ECCrefPublicKey -> EC_KEY 公钥点 */
    if (!sdfprov_eccrefpub_to_ec_key(&sdf_pub, key->ec_key)) {
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key);
        return NULL;
    }

    /* 缓存公钥原始数据 */
    memcpy(&key->cached_pubkey, &sdf_pub, sizeof(sdf_pub));

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

    /* 软件密钥按 EC_KEY 公钥点匹配 */
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

    fprintf(stderr, "  [SDFPROV] sm2_validate: key=%p selection=%d checktype=%d\n",
            keydata, selection, checktype);

    if (key == NULL) {
        fprintf(stderr, "  [SDFPROV] sm2_validate: key=NULL -> invalid\n");
        return 0;
    }

    fprintf(stderr, "  [SDFPROV] sm2_validate: ec_key=%p is_hw=%d\n",
            (void*)key->ec_key, key->is_hardware_key);

    /* 硬件密钥总是有效的 */
    if (key->is_hardware_key) {
        fprintf(stderr, "  [SDFPROV] sm2_validate: hardware key -> valid\n");
        return 1;
    }

    /* 软件密钥验证 */
    if (key->ec_key == NULL) {
        fprintf(stderr, "  [SDFPROV] sm2_validate: no ec_key -> invalid\n");
        return 0;
    }

    pub_point = EC_KEY_get0_public_key(key->ec_key);
    fprintf(stderr, "  [SDFPROV] sm2_validate: pub_point=%p\n", (void*)pub_point);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && pub_point == NULL) {
        fprintf(stderr, "  [SDFPROV] sm2_validate: no public key -> invalid\n");
        return 0;
    }

    fprintf(stderr, "  [SDFPROV] sm2_validate: software key -> valid\n");
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

    fprintf(stderr, "  [SDFPROV] sm2_dup: from=%p -> dup=%p ec_key=%p\n",
            keydata_from, (void*)dup_key, (void*)dup_key->ec_key);

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
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sdfprov_sm2_load },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))sdfprov_sm2_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))sdfprov_sm2_validate },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))sdfprov_sm2_query_operation_name },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))sdfprov_sm2_dup },
    OSSL_DISPATCH_END
};
