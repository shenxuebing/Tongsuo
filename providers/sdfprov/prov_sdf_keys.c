/*
 * SDF Provider for Tongsuo - KEYMGMT Module Implementation
 *
 * SM2 密钥生命周期管理，基于 GM/T 0018 SDF 接口
 * 私钥永不离卡，KEYMGMT 仅管理公钥和设备密钥引用
 */

#include "prov_sdf_keys.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/core.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>
#include <string.h>

/*============================================================================
 * 分发表
 *===========================================================================*/

static const OSSL_DISPATCH sdf_sm2_keymgmt_dispatch[] = {
    { OSSL_FUNC_KEYMGMT_NEW,              (void (*)(void))sdf_sm2_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE,             (void (*)(void))sdf_sm2_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_DUP,              (void (*)(void))sdf_sm2_keymgmt_dup },
    { OSSL_FUNC_KEYMGMT_LOAD,             (void (*)(void))sdf_sm2_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_HAS,              (void (*)(void))sdf_sm2_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH,            (void (*)(void))sdf_sm2_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE,         (void (*)(void))sdf_sm2_keymgmt_validate },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,       (void (*)(void))sdf_sm2_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,  (void (*)(void))sdf_sm2_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,       (void (*)(void))sdf_sm2_keymgmt_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,  (void (*)(void))sdf_sm2_keymgmt_settable_params },
    { OSSL_FUNC_KEYMGMT_IMPORT,           (void (*)(void))sdf_sm2_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,     (void (*)(void))sdf_sm2_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,           (void (*)(void))sdf_sm2_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,     (void (*)(void))sdf_sm2_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,         (void (*)(void))sdf_sm2_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,      (void (*)(void))sdf_sm2_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,   (void (*)(void))sdf_sm2_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                                         (void (*)(void))sdf_sm2_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))sdf_sm2_keymgmt_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN,              (void (*)(void))sdf_sm2_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
                                         (void (*)(void))sdf_sm2_keymgmt_query_operation_name },
    { 0, NULL }
};

/*============================================================================
 * SM2 KEYMGMT 算法查询表
 *===========================================================================*/

const OSSL_ALGORITHM sdf_keymgmt_sm2[] = {
    { "SM2", "provider=sdfprov", sdf_sm2_keymgmt_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};

/*============================================================================
 * 参数表定义
 *===========================================================================*/

/* gettable_params: 查询可以获取哪些参数 */
static const OSSL_PARAM sdf_sm2_keymgmt_gettable[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL, 0),
    OSSL_PARAM_int(SDF_PARAM_KEY_INDEX, NULL),
    OSSL_PARAM_int(SDF_PARAM_KEY_USAGE, NULL),
    OSSL_PARAM_END
};

/* settable_params: 设置密钥参数 (key_index, key_usage, pub_key) */
static const OSSL_PARAM sdf_sm2_keymgmt_settable[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_int(SDF_PARAM_KEY_INDEX, NULL),
    OSSL_PARAM_int(SDF_PARAM_KEY_USAGE, NULL),
    OSSL_PARAM_END
};

/* import_types: 可导入的参数类型 */
static const OSSL_PARAM sdf_sm2_keymgmt_import_types_tbl[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

/* export_types: 可导出的参数类型 */
static const OSSL_PARAM sdf_sm2_keymgmt_export_types_tbl[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

/* gen_settable_params: 密钥生成时设置的参数 */
static const OSSL_PARAM sdf_sm2_keymgmt_gen_settable[] = {
    OSSL_PARAM_int(SDF_PARAM_KEY_INDEX, NULL),
    OSSL_PARAM_int(SDF_PARAM_KEY_USAGE, NULL),
    OSSL_PARAM_END
};

/*============================================================================
 * 辅助函数实现
 *============================================================================*/

/*
 * 将 OSSL_ECCrefPublicKey (来自密码卡) 转换为 EC_POINT
 *
 * OSSL_ECCrefPublicKey 包含 x, y 坐标 (大端)，bits 表示有效位数
 */
int sdf_eccref_to_ec_point(const EC_GROUP *group,
                            const OSSL_ECCrefPublicKey *ecc_ref,
                            EC_POINT **out_point)
{
    EC_POINT *point = NULL;
    BIGNUM *bn_x = NULL, *bn_y = NULL;
    int byte_len;
    int ret = 0;

    if (group == NULL || ecc_ref == NULL || out_point == NULL)
        return 0;

    byte_len = (ecc_ref->bits + 7) / 8;
    if (byte_len <= 0 || byte_len > OSSL_ECCref_MAX_LEN)
        byte_len = OSSL_ECCref_MAX_LEN; /* bits=0 时使用最大长度 */

    bn_x = BN_bin2bn(ecc_ref->x, byte_len, NULL);
    bn_y = BN_bin2bn(ecc_ref->y, byte_len, NULL);
    if (bn_x == NULL || bn_y == NULL)
        goto err;

    point = EC_POINT_new(group);
    if (point == NULL)
        goto err;

    if (!EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, NULL))
        goto err;

    *out_point = point;
    point = NULL;
    ret = 1;

err:
    BN_free(bn_x);
    BN_free(bn_y);
    EC_POINT_free(point);
    return ret;
}

/*
 * 将 EC_POINT 序列化为未压缩格式 octet string
 * SM2 使用未压缩格式: 0x04 || X(32) || Y(32)
 */
int sdf_ec_point_to_oct(const EC_GROUP *group, const EC_POINT *point,
                         unsigned char **out_buf, size_t *out_len)
{
    size_t len;
    unsigned char *buf = NULL;

    if (group == NULL || point == NULL || out_buf == NULL || out_len == NULL)
        return 0;

    len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                              NULL, 0, NULL);
    if (len == 0)
        return 0;

    buf = OPENSSL_malloc(len);
    if (buf == NULL)
        return 0;

    len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                              buf, len, NULL);
    if (len == 0) {
        OPENSSL_free(buf);
        return 0;
    }

    *out_buf = buf;
    *out_len = len;
    return 1;
}

/*
 * 从 SDF 设备导出公钥并填充到 SDF_PROV_KEY 的 ec_key 和 pubkey_buf
 *
 * 根据 key_usage 调用对应的 Export 接口:
 * - SDF_KEY_USAGE_SIGN:    SDF_ExportSignPublicKey_ECC
 * - SDF_KEY_USAGE_ENCRYPT: SDF_ExportEncPublicKey_ECC
 * - SDF_KEY_USAGE_EXCHANGE: SDF_ExportEncPublicKey_ECC (加密密钥)
 */
int sdf_sm2_export_pubkey_from_device(SDF_PROV_KEY *key)
{
    OSSL_ECCrefPublicKey ecc_pub = { 0 };
    EC_POINT *point = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    int ret = 0;
    int sdf_ret;

    if (key == NULL || key->ctx == NULL)
        return 0;

    if (!key->ctx->card_available || !key->ctx->initialized) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    if (key->key_index <= 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    /* 根据 key_usage 选择导出接口 */
    switch (key->key_usage) {
    case SDF_KEY_USAGE_SIGN:
        sdf_ret = SDF_CALL(key->ctx, SDF_ExportSignPublicKey_ECC,
            key->ctx->hSession, (unsigned int)key->key_index, &ecc_pub);
        break;
    case SDF_KEY_USAGE_ENCRYPT:
    case SDF_KEY_USAGE_EXCHANGE:
        sdf_ret = SDF_CALL(key->ctx, SDF_ExportEncPublicKey_ECC,
            key->ctx->hSession, (unsigned int)key->key_index, &ecc_pub);
        break;
    default:
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    if (sdf_ret != SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
        return 0;
    }

    /* 创建 SM2 EC_KEY 并填充公钥 */
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL)
        goto err;

    group = EC_KEY_get0_group(ec_key);

    /* 将 OSSL_ECCrefPublicKey 转为 EC_POINT */
    if (!sdf_eccref_to_ec_point(group, &ecc_pub, &point))
        goto err;

    if (!EC_KEY_set_public_key(ec_key, point))
        goto err;

    /* 序列化公钥为 octet string */
    if (key->pubkey_buf != NULL) {
        OPENSSL_free(key->pubkey_buf);
        key->pubkey_buf = NULL;
    }
    if (!sdf_ec_point_to_oct(group, point, &key->pubkey_buf,
                              (size_t *)&key->pubkey_len))
        goto err;

    /* 替换 ec_key */
    EC_KEY_free(key->ec_key);
    key->ec_key = ec_key;
    ec_key = NULL;
    ret = 1;

err:
    EC_POINT_free(point);
    if (ec_key != NULL)
        EC_KEY_free(ec_key);
    return ret;
}

/*============================================================================
 * 密钥对象生命周期
 *===========================================================================*/

void *sdf_sm2_keymgmt_new(void *provctx)
{
    SDF_PROV_CTX *ctx = (SDF_PROV_CTX *)provctx;
    SDF_PROV_KEY *key = NULL;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;

    key->ctx = ctx;
    key->key_index = -1;      /* 未设置 */
    key->key_usage = 0;
    key->algorithm_id = NID_sm2;
    key->ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (key->ec_key == NULL)
        goto err;

    key->pubkey_buf = NULL;
    key->pubkey_len = 0;
    key->refcnt = 1;

    return key;

err:
    OPENSSL_free(key);
    return NULL;
}

void sdf_sm2_keymgmt_free(void *keydata)
{
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)keydata;

    if (key == NULL)
        return;

    if (!CRYPTO_atomic_add(&key->refcnt, -1, NULL, NULL))
        /* 引用计数为 0 或下溢，直接释放 */
        ;
    else if (key->refcnt > 0)
        /* 仍有引用，不释放 */
        return;

    EC_KEY_free(key->ec_key);
    OPENSSL_free(key->pubkey_buf);
    OPENSSL_free(key);
}

void *sdf_sm2_keymgmt_dup(const void *keydata, int selection)
{
    const SDF_PROV_KEY *src = (const SDF_PROV_KEY *)keydata;
    SDF_PROV_KEY *dst = NULL;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->ctx = src->ctx;
    dst->key_index = src->key_index;
    dst->key_usage = src->key_usage;
    dst->algorithm_id = src->algorithm_id;
    dst->refcnt = 1;

    /* 复制 EC_KEY (包含公钥) */
    if (src->ec_key != NULL) {
        dst->ec_key = EC_KEY_dup(src->ec_key);
        if (dst->ec_key == NULL)
            goto err;
    }

    /* 复制公钥 buffer */
    if (src->pubkey_buf != NULL && src->pubkey_len > 0) {
        dst->pubkey_buf = OPENSSL_memdup(src->pubkey_buf, src->pubkey_len);
        if (dst->pubkey_buf == NULL)
            goto err;
        dst->pubkey_len = src->pubkey_len;
    }

    return dst;

err:
    if (dst != NULL) {
        EC_KEY_free(dst->ec_key);
        OPENSSL_free(dst->pubkey_buf);
        OPENSSL_free(dst);
    }
    return NULL;
}

int sdf_sm2_keymgmt_load(const void *reference, size_t reference_sz,
                          int selection)
{
    /*
     * load 从参考码创建密钥对象。
     * 在 SDF Provider 中，密钥对象通过 key_index 引用，
     * reference 可以是 key_index 的编码。
     * 目前暂不实现此接口，返回 0。
     */
    return 0;
}

/*============================================================================
 * 密钥属性检查
 *===========================================================================*/

int sdf_sm2_keymgmt_has(const void *keydata, int selection)
{
    const SDF_PROV_KEY *key = (const SDF_PROV_KEY *)keydata;

    if (key == NULL)
        return 0;

    if ((selection & SDF_KEYMGMT_POSSIBLE_SELECTIONS) == 0)
        return 1; /* 选择项不在范围内，视为存在 */

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        /* 检查是否有 EC_GROUP */
        if (key->ec_key == NULL || EC_KEY_get0_group(key->ec_key) == NULL)
            return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* 检查是否有公钥 */
        if (key->ec_key == NULL || EC_KEY_get0_public_key(key->ec_key) == NULL) {
            /* 尝试从设备导出 */
            if (key->key_index > 0 && key->ctx != NULL &&
                key->ctx->card_available) {
                SDF_PROV_KEY *mutable_key = (SDF_PROV_KEY *)key;
                if (!sdf_sm2_export_pubkey_from_device(mutable_key))
                    return 0;
            } else {
                return 0;
            }
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /*
         * 私钥在密码卡上，我们不能直接持有。
         * 如果设置了 key_index 且密码卡可用，认为"有"私钥。
         */
        if (key->key_index <= 0 || key->ctx == NULL ||
            !key->ctx->card_available)
            return 0;
    }

    return 1;
}

int sdf_sm2_keymgmt_match(const void *keydata1, const void *keydata2,
                           int selection)
{
    const SDF_PROV_KEY *k1 = (const SDF_PROV_KEY *)keydata1;
    const SDF_PROV_KEY *k2 = (const SDF_PROV_KEY *)keydata2;
    const EC_GROUP *g1, *g2;
    BN_CTX *bnctx = NULL;
    int ok = 1;

    if (k1 == NULL || k2 == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        g1 = (k1->ec_key != NULL) ? EC_KEY_get0_group(k1->ec_key) : NULL;
        g2 = (k2->ec_key != NULL) ? EC_KEY_get0_group(k2->ec_key) : NULL;
        if (g1 != NULL && g2 != NULL) {
            bnctx = BN_CTX_new();
            if (bnctx == NULL)
                return 0;
            ok = ok && (EC_GROUP_cmp(g1, g2, bnctx) == 0);
            BN_CTX_free(bnctx);
            bnctx = NULL;
        } else {
            ok = ok && (g1 == g2);
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* 比较 key_index (同一个设备上的同一对密钥) */
        ok = ok && (k1->key_index == k2->key_index);

        /* 如果 key_index 相同，比较公钥点 */
        if (ok && k1->key_index > 0 && k1->ec_key != NULL &&
            k2->ec_key != NULL) {
            const EC_POINT *p1 = EC_KEY_get0_public_key(k1->ec_key);
            const EC_POINT *p2 = EC_KEY_get0_public_key(k2->ec_key);
            if (p1 != NULL && p2 != NULL) {
                const EC_GROUP *g = EC_KEY_get0_group(k1->ec_key);
                bnctx = BN_CTX_new();
                if (bnctx == NULL)
                    return 0;
                ok = ok && (EC_POINT_cmp(g, p1, p2, bnctx) == 0);
                BN_CTX_free(bnctx);
            }
        }
    }

    return ok;
}

int sdf_sm2_keymgmt_validate(const void *keydata, int selection,
                              int checktype)
{
    const SDF_PROV_KEY *key = (const SDF_PROV_KEY *)keydata;
    int ok = 1;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        if (key->ec_key == NULL || EC_KEY_get0_group(key->ec_key) == NULL)
            ok = 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (key->ec_key == NULL || EC_KEY_get0_public_key(key->ec_key) == NULL) {
            ok = 0;
        } else if (checktype == OSSL_KEYMGMT_VALIDATE_FULL_CHECK) {
            /* 完整校验: 检查公钥点是否在曲线上 */
            const EC_POINT *pub = EC_KEY_get0_public_key(key->ec_key);
            const EC_GROUP *group = EC_KEY_get0_group(key->ec_key);
            if (pub == NULL || group == NULL ||
                !EC_POINT_is_on_curve(group, pub, NULL))
                ok = 0;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /*
         * 私钥在密码卡上，无法本地校验。
         * 只检查 key_index 是否有效 (大于 0 且密码卡可用)。
         */
        if (key->key_index <= 0 || key->ctx == NULL ||
            !key->ctx->card_available)
            ok = 0;
    }

    return ok;
}

/*============================================================================
 * 参数获取/设置
 *===========================================================================*/

const OSSL_PARAM *sdf_sm2_keymgmt_gettable_params(void *provctx)
{
    return sdf_sm2_keymgmt_gettable;
}

int sdf_sm2_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)keydata;
    OSSL_PARAM *p;
    unsigned char *pub_oct = NULL;
    size_t pub_oct_len = 0;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        /* 尝试从 ec_key 导出公钥 */
        if (key->ec_key != NULL &&
            EC_KEY_get0_public_key(key->ec_key) != NULL) {
            if (!sdf_ec_point_to_oct(EC_KEY_get0_group(key->ec_key),
                                      EC_KEY_get0_public_key(key->ec_key),
                                      &pub_oct, &pub_oct_len))
                return 0;
        } else if (key->pubkey_buf != NULL && key->pubkey_len > 0) {
            pub_oct = OPENSSL_memdup(key->pubkey_buf, key->pubkey_len);
            pub_oct_len = key->pubkey_len;
        } else if (key->key_index > 0 && key->ctx != NULL &&
                   key->ctx->card_available) {
            /* 尝试从设备导出 */
            if (!sdf_sm2_export_pubkey_from_device(key))
                return 0;
            pub_oct = OPENSSL_memdup(key->pubkey_buf, key->pubkey_len);
            pub_oct_len = key->pubkey_len;
        }

        if (pub_oct == NULL)
            return 0;

        if (!OSSL_PARAM_set_octet_string(p, pub_oct, pub_oct_len)) {
            OPENSSL_free(pub_oct);
            return 0;
        }
        OPENSSL_free(pub_oct);
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "SM2"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "uncompressed"))
        return 0;

    p = OSSL_PARAM_locate(params, SDF_PARAM_KEY_INDEX);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->key_index))
        return 0;

    p = OSSL_PARAM_locate(params, SDF_PARAM_KEY_USAGE);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->key_usage))
        return 0;

    return 1;
}

const OSSL_PARAM *sdf_sm2_keymgmt_settable_params(void *provctx)
{
    return sdf_sm2_keymgmt_settable;
}

int sdf_sm2_keymgmt_set_params(void *keydata, const OSSL_PARAM params[])
{
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)keydata;
    const OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    /* 设置密钥索引 */
    p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_INDEX);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &key->key_index))
            return 0;
    }

    /* 设置密钥用途 */
    p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_USAGE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &key->key_usage))
            return 0;
        /* 校验 key_usage 取值范围 */
        if (key->key_usage != SDF_KEY_USAGE_SIGN &&
            key->key_usage != SDF_KEY_USAGE_ENCRYPT &&
            key->key_usage != SDF_KEY_USAGE_EXCHANGE)
            return 0;
    }

    /* 设置公钥 */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        const unsigned char *pub_data;
        size_t pub_len;
        EC_POINT *point = NULL;
        const EC_GROUP *group = NULL;

        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pub_data,
                                              &pub_len))
            return 0;

        if (key->ec_key == NULL)
            return 0;

        group = EC_KEY_get0_group(key->ec_key);
        point = EC_POINT_new(group);
        if (point == NULL)
            return 0;

        if (!EC_POINT_oct2point(group, point, pub_data, pub_len, NULL)) {
            EC_POINT_free(point);
            return 0;
        }

        if (!EC_KEY_set_public_key(key->ec_key, point)) {
            EC_POINT_free(point);
            return 0;
        }
        EC_POINT_free(point);

        /* 更新 pubkey_buf */
        if (key->pubkey_buf != NULL)
            OPENSSL_free(key->pubkey_buf);
        key->pubkey_buf = OPENSSL_memdup(pub_data, pub_len);
        key->pubkey_len = (int)pub_len;
    }

    return 1;
}

/*============================================================================
 * 导入
 *===========================================================================*/

const OSSL_PARAM *sdf_sm2_keymgmt_import_types(int selection)
{
    if ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                       OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) != 0)
        return sdf_sm2_keymgmt_import_types_tbl;
    return NULL;
}

int sdf_sm2_keymgmt_import(void *keydata, int selection,
                            const OSSL_PARAM params[])
{
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)keydata;
    const OSSL_PARAM *p;
    int ok = 1;

    if (key == NULL || params == NULL)
        return 0;

    /*
     * 私钥不能导入 — 密钥在密码卡上，只能通过 key_index 引用
     */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    /* 导入域参数 (曲线名) */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if (p != NULL) {
            const char *group_name = NULL;
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &group_name))
                return 0;
            if (OPENSSL_strcasecmp(group_name, "SM2") != 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
                return 0;
            }
            /* 确认 EC_KEY 使用 SM2 曲线 */
            if (key->ec_key == NULL) {
                key->ec_key = EC_KEY_new_by_curve_name(NID_sm2);
                if (key->ec_key == NULL)
                    return 0;
            }
        }
    }

    /* 导入公钥 */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            const unsigned char *pub_data;
            size_t pub_len;
            EC_POINT *point = NULL;
            const EC_GROUP *group;

            if (key->ec_key == NULL) {
                key->ec_key = EC_KEY_new_by_curve_name(NID_sm2);
                if (key->ec_key == NULL)
                    return 0;
            }

            group = EC_KEY_get0_group(key->ec_key);

            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pub_data,
                                                  &pub_len))
                return 0;

            point = EC_POINT_new(group);
            if (point == NULL)
                return 0;

            if (!EC_POINT_oct2point(group, point, pub_data, pub_len, NULL)) {
                EC_POINT_free(point);
                return 0;
            }

            if (!EC_KEY_set_public_key(key->ec_key, point)) {
                EC_POINT_free(point);
                return 0;
            }
            EC_POINT_free(point);

            /* 更新 pubkey_buf */
            if (key->pubkey_buf != NULL)
                OPENSSL_free(key->pubkey_buf);
            key->pubkey_buf = OPENSSL_memdup(pub_data, pub_len);
            if (key->pubkey_buf == NULL)
                return 0;
            key->pubkey_len = (int)pub_len;
        }
    }

    /* SDF 特有参数: key_index 和 key_usage */
    p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_INDEX);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &key->key_index))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_USAGE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &key->key_usage))
            return 0;
        if (key->key_usage != SDF_KEY_USAGE_SIGN &&
            key->key_usage != SDF_KEY_USAGE_ENCRYPT &&
            key->key_usage != SDF_KEY_USAGE_EXCHANGE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }
    }

    return ok;
}

/*============================================================================
 * 导出
 *===========================================================================*/

const OSSL_PARAM *sdf_sm2_keymgmt_export_types(int selection)
{
    if ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                       OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) != 0)
        return sdf_sm2_keymgmt_export_types_tbl;
    return NULL;
}

int sdf_sm2_keymgmt_export(void *keydata, int selection,
                            OSSL_CALLBACK *param_cb, void *cbarg)
{
    SDF_PROV_KEY *key = (SDF_PROV_KEY *)keydata;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    unsigned char *pub_oct = NULL;
    size_t pub_oct_len = 0;
    int ret = 0;

    if (key == NULL || param_cb == NULL)
        return 0;

    /*
     * 私钥不能导出 — 私钥永不离卡
     */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    /* 导出域参数 */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                              "SM2", 3))
            goto err;
    }

    /* 导出公钥 */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        /* 确保有公钥数据 */
        if (key->pubkey_buf != NULL && key->pubkey_len > 0) {
            pub_oct = OPENSSL_memdup(key->pubkey_buf, key->pubkey_len);
            pub_oct_len = key->pubkey_len;
        } else if (key->ec_key != NULL &&
                   EC_KEY_get0_public_key(key->ec_key) != NULL) {
            if (!sdf_ec_point_to_oct(EC_KEY_get0_group(key->ec_key),
                                      EC_KEY_get0_public_key(key->ec_key),
                                      &pub_oct, &pub_oct_len))
                goto err;
        } else if (key->key_index > 0 && key->ctx != NULL &&
                   key->ctx->card_available) {
            /* 尝试从设备导出 */
            if (!sdf_sm2_export_pubkey_from_device(key))
                goto err;
            pub_oct = OPENSSL_memdup(key->pubkey_buf, key->pubkey_len);
            pub_oct_len = key->pubkey_len;
        }

        if (pub_oct == NULL || pub_oct_len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
            goto err;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                               pub_oct, pub_oct_len))
            goto err;
    }

    /* 构建 params */
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_free(pub_oct);
    return ret;
}

/*============================================================================
 * 密钥生成
 *===========================================================================*/

void *sdf_sm2_keymgmt_gen_init(void *provctx, int selection,
                                const OSSL_PARAM params[])
{
    SDF_SM2_GEN_CTX *gctx;

    if (provctx == NULL)
        return NULL;

    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;

    gctx->provctx = (SDF_PROV_CTX *)provctx;
    gctx->key_index = -1;
    gctx->key_usage = 0;
    gctx->group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (gctx->group == NULL)
        goto err;

    /* 解析初始参数 */
    if (params != NULL) {
        const OSSL_PARAM *p;

        p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_INDEX);
        if (p != NULL)
            OSSL_PARAM_get_int(p, &gctx->key_index);

        p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_USAGE);
        if (p != NULL)
            OSSL_PARAM_get_int(p, &gctx->key_usage);
    }

    return gctx;

err:
    EC_GROUP_free((EC_GROUP *)gctx->group);
    OPENSSL_free(gctx);
    return NULL;
}

void sdf_sm2_keymgmt_gen_cleanup(void *genctx)
{
    SDF_SM2_GEN_CTX *gctx = (SDF_SM2_GEN_CTX *)genctx;

    if (gctx == NULL)
        return;

    EC_GROUP_free((EC_GROUP *)gctx->group);
    OPENSSL_free(gctx);
}

const OSSL_PARAM *sdf_sm2_keymgmt_gen_settable_params(void *genctx)
{
    return sdf_sm2_keymgmt_gen_settable;
}

int sdf_sm2_keymgmt_gen_set_params(void *genctx,
                                    const OSSL_PARAM params[])
{
    SDF_SM2_GEN_CTX *gctx = (SDF_SM2_GEN_CTX *)genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_INDEX);
    if (p != NULL && !OSSL_PARAM_get_int(p, &gctx->key_index))
        return 0;

    p = OSSL_PARAM_locate_const(params, SDF_PARAM_KEY_USAGE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &gctx->key_usage))
            return 0;
        if (gctx->key_usage != SDF_KEY_USAGE_SIGN &&
            gctx->key_usage != SDF_KEY_USAGE_ENCRYPT &&
            gctx->key_usage != SDF_KEY_USAGE_EXCHANGE)
            return 0;
    }

    return 1;
}

int sdf_sm2_keymgmt_gen_set_template(void *genctx, void *templ)
{
    /*
     * 模板密钥: 从模板复制 key_index 和 key_usage 到生成上下文。
     * 在 SDF Provider 中，"生成"密钥意味着引用卡上已有的密钥对。
     */
    SDF_SM2_GEN_CTX *gctx = (SDF_SM2_GEN_CTX *)genctx;
    SDF_PROV_KEY *template_key = (SDF_PROV_KEY *)templ;

    if (gctx == NULL || template_key == NULL)
        return 0;

    gctx->key_index = template_key->key_index;
    gctx->key_usage = template_key->key_usage;

    return 1;
}

int sdf_sm2_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    SDF_SM2_GEN_CTX *gctx = (SDF_SM2_GEN_CTX *)genctx;
    SDF_PROV_KEY *key = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (gctx == NULL)
        return 0;

    /*
     * SDF Provider 的 "密钥生成":
     * 密钥对已经存在于密码卡上，gen 操作创建一个 SDF_PROV_KEY 对象，
     * 关联到指定的 key_index，并尝试从设备导出公钥。
     */
    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return 0;

    key->ctx = gctx->provctx;
    key->key_index = gctx->key_index;
    key->key_usage = gctx->key_usage;
    key->algorithm_id = NID_sm2;
    key->refcnt = 1;

    /* 创建 SM2 EC_KEY */
    key->ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (key->ec_key == NULL)
        goto err;

    /* 如果有 key_index 且密码卡可用，尝试导出公钥 */
    if (key->key_index > 0 && key->ctx != NULL &&
        key->ctx->card_available && key->key_usage > 0) {
        if (!sdf_sm2_export_pubkey_from_device(key)) {
            /* 公钥导出失败不一定是致命错误 */
            /* 密钥对象仍然有效，公钥可以后续再导出 */
        }
    }

    /* 通过回调传递密钥引用 */
    params = OPENSSL_zalloc(sizeof(OSSL_PARAM) + sizeof(OSSL_PARAM));
    if (params == NULL)
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PRIV_KEY, NULL, (size_t)0);
    params[0].data = (void *)key;
    params[0].data_size = sizeof(*key);
    params[1] = OSSL_PARAM_construct_end();

    ret = cb(params, cbarg);

err:
    OSSL_PARAM_free(params);
    if (!ret && key != NULL) {
        EC_KEY_free(key->ec_key);
        OPENSSL_free(key->pubkey_buf);
        OPENSSL_free(key);
    }
    return ret;
}

/*============================================================================
 * 操作名查询
 *============================================================================*/

const char *sdf_sm2_keymgmt_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return "SM2";
    case OSSL_OP_ASYM_CIPHER:
        return "SM2";
    default:
        return NULL;
    }
}
