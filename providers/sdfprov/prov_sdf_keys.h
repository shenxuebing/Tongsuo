/*
 * SDF Provider for Tongsuo - KEYMGMT Module
 *
 * 密钥生命周期管理，基于 GM/T 0018 SDF 接口
 * 私钥永不离卡，仅管理公钥和设备密钥引用
 */

#ifndef PROV_SDF_KEYS_H
#define PROV_SDF_KEYS_H

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov_sdf.h"

/*
 * KEYMGMT 支持的选择组合:
 * - OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
 *   (公钥 + 域参数)
 *
 * 私钥不能导入/导出，私钥操作通过 key_index 引用卡上密钥完成
 */
#define SDF_KEYMGMT_POSSIBLE_SELECTIONS \
    (OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

/* 自定义参数名 */
#define SDF_PARAM_KEY_INDEX     "sdf-key-index"
#define SDF_PARAM_KEY_USAGE     "sdf-key-usage"

/* SM2 密钥用途 (对应 SDF 标准) */
#define SDF_KEY_USAGE_SIGN      1   /* SGD_SM2_1 - 签名 */
#define SDF_KEY_USAGE_ENCRYPT   2   /* SGD_SM2_2 - 加密 */
#define SDF_KEY_USAGE_EXCHANGE  3   /* SGD_SM2_3 - 密钥协商 */

/* SM2 公钥未压缩格式长度: 0x04 || X(32) || Y(32) = 65 bytes */
#define SM2_UNCOMPRESSED_PUBKEY_LEN  65

/*============================================================================
 * SM2 密钥生成上下文
 *===========================================================================*/
typedef struct sdf_sm2_gen_ctx_st {
    SDF_PROV_CTX *provctx;
    /*
     * 密钥生成参数:
     * - 在 SDF Provider 中，密钥对通常已存在于密码卡上
     * - gen 操作创建一个新的 SDF_PROV_KEY 对象，关联到指定的 key_index
     * - 如果 key_index 指定为 0，则仅生成空壳密钥对象
     */
    int key_index;
    int key_usage;
    const EC_GROUP *group;
    /* 后续回调 */
    OSSL_CALLBACK *cb;
    void *cbarg;
} SDF_SM2_GEN_CTX;

/*============================================================================
 * SM2 KEYMGMT 函数声明
 *===========================================================================*/

/* 密钥对象生命周期 */
void *sdf_sm2_keymgmt_new(void *provctx);
void sdf_sm2_keymgmt_free(void *keydata);
void *sdf_sm2_keymgmt_dup(const void *keydata, int selection);
int sdf_sm2_keymgmt_load(const void *reference, size_t reference_sz,
                         int selection);

/* 密钥属性检查 */
int sdf_sm2_keymgmt_has(const void *keydata, int selection);
int sdf_sm2_keymgmt_match(const void *keydata1, const void *keydata2,
                           int selection);
int sdf_sm2_keymgmt_validate(const void *keydata, int selection,
                              int checktype);

/* 参数获取/设置 */
int sdf_sm2_keymgmt_get_params(void *keydata, OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm2_keymgmt_gettable_params(void *provctx);
int sdf_sm2_keymgmt_set_params(void *keydata, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm2_keymgmt_settable_params(void *provctx);

/* 导入/导出 */
int sdf_sm2_keymgmt_import(void *keydata, int selection,
                            const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm2_keymgmt_import_types(int selection);
int sdf_sm2_keymgmt_export(void *keydata, int selection,
                            OSSL_CALLBACK *param_cb, void *cbarg);
const OSSL_PARAM *sdf_sm2_keymgmt_export_types(int selection);

/* 密钥生成 */
void *sdf_sm2_keymgmt_gen_init(void *provctx, int selection,
                                const OSSL_PARAM params[]);
void sdf_sm2_keymgmt_gen_cleanup(void *genctx);
int sdf_sm2_keymgmt_gen_set_params(void *genctx,
                                    const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm2_keymgmt_gen_settable_params(void *genctx);
int sdf_sm2_keymgmt_gen_set_template(void *genctx, void *templ);
int sdf_sm2_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg);

/* 操作名查询 */
const char *sdf_sm2_keymgmt_query_operation_name(int operation_id);

/* 分发表 */
const OSSL_DISPATCH *sdf_sm2_keymgmt_functions(void);

/* 算法定义 (供 prov_sdf.c query 使用) */
extern const OSSL_ALGORITHM sdf_keymgmt_sm2[];

/*============================================================================
 * 内部辅助函数
 *===========================================================================*/

/*
 * 从 SDF 设备导出公钥并填充到 SDF_PROV_KEY 中
 * 根据 key_usage 调用对应的 Export 接口
 */
int sdf_sm2_export_pubkey_from_device(SDF_PROV_KEY *key);

/*
 * 将 OSSL_ECCrefPublicKey 转换为 EC_POINT
 * 成功返回 1，失败返回 0
 */
int sdf_eccref_to_ec_point(const EC_GROUP *group,
                            const OSSL_ECCrefPublicKey *ecc_ref,
                            EC_POINT **out_point);

/*
 * 将 EC_POINT 序列化为未压缩格式 octet string
 * 返回分配的 buffer 和长度，调用者需 OPENSSL_free
 */
int sdf_ec_point_to_oct(const EC_GROUP *group, const EC_POINT *point,
                         unsigned char **out_buf, size_t *out_len);

#endif /* PROV_SDF_KEYS_H */
