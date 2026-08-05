/*
 * SDFE API Stub 实现
 *
 * SDFE_* 扩展函数通过 ossl_sdf_get_method() 获取 DSO 动态绑定的厂商库
 * 函数指针表（sdfm），转发到厂商库的管理接口。
 * 厂商库未加载（静态链接或 preload 未执行）时返回 OSSL_SDR_NOTSUPPORT。
 *
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <stddef.h>
#include <string.h>
#include <openssl/sdf.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/sdf.h"
#include "../sdf/sdf_local.h"
#include "sdfe_api.h"

/* 获取 DSO 绑定的厂商库函数指针表，未加载时返回 NULL */
#define SDFE_GET_METH()  ossl_sdf_get_method()

/*
 * 统一的函数指针空值检查。
 * member 是 SDF_METHOD 的成员名（如 ImportECCKey、InputRSAKey），
 * 错误信息打印实际成员名，帮助定位厂商库缺少哪个接口。
 * 不硬编码厂商前缀（SWCSM_/BYCSM_/SDF_），适用于所有厂商。
 */
#define SDFE_CHECK_METH(meth, member)                                 \
    do {                                                              \
        if (meth == NULL) {                                           \
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,        \
                           "vendor library not loaded");              \
            return OSSL_SDR_NOTSUPPORT;                               \
        }                                                             \
        if (meth->member == NULL) {                                   \
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,        \
                           #member " not found in vendor library");   \
            return OSSL_SDR_NOTSUPPORT;                               \
        }                                                             \
    } while (0)

int SDFE_LoginUsr(void *hSessionHandle, sdfe_login_arg_t *login_arg)
{
    /*
     * 用户登录：byzk0018 等厂商库通过 BYCSM_LoadModule（启动口令）完成模块加载
     * 即视为登录，该接口在 ossl_sdf_lib_init(RUN_ONCE) 阶段已调用一次。
     * 若 use_load_module=0（如三未卡），跳过登录检查直接返回成功。
     * 否则验证 LoadModule 已在 preload 阶段绑定。
     */
    const SDF_METHOD *meth = SDFE_GET_METH();

    if (!ossl_sdf_lib_uses_load_module())
        return OSSL_SDR_OK;

    SDFE_CHECK_METH(meth, LoadModule);

    return OSSL_SDR_OK;
}

int SDFE_DelECCKey(void *hSessionHandle, int area, int index)
{
    /* 转发到厂商库，按索引销毁 SM2 密钥对 */
    const SDF_METHOD *meth = SDFE_GET_METH();

    SDFE_CHECK_METH(meth, DelECCKey);

    return meth->DelECCKey(hSessionHandle, (unsigned int)index);
}

int SDFE_GenECCKey(void *hSessionHandle, int area, int index,
                   unsigned int flags, void *cb)
{
    /*
     * 转发到厂商库，在指定索引生成 SM2 密钥对。
     * 返回的公私钥在此忽略（TSAPI 层调用此接口仅为触发"生成"）。
     */
    const SDF_METHOD *meth = SDFE_GET_METH();
    OSSL_ECCrefPublicKey pub;
    OSSL_ECCrefPrivateKey pri;

    SDFE_CHECK_METH(meth, GenECCKey);

    memset(&pub, 0, sizeof(pub));
    memset(&pri, 0, sizeof(pri));
    return meth->GenECCKey(hSessionHandle, (unsigned int)index, &pub, &pri);
}

int SDFE_ImportECCKey(void *hSessionHandle, sdfe_asym_key_ecc_t *key,
                      void *cb)
{
    /*
     * 转发到厂商库，导入 SM2 密钥对。
     * sdfe_asym_key_ecc_t.pubkey/privkey 是 OSSL_ECCrefPublicKey/PrivateKey 数组，
     * 取首元素地址传入（与厂商库 ECCrefPublicKey/PrivateKey 二进制兼容）。
     */
    const SDF_METHOD *meth = SDFE_GET_METH();

    SDFE_CHECK_METH(meth, ImportECCKey);

    return meth->ImportECCKey(hSessionHandle, (unsigned int)key->index,
                              key->pubkey, key->privkey);
}

int SDFE_ImportRSAKey(void *hSessionHandle, sdfe_asym_key_rsa_t *key,
                      void *cb)
{
    /*
     * 转发到厂商库，导入 RSA 密钥对。
     * 由 key->use_ex 决定调用 InputRSAKey(≤2048) 或 InputRSAKeyEx(3072/4096)。
     */
    const SDF_METHOD *meth = SDFE_GET_METH();

    if (key->use_ex) {
        SDFE_CHECK_METH(meth, InputRSAKeyEx);
        return meth->InputRSAKeyEx(hSessionHandle, (unsigned int)key->index,
                                   key->pub_ex, key->pri_ex);
    }

    SDFE_CHECK_METH(meth, InputRSAKey);
    return meth->InputRSAKey(hSessionHandle, (unsigned int)key->index,
                             key->pub, key->pri);
}

int SDFE_ImportECCKeyWithEvlp(void *hSessionHandle,
                              sdfe_asym_key_ecc_t *key,
                              sdfe_sym_key_evlp_t *evlp, void *cb)
{
    return OSSL_SDR_NOTSUPPORT;
}

int SDFE_ExportECCKeyWithEvlp(void *hSessionHandle,
                              sdfe_asym_key_ecc_t *key,
                              sdfe_sym_key_evlp_t *evlp,
                              void *pubkey)
{
    return OSSL_SDR_NOTSUPPORT;
}

int SDFE_ExportECCPrivKey(void *hSessionHandle, int area, int index,
                          unsigned int flags, void *cb,
                          void *privkey)
{
    return OSSL_SDR_NOTSUPPORT;
}

int SDFE_BitmapAsymKey(void *hSessionHandle, int area, int type,
                        sdfe_bitmap_t *bitmap)
{
    return OSSL_SDR_NOTSUPPORT;
}
