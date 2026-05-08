/*
 * SDFE API Stub 实现
 * 所有 SDFE_* 扩展函数返回不支持错误
 * 仅在 SDF_LIB 编译时使用，实际功能需厂商 SDK
 *
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <stddef.h>
#include <openssl/sdf.h>
#include "../sdf/sdf_local.h"
#include "sdfe_api.h"

int SDFE_LoginUsr(void *hSessionHandle, sdfe_login_arg_t *login_arg)
{
    return OSSL_SDR_NOTSUPPORT;
}

int SDFE_DelECCKey(void *hSessionHandle, int area, int index)
{
    return OSSL_SDR_NOTSUPPORT;
}

int SDFE_GenECCKey(void *hSessionHandle, int area, int index,
                   unsigned int flags, void *cb)
{
    return OSSL_SDR_NOTSUPPORT;
}

int SDFE_ImportECCKey(void *hSessionHandle, sdfe_asym_key_ecc_t *key,
                      void *cb)
{
    return OSSL_SDR_NOTSUPPORT;
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
