/*
 * SDF Provider internal types
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#ifndef OSSL_PROVIDERS_SDFPROV_INTERNAL_H
# define OSSL_PROVIDERS_SDFPROV_INTERNAL_H

# include <openssl/ec.h>
# include <openssl/sdf.h>
# include "crypto/sdf/sdf_local.h"

/* SDF SM2 key data structure - used across KEYMGMT/SIGNATURE/ASYM_CIPHER/KEYEXCH */
typedef struct sdf_sm2_key_st {
    OSSL_LIB_CTX *libctx;
    EC_KEY *ec_key;
    int is_hardware_key;         /* 1=硬件密钥, 0=软件密钥 */
    unsigned int key_index;      /* SDF 设备密钥索引 */
    int key_type;                /* 0=签名密钥, 1=加密密钥 */
    void *hSession;              /* SDF 会话句柄 */
    OSSL_ECCrefPublicKey cached_pubkey;
} SDF_SM2_KEY;

#endif
