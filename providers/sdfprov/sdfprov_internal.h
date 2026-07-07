/*
 * SDF Provider internal types
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#ifndef OSSL_PROVIDERS_SDFPROV_INTERNAL_H
# define OSSL_PROVIDERS_SDFPROV_INTERNAL_H

# include <openssl/ec.h>
# include <openssl/rsa.h>
# include <openssl/sdf.h>
# include "crypto/sdf/sdf_local.h"

/* 算法类型标识 */
#define SDF_ALGO_SM2    0
#define SDF_ALGO_RSA    1

/* SDF 密钥数据结构 - 用于 KEYMGMT/SIGNATURE/ASYM_CIPHER/KEYEXCH */
typedef struct sdf_sm2_key_st {
    OSSL_LIB_CTX *libctx;
    int rsa_bits;                /* RSA 密钥位数缓存（如 2048），key->rsa 为 NULL 时备用 */
    int rsa_size;                /* RSA 签名块字节数缓存（如 256），key->rsa 为 NULL 时备用 */
    EC_KEY* ec_key;              /* SM2 软/硬件公钥壳 */
    RSA* rsa;                    /* RSA 软/硬件公钥壳 */
    int is_hardware_key;         /* 1=硬件密钥, 0=软件密钥 */
    unsigned int key_index;      /* SDF 设备密钥索引 */
    int key_type;                /* 0=签名密钥, 1=加密密钥 */
    int algo;                    /* SDF_ALGO_SM2 / SDF_ALGO_RSA */
    void* hSession;              /* SDF 会话句柄 */
    int external_session;        /* 1=URI 传入的外部 session */
    OSSL_ECCrefPublicKey cached_pubkey;  /* SM2 协商场景缓存公钥 */

    /* 私钥访问控制码 (GetPrivateKeyAccessRight), 通过 URI 传入 */
    char* key_password;

    /* ECDHE 临时密钥协商相关字段 */
    void* agreement_handle;      /* SDF 密钥协商句柄 (SDF_GenerateAgreementDataWithECCEx 返回) */
    int is_initiator;            /* 1=发起方(服务端), 0=响应方(客户端) */
    int has_agreement;           /* 1=已通过SDF硬件生成协商数据 */
} SDF_SM2_KEY;

#endif
