/*
 * SDFE API 扩展接口定义 (stub)
 * 提供编译所需的类型定义和函数声明
 * 实际实现由 SDFE_ stub 函数提供（返回不支持错误）
 *
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#ifndef SDFE_API_H
# define SDFE_API_H

# include <stdint.h>
# include <stddef.h>
# include <openssl/sdf.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* 密钥区域类型 */
#define SDFE_ASYM_KEY_AREA_SIGN    0x0001
#define SDFE_ASYM_KEY_AREA_ENC     0x0002

/* 非对称密钥算法类型 */
#define SDFE_ASYM_KEY_TYPE_SM2     0x0001
#define SDFE_ASYM_KEY_TYPE_RSA     0x0002

/* 对称密钥算法类型 */
#define SDFE_SYM_KEY_TYPE_SM4      0x0001

/* 对称密钥信封标志 */
#define SDFE_SYM_KEY_EVLP_F_IMPORT_KEY_INDEX_VALID  0x0001

/* bitmap 最大容量 */
#define SDFE_BITMAP_U64_MAX_CNT  4

/* 密钥位图结构 */
typedef struct sdfe_bitmap_st {
    uint32_t start;
    uint32_t cnt;
    uint64_t bitmap[SDFE_BITMAP_U64_MAX_CNT];
} sdfe_bitmap_t;

/* 兼容原始 SDF API 类型名 */
typedef OSSL_ECCrefPublicKey ECCrefPublicKey;
typedef OSSL_ECCrefPrivateKey ECCrefPrivateKey;

/* 用户登录参数 */
typedef struct sdfe_login_arg_st {
    uint8_t *passwd;
    uint32_t passwd_len;
    uint8_t name[64];
} sdfe_login_arg_t;

/* 非对称 ECC 密钥结构 */
typedef struct sdfe_asym_key_ecc_st {
    int area;
    int index;
    int type;
    unsigned int privkey_bits;
    unsigned int privkey_len;
    unsigned int pubkey_bits;
    unsigned int pubkey_len;
    OSSL_ECCrefPublicKey pubkey[1];  /* 数组形式，使名称退化为指针 */
    OSSL_ECCrefPrivateKey privkey[1];
} sdfe_asym_key_ecc_t;

/*
 * 非对称 RSA 密钥结构
 * use_ex=0: 密钥位数 ≤2048，使用 pub/pri（RSArefPublicKey/PrivateKey）
 * use_ex=1: 密钥位数 3072/4096，使用 pub_ex/pri_ex（RSArefPublicKeyEx/PrivateKeyEx）
 * 由 TSAPI 层根据 EVP_PKEY 的 RSA 位数自动设置。
 */
typedef struct sdfe_asym_key_rsa_st {
    int area;
    int index;
    int type;          /* SDFE_ASYM_KEY_TYPE_RSA */
    int use_ex;        /* 0=普通版(≤2048), 1=Ex版(3072/4096) */
    unsigned int bits;
    OSSL_RSArefPublicKey pub[1];
    OSSL_RSArefPrivateKey pri[1];
    OSSL_RSArefPublicKeyEx pub_ex[1];
    OSSL_RSArefPrivateKeyEx pri_ex[1];
} sdfe_asym_key_rsa_t;

/* 对称密钥信封结构 */
typedef struct sdfe_sym_key_evlp_st {
    uint32_t flags;
    int asym_key_type;
    int sym_key_type;
    unsigned int sym_key_len;
    unsigned int asym_key_index;
    uint32_t data_len;
    uint8_t data[1024];
} sdfe_sym_key_evlp_t;

/* SDFE 扩展 API 函数声明 */
int SDFE_LoginUsr(void *hSessionHandle, sdfe_login_arg_t *login_arg);
int SDFE_DelECCKey(void *hSessionHandle, int area, int index);
int SDFE_DelRSAKey(void *hSessionHandle, int area, int index);
int SDFE_GenECCKey(void *hSessionHandle, int area, int index,
                   unsigned int flags, void *cb);
int SDFE_ImportECCKey(void *hSessionHandle, sdfe_asym_key_ecc_t *key,
                      void *cb);
int SDFE_ImportRSAKey(void *hSessionHandle, sdfe_asym_key_rsa_t *key,
                      void *cb);
int SDFE_ImportECCKeyWithEvlp(void *hSessionHandle,
                              sdfe_asym_key_ecc_t *key,
                              sdfe_sym_key_evlp_t *evlp, void *cb);
int SDFE_ExportECCKeyWithEvlp(void *hSessionHandle,
                              sdfe_asym_key_ecc_t *key,
                              sdfe_sym_key_evlp_t *evlp,
                              void *pubkey);
int SDFE_ExportECCPrivKey(void *hSessionHandle, int area, int index,
                          unsigned int flags, void *cb,
                          void *privkey);
int SDFE_BitmapAsymKey(void *hSessionHandle, int area, int type,
                        sdfe_bitmap_t *bitmap);

#ifdef  __cplusplus
}
#endif

#endif /* SDFE_API_H */
