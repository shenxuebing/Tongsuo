/*
 * SDF Provider for Tongsuo - SM2 Asymmetric Cipher Module
 *
 * 基于 GM/T 0018 SDF 接口的 SM2 加解密实现
 * - 加密使用公钥 (可在本地或通过 SDF_InternalEncrypt_ECC)
 * - 解密使用私钥通过 SDF_InternalDecrypt_ECC 在密码卡上完成
 * - 集成私钥访问控制
 */

#ifndef PROV_SDF_ENC_H
#define PROV_SDF_ENC_H

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include "prov_sdf.h"

/*============================================================================
 * SM2 加解密上下文
 *===========================================================================*/
typedef struct sdf_sm2_enc_ctx_st {
    SDF_PROV_CTX *provctx;
    SDF_PROV_KEY *key;
    EVP_MD *md;                  /* 摘要算法 (SM3) */
    int encdata_format;          /* 加密输出格式: 0=ASN1, 1=C1C3C2 */
    int access_granted;
    unsigned char *password;
    int password_len;
} SDF_SM2_ENC_CTX;

/*============================================================================
 * 函数声明
 *============================================================================*/

void *sdf_sm2_enc_newctx(void *provctx);
void sdf_sm2_enc_freectx(void *ctx);
void *sdf_sm2_enc_dupctx(void *ctx);

int sdf_sm2_enc_encrypt_init(void *ctx, void *key, const OSSL_PARAM params[]);
int sdf_sm2_enc_encrypt(void *ctx, unsigned char *out, size_t *outlen,
                         size_t outsize, const unsigned char *in, size_t inlen);

int sdf_sm2_enc_decrypt_init(void *ctx, void *key, const OSSL_PARAM params[]);
int sdf_sm2_enc_decrypt(void *ctx, unsigned char *out, size_t *outlen,
                         size_t outsize, const unsigned char *in, size_t inlen);

int sdf_sm2_enc_get_ctx_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm2_enc_gettable_ctx_params(void *ctx, void *provctx);
int sdf_sm2_enc_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm2_enc_settable_ctx_params(void *ctx, void *provctx);

/* 分发表和算法定义 */
extern const OSSL_DISPATCH sdf_sm2_enc_dispatch[];
extern const OSSL_ALGORITHM sdf_asym_cipher_sm2[];

#endif /* PROV_SDF_ENC_H */
