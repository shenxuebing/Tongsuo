/*
 * SDF Provider for Tongsuo - SM4 Symmetric Cipher Module
 *
 * SM4 对称加密通过 SDF_Encrypt/SDF_Decrypt 在密码卡上完成。
 * 支持的模式: ECB, CBC, CTR, OFB, CFB。
 * 密钥通过 SDF_GenerateKey 在卡上创建。
 */

#ifndef PROV_SDF_CIPHER_H
#define PROV_SDF_CIPHER_H

#include <openssl/core_dispatch.h>

/* SM4 模式 */
#define SDF_SM4_MODE_ECB    0
#define SDF_SM4_MODE_CBC    1
#define SDF_SM4_MODE_CTR    2
#define SDF_SM4_MODE_OFB    3
#define SDF_SM4_MODE_CFB    4

void *sdf_sm4_cipher_newctx(void *provctx, int mode);
void sdf_sm4_cipher_freectx(void *ctx);
void *sdf_sm4_cipher_dupctx(void *ctx);
int sdf_sm4_cipher_encrypt_init(void *ctx, const unsigned char *key,
                                 size_t keylen, const unsigned char *iv,
                                 size_t ivlen, const OSSL_PARAM params[]);
int sdf_sm4_cipher_decrypt_init(void *ctx, const unsigned char *key,
                                 size_t keylen, const unsigned char *iv,
                                 size_t ivlen, const OSSL_PARAM params[]);
int sdf_sm4_cipher_update(void *ctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl);
int sdf_sm4_cipher_final(void *ctx, unsigned char *out, size_t *outl,
                           size_t outsize);
int sdf_sm4_cipher_cipher(void *ctx, unsigned char *out, const unsigned char *in,
                            size_t inl);
int sdf_sm4_cipher_get_params(OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm4_cipher_gettable_params(void *ctx, void *provctx);
int sdf_sm4_cipher_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm4_cipher_settable_ctx_params(void *ctx, void *provctx);
int sdf_sm4_cipher_get_ctx_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm4_cipher_gettable_ctx_params(void *ctx, void *provctx);

/* 各模式的分发表 */
extern const OSSL_DISPATCH sdf_sm4_ecb_dispatch[];
extern const OSSL_DISPATCH sdf_sm4_cbc_dispatch[];
extern const OSSL_DISPATCH sdf_sm4_ctr_dispatch[];
extern const OSSL_DISPATCH sdf_sm4_ofb_dispatch[];
extern const OSSL_DISPATCH sdf_sm4_cfb_dispatch[];

/* 算法定义 */
extern const OSSL_ALGORITHM sdf_cipher_sm4[];

#endif /* PROV_SDF_CIPHER_H */
