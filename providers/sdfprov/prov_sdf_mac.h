/*
 * SDF Provider for Tongsuo - MAC Module
 *
 * 支持 CMAC-SM4 和 HMAC-SM3。
 * CMAC-SM4 通过 SDF_CalculateMAC 在密码卡上完成。
 * HMAC-SM3 在本地计算。
 */

#ifndef PROV_SDF_MAC_H
#define PROV_SDF_MAC_H

#include <openssl/core_dispatch.h>

/* CMAC-SM4 (卡上) */
void *sdf_cmac_sm4_newctx(void *provctx);
void sdf_cmac_sm4_freectx(void *ctx);
void *sdf_cmac_sm4_dupctx(void *ctx);
int sdf_cmac_sm4_init(void *ctx, const unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[]);
int sdf_cmac_sm4_update(void *ctx, const unsigned char *data, size_t datalen);
int sdf_cmac_sm4_final(void *ctx, unsigned char *out, size_t *outlen,
                         size_t outsize);
int sdf_cmac_sm4_get_params(OSSL_PARAM *params);
const OSSL_PARAM *sdf_cmac_sm4_gettable_params(void *ctx, void *provctx);
int sdf_cmac_sm4_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_cmac_sm4_settable_ctx_params(void *ctx, void *provctx);
int sdf_cmac_sm4_get_ctx_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_cmac_sm4_gettable_ctx_params(void *ctx, void *provctx);

extern const OSSL_DISPATCH sdf_cmac_sm4_dispatch[];
extern const OSSL_ALGORITHM sdf_mac_cmac_sm4[];

/* HMAC-SM3 (本地) */
void *sdf_hmac_sm3_newctx(void *provctx);
void sdf_hmac_sm3_freectx(void *ctx);
void *sdf_hmac_sm3_dupctx(void *ctx);
int sdf_hmac_sm3_init(void *ctx, const unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[]);
int sdf_hmac_sm3_update(void *ctx, const unsigned char *data, size_t datalen);
int sdf_hmac_sm3_final(void *ctx, unsigned char *out, size_t *outlen,
                         size_t outsize);
int sdf_hmac_sm3_get_params(OSSL_PARAM *params);
const OSSL_PARAM *sdf_hmac_sm3_gettable_params(void *ctx, void *provctx);
int sdf_hmac_sm3_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_hmac_sm3_settable_ctx_params(void *ctx, void *provctx);
int sdf_hmac_sm3_get_ctx_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_hmac_sm3_gettable_ctx_params(void *ctx, void *provctx);

extern const OSSL_DISPATCH sdf_hmac_sm3_dispatch[];
extern const OSSL_ALGORITHM sdf_mac_hmac_sm3[];

#endif /* PROV_SDF_MAC_H */
