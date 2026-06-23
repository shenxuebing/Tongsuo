/*
 * SDF Provider - SM3 Digest Module
 *
 * SM3 摘要通过本地软件算法计算（不经过密码卡）。
 */

#ifndef PROV_SDF_DIGEST_H
#define PROV_SDF_DIGEST_H

#include <openssl/core_dispatch.h>

void *sdf_sm3_digest_newctx(void *provctx);
void sdf_sm3_digest_freectx(void *ctx);
void *sdf_sm3_digest_dupctx(void *ctx);
int sdf_sm3_digest_init(void *ctx);
int sdf_sm3_digest_update(void *ctx, const unsigned char *data, size_t datalen);
int sdf_sm3_digest_final(void *ctx, unsigned char *out, size_t *outlen,
                          size_t outsize);
int sdf_sm3_digest(void *provctx, const unsigned char *in, size_t inlen,
                    unsigned char *out, size_t *outlen, size_t outsize);
int sdf_sm3_digest_get_params(OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm3_digest_gettable_params(void *ctx, void *provctx);
int sdf_sm3_digest_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm3_digest_settable_ctx_params(void *ctx, void *provctx);
int sdf_sm3_digest_get_ctx_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm3_digest_gettable_ctx_params(void *ctx, void *provctx);

extern const OSSL_DISPATCH sdf_sm3_digest_dispatch[];
extern const OSSL_ALGORITHM sdf_digest_sm3[];

#endif /* PROV_SDF_DIGEST_H */
