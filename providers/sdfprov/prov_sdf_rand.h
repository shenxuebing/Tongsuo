/*
 * SDF Provider for Tongsuo - Random Number Module
 *
 * 随机数通过 SDF_GenerateRandom 从密码卡获取。
 */

#ifndef PROV_SDF_RAND_H
#define PROV_SDF_RAND_H

#include <openssl/core_dispatch.h>

void *sdf_rand_newctx(void *provctx, const OSSL_PARAM params[]);
void sdf_rand_freectx(void *ctx);
int sdf_rand_instantiate(void *vctx, int prediction_resistance,
                          const unsigned char *personalization_string,
                          size_t personalization_string_len);
int sdf_rand_uninstantiate(void *vctx);
int sdf_rand_generate(void *vctx, unsigned char *out, size_t outlen,
                       unsigned int strength, int prediction_resistance,
                       const unsigned char *additional_input,
                       size_t additional_input_len);
int sdf_rand_reseed(void *vctx, int prediction_resistance,
                     const unsigned char *entropy, size_t entropy_len,
                     const unsigned char *additional_input,
                     size_t additional_input_len);
int sdf_rand_enable_locking(void *vctx);
int sdf_rand_lock(void *vctx);
void sdf_rand_unlock(void *vctx);
int sdf_rand_get_ctx_params(void *vctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_rand_gettable_ctx_params(void *vctx, void *provctx);
int sdf_rand_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_rand_settable_ctx_params(void *vctx, void *provctx);
int sdf_rand_get_params(OSSL_PARAM *params);
const OSSL_PARAM *sdf_rand_gettable_params(void *provctx);
int sdf_rand_verify_zeroization(void *vctx);
int sdf_rand_nonce(void *vctx, unsigned char *out, size_t outlen);

extern const OSSL_DISPATCH sdf_rand_dispatch[];
extern const OSSL_ALGORITHM sdf_rand[];

#endif /* PROV_SDF_RAND_H */
