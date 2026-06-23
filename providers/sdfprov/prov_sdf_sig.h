/*
 * SDF Provider for Tongsuo - SM2 Signature Module
 *
 * 基于 GM/T 0018 SDF 接口的 SM2 签名实现
 * - 签名操作通过 SDF_InternalSign_ECC 在密码卡上完成
 * - 验签操作可以使用公钥在本地完成
 * - 集成私钥访问控制 (SDF_GetPrivateKeyAccessRight / ReleasePrivateKeyAccessRight)
 */

#ifndef PROV_SDF_SIG_H
#define PROV_SDF_SIG_H

#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include "prov_sdf.h"

/*============================================================================
 * SM2 签名上下文
 *===========================================================================*/
typedef struct sdf_sm2_sig_ctx_st {
    SDF_PROV_CTX *provctx;       /* Provider 上下文 */

    /* 密钥信息 (来自 KEYMGMT) */
    SDF_PROV_KEY *key;           /* SDF 密钥对象 */

    /* 摘要相关 */
    char mdname[64];             /* 摘要算法名 (SM3) */
    size_t mdsize;               /* 摘要长度 */
    EVP_MD *md;                  /* 摘要算法 */
    EVP_MD_CTX *mdctx;           /* 摘要上下文 */

    /* SM2 ID (默认 "1234567812345678") */
    unsigned char *id;
    size_t id_len;

    /* Z 值计算标志 */
    unsigned int flag_compute_z_digest : 1;

    /* 私钥访问控制 */
    int access_granted;           /* 是否已获取私钥访问权限 */
    unsigned char *password;      /* 访问密码 */
    int password_len;

    /* Algorithm Identifier */
    unsigned char aid_buf[128];
    unsigned char *aid;
    size_t aid_len;
} SDF_SM2_SIG_CTX;

/*============================================================================
 * 函数声明
 *===========================================================================*/

/* 签名上下文管理 */
void *sdf_sm2_sig_newctx(void *provctx, const char *propq);
void sdf_sm2_sig_freectx(void *ctx);
void *sdf_sm2_sig_dupctx(void *ctx);

/* 签名操作 */
int sdf_sm2_sig_sign_init(void *ctx, void *key, const OSSL_PARAM params[]);
int sdf_sm2_sig_sign(void *ctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen);

/* 验签操作 */
int sdf_sm2_sig_verify_init(void *ctx, void *key, const OSSL_PARAM params[]);
int sdf_sm2_sig_verify(void *ctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen);

/* 摘要签名/验签 */
int sdf_sm2_sig_digest_sign_init(void *ctx, const char *mdname,
                                  void *key, const OSSL_PARAM params[]);
int sdf_sm2_sig_digest_sign_update(void *ctx, const unsigned char *data,
                                    size_t datalen);
int sdf_sm2_sig_digest_sign_final(void *ctx, unsigned char *sig,
                                   size_t *siglen, size_t sigsize);
int sdf_sm2_sig_digest_verify_init(void *ctx, const char *mdname,
                                    void *key, const OSSL_PARAM params[]);
int sdf_sm2_sig_digest_verify_update(void *ctx, const unsigned char *data,
                                      size_t datalen);
int sdf_sm2_sig_digest_verify_final(void *ctx, const unsigned char *sig,
                                     size_t siglen);

/* 上下文参数 */
int sdf_sm2_sig_get_ctx_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm2_sig_gettable_ctx_params(void *ctx, void *provctx);
int sdf_sm2_sig_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *sdf_sm2_sig_settable_ctx_params(void *ctx, void *provctx);
int sdf_sm2_sig_get_ctx_md_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm2_sig_gettable_ctx_md_params(void *ctx, void *provctx);
int sdf_sm2_sig_set_ctx_md_params(void *ctx, const OSSL_PARAM *params);
const OSSL_PARAM *sdf_sm2_sig_settable_ctx_md_params(void *ctx, void *provctx);

/* 分发表 */
extern const OSSL_DISPATCH sdf_sm2_sig_dispatch[];

/* 算法定义 (供 prov_sdf.c query 使用) */
extern const OSSL_ALGORITHM sdf_signature_sm2[];

/* 内部辅助函数 */
int sdf_sm2_compute_z_digest(SDF_SM2_SIG_CTX *ctx);
int sdf_sm2_acquire_private_key(SDF_SM2_SIG_CTX *ctx);
void sdf_sm2_release_private_key(SDF_SM2_SIG_CTX *ctx);

#endif /* PROV_SDF_SIG_H */
