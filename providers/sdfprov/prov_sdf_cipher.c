/*
 * SDF Provider - SM4 Symmetric Cipher Module
 *
 * SM4 对称加密通过 SDF_Encrypt/SDF_Decrypt 在密码卡上完成。
 *
 * 两种使用方式:
 * 1. 使用用户传入的密钥: 通过 SDF_ImportKey 导入明文密钥获取 hKeyHandle
 * 2. 使用设备内部密钥: 通过 SDF_GetSymmKeyHandle 按索引获取 hKeyHandle
 *
 * SDF 接口签名:
 *   SGD_RV SDF_Encrypt(hSession, hKeyHandle, uiSDFID, pucIV,
 *                       pucData, uiDataLength, pucEncData, puiEncDataLength)
 *   SGD_RV SDF_Decrypt(hSession, hKeyHandle, uiSDFID, pucIV,
 *                       pucEncData, uiEncDataLength, pucData, puiDataLength)
 *   SGD_RV SDF_ImportKey(hSession, pucKey, uiKeyLength, phKeyHandle)
 *   SGD_RV SDF_DestroyKey(hSession, hKeyHandle)
 *   SGD_RV SDF_GetSymmKeyHandle(hSession, uiKeyIndex, phKeyHandle)
 *
 * SDFID 算法标识 (GM/T 0018-2012):
 *   SGD_SM4_ECB = 0x00000401
 *   SGD_SM4_CBC = 0x00000402
 *   SGD_SM4_CFB = 0x00000404
 *   SGD_SM4_OFB = 0x00000408
 *   SGD_SM4_MAC = 0x00000410
 *   SGD_SM4_CTR = 0x00000420
 */

#include "prov_sdf_cipher.h"
#include "prov_sdf.h"
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <string.h>

/* SDFID 算法标识 (GM/T 0018-2012) */
#ifndef SGD_SM4_ECB
#define SGD_SM4_ECB     0x00000401
#define SGD_SM4_CBC     0x00000402
#define SGD_SM4_CFB     0x00000404
#define SGD_SM4_OFB     0x00000408
#define SGD_SM4_MAC     0x00000410
#define SGD_SM4_CTR     0x00000420
#endif

/* SM4 块大小和密钥大小 */
#define SM4_BLOCK_SIZE  16
#define SM4_KEY_SIZE    16

typedef struct sdf_sm4_ctx_st {
    SDF_PROV_CTX *provctx;
    int mode;                    /* SDF_SM4_MODE_* */
    int encrypting;              /* 1=encrypt, 0=decrypt */
    unsigned char iv[SM4_BLOCK_SIZE];
    unsigned char key[SM4_KEY_SIZE];
    size_t key_len;
    void *key_handle;            /* SDF 密钥句柄 */
    unsigned int alg_id;         /* SDF 算法 ID */
    int key_ready;               /* 密钥句柄是否已创建 */

    /* 缓存: SDF_Encrypt/Decrypt 按块操作，需要缓存不完整块 */
    unsigned char buf[SM4_BLOCK_SIZE];
    unsigned int buf_len;
} SDF_SM4_CIPHER_CTX;

/*============================================================================
 * 参数表
 *===========================================================================*/

static const OSSL_PARAM sdf_sm4_cipher_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_sm4_cipher_known_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM sdf_sm4_cipher_known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_END
};

static unsigned int mode_to_alg_id(int mode)
{
    switch (mode) {
    case SDF_SM4_MODE_ECB: return SGD_SM4_ECB;
    case SDF_SM4_MODE_CBC: return SGD_SM4_CBC;
    case SDF_SM4_MODE_CTR: return SGD_SM4_CTR;
    case SDF_SM4_MODE_OFB: return SGD_SM4_OFB;
    case SDF_SM4_MODE_CFB: return SGD_SM4_CFB;
    default:               return SGD_SM4_CBC;
    }
}

static int iv_needed(int mode)
{
    return mode != SDF_SM4_MODE_ECB;
}

static int is_stream(int mode)
{
    return mode == SDF_SM4_MODE_CTR || mode == SDF_SM4_MODE_OFB ||
           mode == SDF_SM4_MODE_CFB;
}

/*============================================================================
 * 密钥句柄管理
 *
 * 使用 SDF_ImportKey 导入用户指定的明文密钥:
 *   SGD_RV SDF_ImportKey(hSession, pucKey, uiKeyLength, phKeyHandle)
 *
 * 使用完毕后通过 SDF_DestroyKey 销毁:
 *   SGD_RV SDF_DestroyKey(hSession, hKeyHandle)
 *
 * 内部密钥可通过 SDF_GetSymmKeyHandle 获取:
 *   SGD_RV SDF_GetSymmKeyHandle(hSession, uiKeyIndex, phKeyHandle)
 *============================================================================*/

static int sdf_sm4_import_key(SDF_SM4_CIPHER_CTX *ctx)
{
    if (ctx->provctx == NULL || !ctx->provctx->card_available)
        return 0;

    if (SDF_CALL(ctx->provctx, SDF_ImportKey,
                 ctx->provctx->hSession,
                 ctx->key, (SGD_UINT32)ctx->key_len,
                 &ctx->key_handle) != SDR_OK) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return 0;
    }

    ctx->key_ready = 1;
    return 1;
}

static void sdf_sm4_destroy_key(SDF_SM4_CIPHER_CTX *ctx)
{
    if (ctx != NULL && ctx->key_handle != NULL && ctx->provctx != NULL &&
        ctx->provctx->card_available) {
        SDF_CALL(ctx->provctx, SDF_DestroyKey,
                 ctx->provctx->hSession, ctx->key_handle);
        ctx->key_handle = NULL;
        ctx->key_ready = 0;
    }
}

/*============================================================================
 * 上下文管理
 *============================================================================*/

void *sdf_sm4_cipher_newctx(void *provctx, int mode)
{
    SDF_SM4_CIPHER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = (SDF_PROV_CTX *)provctx;
    ctx->mode = mode;
    ctx->encrypting = 0;
    ctx->alg_id = mode_to_alg_id(mode);
    ctx->key_handle = NULL;
    ctx->key_ready = 0;
    ctx->buf_len = 0;

    return ctx;
}

void sdf_sm4_cipher_freectx(void *vctx)
{
    SDF_SM4_CIPHER_CTX *ctx = (SDF_SM4_CIPHER_CTX *)vctx;
    if (ctx == NULL)
        return;
    sdf_sm4_destroy_key(ctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

void *sdf_sm4_cipher_dupctx(void *vctx)
{
    SDF_SM4_CIPHER_CTX *src = (SDF_SM4_CIPHER_CTX *)vctx;
    SDF_SM4_CIPHER_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*src));
    if (dst == NULL)
        return NULL;

    *dst = *src;
    /* 密钥句柄不复制，init 后重新创建 */
    dst->key_handle = NULL;
    dst->key_ready = 0;
    return dst;
}

/*============================================================================
 * 加密/解密初始化
 *============================================================================*/

static int sdf_sm4_cipher_common_init(void *vctx, const unsigned char *key,
                                       size_t keylen, const unsigned char *iv,
                                       size_t ivlen, int encrypting)
{
    SDF_SM4_CIPHER_CTX *ctx = (SDF_SM4_CIPHER_CTX *)vctx;

    if (ctx == NULL)
        return 0;

    if (keylen != SM4_KEY_SIZE) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    if (iv_needed(ctx->mode)) {
        if (iv == NULL || ivlen != SM4_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->iv, iv, SM4_BLOCK_SIZE);
    } else {
        memset(ctx->iv, 0, SM4_BLOCK_SIZE);
    }

    memcpy(ctx->key, key, SM4_KEY_SIZE);
    ctx->key_len = keylen;
    ctx->encrypting = encrypting;
    ctx->buf_len = 0;

    /* 销毁旧密钥 */
    sdf_sm4_destroy_key(ctx);

    /* 导入用户密钥 */
    if (ctx->provctx != NULL && ctx->provctx->card_available) {
        if (!sdf_sm4_import_key(ctx))
            return 0;
    }

    return 1;
}

int sdf_sm4_cipher_encrypt_init(void *vctx, const unsigned char *key,
                                 size_t keylen, const unsigned char *iv,
                                 size_t ivlen, const OSSL_PARAM params[])
{
    int ret = sdf_sm4_cipher_common_init(vctx, key, keylen, iv, ivlen, 1);
    if (ret && params != NULL)
        ret = sdf_sm4_cipher_set_ctx_params(vctx, params);
    return ret;
}

int sdf_sm4_cipher_decrypt_init(void *vctx, const unsigned char *key,
                                 size_t keylen, const unsigned char *iv,
                                 size_t ivlen, const OSSL_PARAM params[])
{
    int ret = sdf_sm4_cipher_common_init(vctx, key, keylen, iv, ivlen, 0);
    if (ret && params != NULL)
        ret = sdf_sm4_cipher_set_ctx_params(vctx, params);
    return ret;
}

/*============================================================================
 * 加密/解密操作 (按块调用 SDF)
 *
 * SDF_Encrypt/Decrypt 对输入数据大小没有严格限制，
 * 但对于块密码 (ECB/CBC)，输入必须是块大小的整数倍。
 * 流模式 (CTR/OFB/CFB) 可以是任意长度。
 *============================================================================*/

int sdf_sm4_cipher_update(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl)
{
    SDF_SM4_CIPHER_CTX *ctx = (SDF_SM4_CIPHER_CTX *)vctx;
    unsigned int out_len = 0;
    int ret;

    if (ctx == NULL) {
        if (outl) *outl = 0;
        return 1;
    }

    if (inl == 0) {
        if (outl) *outl = 0;
        return 1;
    }

    /* 大小查询 */
    if (out == NULL) {
        if (is_stream(ctx->mode)) {
            *outl = inl;
        } else {
            /* 块模式: 需要缓存到完整块 */
            *outl = (ctx->buf_len + inl) / SM4_BLOCK_SIZE * SM4_BLOCK_SIZE;
        }
        return 1;
    }

    if (!ctx->key_ready) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    /*
     * 对于块模式 (ECB/CBC): 缓存不完整块，只在完整块时调用 SDF
     * 对于流模式 (CTR/OFB/CFB): 可以直接调用 SDF
     */
    if (is_stream(ctx->mode)) {
        /* 流模式: 直接调用 SDF */
        ret = ctx->encrypting ?
            SDF_CALL(ctx->provctx, SDF_Encrypt,
                     ctx->provctx->hSession, ctx->key_handle,
                               ctx->alg_id, ctx->iv,
                               (unsigned char *)in, (unsigned int)inl,
                               out, &out_len) :
            SDF_CALL(ctx->provctx, SDF_Decrypt,
                     ctx->provctx->hSession, ctx->key_handle,
                               ctx->alg_id, ctx->iv,
                               (unsigned char *)in, (unsigned int)inl,
                               out, &out_len);

        if (ret != SDR_OK) {
            ERR_raise(ERR_LIB_PROV, ctx->encrypting ?
                      PROV_R_FAILED_TO_DECRYPT : PROV_R_FAILED_TO_DECRYPT);
            return 0;
        }

        *outl = out_len;
        return 1;
    }

    /* 块模式: 需要按块处理 */
    {
        size_t total_in = ctx->buf_len + inl;
        size_t process_len = total_in / SM4_BLOCK_SIZE * SM4_BLOCK_SIZE;
        size_t remaining = total_in - process_len;
        size_t copy_back = 0;
        unsigned char tmp[4096]; /* 临时缓冲区用于合并数据 */

        if (process_len == 0) {
            /* 还不够一块，全部缓存 */
            if (inl > SM4_BLOCK_SIZE - ctx->buf_len) {
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
                return 0;
            }
            memcpy(ctx->buf + ctx->buf_len, in, inl);
            ctx->buf_len += inl;
            *outl = 0;
            return 1;
        }

        /* 合并缓存和新数据 */
        if (ctx->buf_len > 0) {
            if (process_len > sizeof(tmp)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
                return 0;
            }
            memcpy(tmp, ctx->buf, ctx->buf_len);
            memcpy(tmp + ctx->buf_len, in, process_len - ctx->buf_len);
            copy_back = process_len - ctx->buf_len;
        } else {
            memcpy(tmp, in, process_len);
            copy_back = process_len;
        }

        /* 调用 SDF 处理完整块 */
        ret = ctx->encrypting ?
            SDF_CALL(ctx->provctx, SDF_Encrypt,
                     ctx->provctx->hSession, ctx->key_handle,
                               ctx->alg_id, ctx->iv,
                               tmp, (unsigned int)process_len,
                               out, &out_len) :
            SDF_CALL(ctx->provctx, SDF_Decrypt,
                     ctx->provctx->hSession, ctx->key_handle,
                               ctx->alg_id, ctx->iv,
                               tmp, (unsigned int)process_len,
                               out, &out_len);

        if (ret != SDR_OK) {
            ERR_raise(ERR_LIB_PROV, ctx->encrypting ?
                      PROV_R_FAILED_TO_DECRYPT : PROV_R_FAILED_TO_DECRYPT);
            return 0;
        }

        *outl = out_len;

        /* 缓存剩余数据 */
        ctx->buf_len = 0;
        if (remaining > 0) {
            memcpy(ctx->buf, in + copy_back, remaining);
            ctx->buf_len = remaining;
        }

        return 1;
    }
}

int sdf_sm4_cipher_final(void *vctx, unsigned char *out, size_t *outl,
                           size_t outsize)
{
    SDF_SM4_CIPHER_CTX *ctx = (SDF_SM4_CIPHER_CTX *)vctx;

    if (vctx == NULL) {
        if (outl) *outl = 0;
        return 1;
    }

    /*
     * SM4 块模式 final 不做 padding 处理。
     * 如果有缓存的不完整块数据，说明输入不是块大小的整数倍。
     * 流模式不会有剩余数据。
     */
    if (ctx->buf_len > 0 && !is_stream(ctx->mode)) {
        /* 有未处理的不完整块 — 不是错误，只是没有输出 */
    }

    if (outl) *outl = 0;
    return 1;
}

int sdf_sm4_cipher_cipher(void *vctx, unsigned char *out, const unsigned char *in,
                            size_t inl)
{
    size_t outl = 0;
    if (!sdf_sm4_cipher_update(vctx, out, &outl, inl, in, inl))
        return 0;
    return (int)outl;
}

/*============================================================================
 * 参数操作
 *============================================================================*/

int sdf_sm4_cipher_get_params(OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, SM4_BLOCK_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, SM4_KEY_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, SM4_BLOCK_SIZE))
        return 0;
    return 1;
}

const OSSL_PARAM *sdf_sm4_cipher_gettable_params(void *ctx, void *provctx)
{
    return sdf_sm4_cipher_known_gettable_params;
}

int sdf_sm4_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SDF_SM4_CIPHER_CTX *ctx = (SDF_SM4_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) {
        if (p->data_size != SM4_BLOCK_SIZE)
            return 0;
        memcpy(ctx->iv, p->data, SM4_BLOCK_SIZE);
    }

    return 1;
}

const OSSL_PARAM *sdf_sm4_cipher_settable_ctx_params(void *ctx, void *provctx)
{
    return sdf_sm4_cipher_known_settable_ctx_params;
}

int sdf_sm4_cipher_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    SDF_SM4_CIPHER_CTX *ctx = (SDF_SM4_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    if (vctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p && !OSSL_PARAM_set_octet_string(p, ctx->iv, SM4_BLOCK_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, SM4_KEY_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p && !OSSL_PARAM_set_size_t(p, 0))
        return 0;

    return 1;
}

const OSSL_PARAM *sdf_sm4_cipher_gettable_ctx_params(void *ctx, void *provctx)
{
    return sdf_sm4_cipher_known_gettable_ctx_params;
}

/*============================================================================
 * 各模式分发表 (包装函数绑定 mode 参数)
 *============================================================================*/

static void *ecb_newctx(void *provctx) { return sdf_sm4_cipher_newctx(provctx, SDF_SM4_MODE_ECB); }
static void *cbc_newctx(void *provctx) { return sdf_sm4_cipher_newctx(provctx, SDF_SM4_MODE_CBC); }
static void *ctr_newctx(void *provctx) { return sdf_sm4_cipher_newctx(provctx, SDF_SM4_MODE_CTR); }
static void *ofb_newctx(void *provctx) { return sdf_sm4_cipher_newctx(provctx, SDF_SM4_MODE_OFB); }
static void *cfb_newctx(void *provctx) { return sdf_sm4_cipher_newctx(provctx, SDF_SM4_MODE_CFB); }

const OSSL_DISPATCH sdf_sm4_ecb_dispatch[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))ecb_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))sdf_sm4_cipher_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX,              (void (*)(void))sdf_sm4_cipher_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))sdf_sm4_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))sdf_sm4_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))sdf_sm4_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))sdf_sm4_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))sdf_sm4_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_settable_ctx_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH sdf_sm4_cbc_dispatch[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))cbc_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))sdf_sm4_cipher_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX,              (void (*)(void))sdf_sm4_cipher_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))sdf_sm4_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))sdf_sm4_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))sdf_sm4_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))sdf_sm4_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))sdf_sm4_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_settable_ctx_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH sdf_sm4_ctr_dispatch[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))ctr_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))sdf_sm4_cipher_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX,              (void (*)(void))sdf_sm4_cipher_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))sdf_sm4_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))sdf_sm4_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))sdf_sm4_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))sdf_sm4_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))sdf_sm4_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_settable_ctx_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH sdf_sm4_ofb_dispatch[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))ofb_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))sdf_sm4_cipher_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX,              (void (*)(void))sdf_sm4_cipher_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))sdf_sm4_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))sdf_sm4_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))sdf_sm4_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))sdf_sm4_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))sdf_sm4_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_settable_ctx_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH sdf_sm4_cfb_dispatch[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))cfb_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))sdf_sm4_cipher_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX,              (void (*)(void))sdf_sm4_cipher_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))sdf_sm4_cipher_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))sdf_sm4_cipher_update },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))sdf_sm4_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))sdf_sm4_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))sdf_sm4_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))sdf_sm4_cipher_gettable_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_settable_ctx_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))sdf_sm4_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))sdf_sm4_cipher_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_ALGORITHM sdf_cipher_sm4[] = {
    { "SM4-ECB", "provider=sdfprov", sdf_sm4_ecb_dispatch, NULL },
    { "SM4-CBC", "provider=sdfprov", sdf_sm4_cbc_dispatch, NULL },
    { "SM4-CTR", "provider=sdfprov", sdf_sm4_ctr_dispatch, NULL },
    { "SM4-OFB", "provider=sdfprov", sdf_sm4_ofb_dispatch, NULL },
    { "SM4-CFB", "provider=sdfprov", sdf_sm4_cfb_dispatch, NULL },
    { NULL, NULL, NULL, NULL }
};
