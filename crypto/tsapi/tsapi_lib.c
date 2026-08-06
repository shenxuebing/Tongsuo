/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"
#include <string.h>
#include <openssl/tsapi.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sdf.h>
#include <openssl/sgd.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/proverr.h>
#include "internal/e_os.h"
#include "crypto/rand.h"
#include "crypto/sm2.h"
#include "../sdf/sdf_local.h"
#ifdef SDF_LIB
# include "sdfe_api.h"
#endif

static const char *tsapi_key_area_name(int sign)
{
    return sign ? "sign" : "enc";
}

static void tsapi_raise_user_too_long(const char *op, const char *user)
{
    ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                   "%s: user name too long: user=%s", op,
                   user != NULL ? user : "(null)");
}

static void tsapi_raise_sdf_error(const char *op, const char *api, int ret,
                                  int index, int sign, const char *user)
{
    ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                   "%s: %s failed: ret=0x%08x index=%d type=%s user=%s",
                   op, api, ret, index, tsapi_key_area_name(sign),
                   user != NULL ? user : "(null)");
}

unsigned char *TSAPI_GetEntropy(int entropy, size_t *outlen)
{
    unsigned char *out = NULL;
    size_t len;

    len = ossl_rand_get_entropy(NULL, &out, entropy, entropy, entropy * 4);
    if (len == 0) {
        *outlen = 0;
        return NULL;
    }

    *outlen = len;
    return out;
}

void TSAPI_FreeEntropy(unsigned char *ent, size_t len)
{
    ossl_rand_cleanup_entropy(NULL, ent, len);
}

unsigned char *TSAPI_RandBytes(size_t len)
{
    unsigned char *buf = OPENSSL_malloc(len);

    if (buf == NULL)
        return NULL;

    if (RAND_bytes(buf, (int)len) <= 0) {
        OPENSSL_free(buf);
        return NULL;
    }

    return buf;
}

char *TSAPI_Version(void)
{
    int ret;
    int buflen = 1 + strlen(OpenSSL_version(TONGSUO_VERSION)) + 1
#ifdef SMTC_MODULE
                 + strlen(OpenSSL_version(TONGSUO_SMTC_INFO)) + 1
#endif
                 ;
    char *buf = OPENSSL_malloc(buflen);

    ret = BIO_snprintf((char *)buf, buflen, "%s\n",
                            OpenSSL_version(TONGSUO_VERSION));
    if (ret < 0) {
        OPENSSL_free(buf);
        return NULL;
    }

#ifdef SMTC_MODULE
    ret = BIO_snprintf(buf + ret, buflen - ret, "%s\n",
                       OpenSSL_version(TONGSUO_SMTC_INFO));
    if (ret < 0) {
        OPENSSL_free(buf);
        return NULL;
    }
#endif

    return buf;
}

#ifndef OPENSSL_NO_SM2
int TSAPI_DelSm2KeyWithIndex(int index, int sign, const char *user,
                                 const char *password)
{
    int ok = 0;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;

    if (sign) {
        area = SDFE_ASYM_KEY_AREA_SIGN;
    } else {
        area = SDFE_ASYM_KEY_AREA_ENC;
    }

    memset(&login_arg, 0, sizeof(login_arg));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_DelSm2KeyWithIndex", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_DelSm2KeyWithIndex: SDF_OpenDevice failed");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_DelSm2KeyWithIndex: SDF_OpenSession failed");
        goto end;
    }

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_DelSm2KeyWithIndex: SDFE_LoginUsr failed");
        goto end;
    }

    {
        int sdf_ret = SDFE_DelECCKey(hSessionHandle, area, index);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_DelSm2KeyWithIndex: SDFE_DelECCKey failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

int TSAPI_GenerateSM2KeyWithIndex(int index, int sign, const char *user,
                                  const char *password)
{
    int ok = 0;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_GenerateSM2KeyWithIndex", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_GenerateSM2KeyWithIndex: SDF_OpenDevice failed");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_GenerateSM2KeyWithIndex: SDF_OpenSession failed");
        goto end;
    }

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_GenerateSM2KeyWithIndex: SDFE_LoginUsr failed");
        goto end;
    }

    {
        int sdf_ret = SDFE_GenECCKey(hSessionHandle, area, index, 0, NULL);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_GenerateSM2KeyWithIndex: SDFE_GenECCKey failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

EVP_PKEY *TSAPI_EVP_PKEY_new_from_ECCrefKey(const OSSL_ECCrefPublicKey *pubkey,
                                            const OSSL_ECCrefPrivateKey *privkey)
{
    int ok = 0;
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int bytes;

    if (pubkey == NULL)
        return NULL;

    eckey = EC_KEY_new();
    if (eckey == NULL)
        return NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto end;

    if (!EC_KEY_set_group(eckey, group))
        goto end;

    bytes = (pubkey->bits + 7) / 8;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto end;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);

    if (BN_bin2bn(pubkey->x + sizeof(pubkey->x) - bytes, bytes, x) == NULL)
        goto end;

    if (BN_bin2bn(pubkey->y + sizeof(pubkey->y) - bytes, bytes, y) == NULL)
        goto end;

    if (!EC_KEY_set_public_key_affine_coordinates(eckey, x, y))
        goto end;

    if (privkey) {
        bytes = (privkey->bits + 7) / 8;
        if (BN_bin2bn(privkey->K + sizeof(privkey->K) - bytes, bytes, x) == NULL)
            goto end;

        if (!EC_KEY_set_private_key(eckey, x))
            goto end;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto end;

    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
        goto end;

    eckey = NULL;

    ok = 1;
end:
    if (!ok) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    EC_KEY_free(eckey);
    return pkey;
}

OSSL_ECCrefPublicKey *TSAPI_EVP_PKEY_get_ECCrefPublicKey(const EVP_PKEY *pkey)
{
    int ok = 0;
    const EC_KEY *eckey = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    BN_CTX *ctx = NULL;
    OSSL_ECCrefPublicKey *outkey = NULL;

    if (pkey == NULL)
        return NULL;

    eckey = EVP_PKEY_get0_EC_KEY(pkey);
    if (eckey == NULL)
        return NULL;

    group = EC_KEY_get0_group(eckey);
    point = EC_KEY_get0_public_key(eckey);
    if (group == NULL || point == NULL)
        return NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return NULL;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto end;

    if (!EC_POINT_get_affine_coordinates(group, point, x, y, ctx))
        goto end;

    outkey = OPENSSL_zalloc(sizeof(*outkey));
    if (outkey == NULL)
        goto end;

    outkey->bits = EVP_PKEY_get_bits(pkey);

    if (BN_bn2bin(x, outkey->x + sizeof(outkey->x) - BN_num_bytes(x)) < 0)
        goto end;
    if (BN_bn2bin(y, outkey->y + sizeof(outkey->y) - BN_num_bytes(y)) < 0)
        goto end;

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(outkey);
        outkey = NULL;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return outkey;
}

OSSL_ECCrefPrivateKey *TSAPI_EVP_PKEY_get_ECCrefPrivateKey(const EVP_PKEY *pkey)
{
    int ok = 0;
    const EC_KEY *eckey = NULL;
    const BIGNUM *priv = NULL;
    OSSL_ECCrefPrivateKey *outkey = NULL;

    if (pkey == NULL)
        return NULL;

    eckey = EVP_PKEY_get0_EC_KEY(pkey);
    if (eckey == NULL)
        return NULL;

    priv = EC_KEY_get0_private_key(eckey);
    if (priv == NULL)
        return NULL;

    outkey = OPENSSL_zalloc(sizeof(*outkey));
    if (outkey == NULL)
        goto end;

    outkey->bits = EVP_PKEY_get_bits(pkey);

    if (BN_bn2bin(priv, outkey->K + sizeof(outkey->K) - BN_num_bytes(priv)) < 0)
        goto end;

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(outkey);
        outkey = NULL;
    }
    return outkey;
}

int TSAPI_ImportSM2Key(int index, int sign, const char *user,
                       const char *password, const EVP_PKEY *sm2_pkey)
{
    int ok = 0;
#ifdef SDF_LIB
    int area;
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCrefPrivateKey *privkey = NULL;
    OSSL_ECCrefPublicKey *pubkey = NULL;
    sdfe_asym_key_ecc_t sm2_key;
    sdfe_login_arg_t login_arg;

    memset(&login_arg, 0, sizeof(login_arg));
    memset(&sm2_key, 0, sizeof(sm2_key));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_ImportSM2Key", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2Key: SDF_OpenDevice failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }
    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2Key: SDF_OpenSession failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }
    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2Key: SDFE_LoginUsr failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    privkey = TSAPI_EVP_PKEY_get_ECCrefPrivateKey(sm2_pkey);
    if (privkey == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2Key: failed to convert private key: index=%d type=%s",
                       index, tsapi_key_area_name(sign));
        goto end;
    }
    pubkey = TSAPI_EVP_PKEY_get_ECCrefPublicKey(sm2_pkey);
    if (pubkey == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2Key: failed to convert public key: index=%d type=%s",
                       index, tsapi_key_area_name(sign));
        goto end;
    }

    sm2_key.area = area;
    sm2_key.index = index;
    sm2_key.type = SDFE_ASYM_KEY_TYPE_SM2;
    sm2_key.privkey_bits = 256;
    sm2_key.privkey_len = sm2_key.privkey_bits >> 3;
    sm2_key.pubkey_bits = 256;
    sm2_key.pubkey_len = (sm2_key.pubkey_bits >> 3) << 1;

    memcpy(sm2_key.pubkey, pubkey, sizeof(*pubkey));
    memcpy(sm2_key.privkey, privkey, sizeof(*privkey));

    {
        int sdf_ret = SDFE_ImportECCKey(hSessionHandle, &sm2_key, NULL);
        if (sdf_ret != OSSL_SDR_OK) {
            tsapi_raise_sdf_error("TSAPI_ImportSM2Key", "SDFE_ImportECCKey",
                                  sdf_ret, index, sign, user);
            goto end;
        }
    }

    ok = 1;
end:
    OPENSSL_free(privkey);
    OPENSSL_free(pubkey);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

# ifndef OPENSSL_NO_RSA
int TSAPI_DelRSAKeyWithIndex(int index, int sign, const char *user,
                             const char *password)
{
    int ok = 0;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_DelRSAKeyWithIndex", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_DelRSAKeyWithIndex: SDF_OpenDevice failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_DelRSAKeyWithIndex: SDF_OpenSession failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_DelRSAKeyWithIndex: SDFE_LoginUsr failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    {
        int sdf_ret = SDFE_DelRSAKey(hSessionHandle, area, index);
        if (sdf_ret != OSSL_SDR_OK) {
            tsapi_raise_sdf_error("TSAPI_DelRSAKeyWithIndex", "SDFE_DelRSAKey",
                                  sdf_ret, index, sign, user);
            goto end;
        }
    }

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

/*
 * RSA 私钥转换辅助函数（参考厂商库 csm_manager.cpp 的 convertEVPToRSA）。
 * 零外部依赖，只使用铜锁 libcrypto 的 RSA/BIGNUM API。
 */

/* BIGNUM 大端定长填充（左侧补零），带长度校验。成功返回 1。 */
static int rsa_bn_to_fixed(const BIGNUM *bn, unsigned char *dest, size_t dest_len)
{
    if (bn == NULL || BN_num_bytes(bn) > (int)dest_len)
        return 0;
    return BN_bn2binpad(bn, dest, (int)dest_len) >= 0;
}

/*
 * 将 EVP_PKEY(RSA) 转换为 OSSL_RSArefPublicKey/PrivateKey（≤2048）或 Ex 版（3072/4096）。
 * @param pkey       RSA 私钥（含 CRT 分量）
 * @param use_ex     [out] 0=普通版, 1=Ex版
 * @param pub        [out] 普通版公钥（use_ex=0 时填充）
 * @param pri        [out] 普通版私钥（use_ex=0 时填充）
 * @param pub_ex     [out] Ex版公钥（use_ex=1 时填充）
 * @param pri_ex     [out] Ex版私钥（use_ex=1 时填充）
 * @return 1=成功 0=失败
 */
static int rsa_pkey_to_ref(const EVP_PKEY *pkey, int *use_ex,
                           OSSL_RSArefPublicKey *pub,
                           OSSL_RSArefPrivateKey *pri,
                           OSSL_RSArefPublicKeyEx *pub_ex,
                           OSSL_RSArefPrivateKeyEx *pri_ex)
{
    const RSA *rsa;
    const BIGNUM *n = NULL, *e = NULL, *d = NULL;
    const BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    int bits;

    if (pkey == NULL || EVP_PKEY_get_base_id(pkey) != EVP_PKEY_RSA) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "rsa_pkey_to_ref: input key is not RSA");
        return 0;
    }

    rsa = EVP_PKEY_get0_RSA((EVP_PKEY *)pkey);
    if (rsa == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "rsa_pkey_to_ref: EVP_PKEY_get0_RSA failed");
        return 0;
    }

    bits = RSA_bits(rsa);
    if (bits <= 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "rsa_pkey_to_ref: invalid RSA bits=%d", bits);
        return 0;
    }

    *use_ex = bits > (int)OSSL_RSAref_MAX_BITS;  /* >2048 用 Ex 版 */
    if (*use_ex && bits > (int)OSSL_RSAref_MAX_BITS_EX) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "rsa_pkey_to_ref: RSA bits not supported: bits=%d max=%d",
                       bits, (int)OSSL_RSAref_MAX_BITS_EX);
        return 0;
    }

    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

    if (*use_ex) {
        memset(pub_ex, 0, sizeof(*pub_ex));
        memset(pri_ex, 0, sizeof(*pri_ex));
        pub_ex->bits = bits;
        pri_ex->bits = bits;
        if (!rsa_bn_to_fixed(n, pub_ex->m, sizeof(pub_ex->m)) ||
            !rsa_bn_to_fixed(e, pub_ex->e, sizeof(pub_ex->e)) ||
            !rsa_bn_to_fixed(n, pri_ex->m, sizeof(pri_ex->m)) ||
            !rsa_bn_to_fixed(e, pri_ex->e, sizeof(pri_ex->e)) ||
            !rsa_bn_to_fixed(d, pri_ex->d, sizeof(pri_ex->d)) ||
            !rsa_bn_to_fixed(p, pri_ex->prime[0], sizeof(pri_ex->prime[0])) ||
            !rsa_bn_to_fixed(q, pri_ex->prime[1], sizeof(pri_ex->prime[1])) ||
            !rsa_bn_to_fixed(dmp1, pri_ex->pexp[0], sizeof(pri_ex->pexp[0])) ||
            !rsa_bn_to_fixed(dmq1, pri_ex->pexp[1], sizeof(pri_ex->pexp[1])) ||
            !rsa_bn_to_fixed(iqmp, pri_ex->coef, sizeof(pri_ex->coef))) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "rsa_pkey_to_ref: failed to export RSA CRT components: bits=%d use_ex=1",
                           bits);
            return 0;
        }
    } else {
        memset(pub, 0, sizeof(*pub));
        memset(pri, 0, sizeof(*pri));
        pub->bits = bits;
        pri->bits = bits;
        if (!rsa_bn_to_fixed(n, pub->m, sizeof(pub->m)) ||
            !rsa_bn_to_fixed(e, pub->e, sizeof(pub->e)) ||
            !rsa_bn_to_fixed(n, pri->m, sizeof(pri->m)) ||
            !rsa_bn_to_fixed(e, pri->e, sizeof(pri->e)) ||
            !rsa_bn_to_fixed(d, pri->d, sizeof(pri->d)) ||
            !rsa_bn_to_fixed(p, pri->prime[0], sizeof(pri->prime[0])) ||
            !rsa_bn_to_fixed(q, pri->prime[1], sizeof(pri->prime[1])) ||
            !rsa_bn_to_fixed(dmp1, pri->pexp[0], sizeof(pri->pexp[0])) ||
            !rsa_bn_to_fixed(dmq1, pri->pexp[1], sizeof(pri->pexp[1])) ||
            !rsa_bn_to_fixed(iqmp, pri->coef, sizeof(pri->coef))) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "rsa_pkey_to_ref: failed to export RSA CRT components: bits=%d use_ex=0",
                           bits);
            return 0;
        }
    }
    return 1;
}

int TSAPI_ImportRSAKey(int index, int sign, const char *user,
                       const char *password, const EVP_PKEY *rsa_pkey)
{
    int ok = 0;
#ifdef SDF_LIB
    int area, use_ex = 0;
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_asym_key_rsa_t rsa_key;
    sdfe_login_arg_t login_arg;
    OSSL_RSArefPublicKey pub;
    OSSL_RSArefPrivateKey pri;
    OSSL_RSArefPublicKeyEx pub_ex;
    OSSL_RSArefPrivateKeyEx pri_ex;

    memset(&login_arg, 0, sizeof(login_arg));
    memset(&rsa_key, 0, sizeof(rsa_key));
    memset(&pub, 0, sizeof(pub));
    memset(&pri, 0, sizeof(pri));
    memset(&pub_ex, 0, sizeof(pub_ex));
    memset(&pri_ex, 0, sizeof(pri_ex));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_ImportRSAKey", user);
            return 0;
        }
        strcpy((char *)login_arg.name, user);
    }

    if (!rsa_pkey_to_ref(rsa_pkey, &use_ex, &pub, &pri, &pub_ex, &pri_ex)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportRSAKey: RSA key conversion failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportRSAKey: SDF_OpenDevice failed: index=%d type=%s user=%s bits=%d use_ex=%d",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)",
                       use_ex ? pub_ex.bits : pub.bits, use_ex);
        goto end;
    }
    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportRSAKey: SDF_OpenSession failed: index=%d type=%s user=%s bits=%d use_ex=%d",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)",
                       use_ex ? pub_ex.bits : pub.bits, use_ex);
        goto end;
    }
    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportRSAKey: SDFE_LoginUsr failed: index=%d type=%s user=%s bits=%d use_ex=%d",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)",
                       use_ex ? pub_ex.bits : pub.bits, use_ex);
        goto end;
    }

    area = sign ? SDFE_ASYM_KEY_AREA_SIGN : SDFE_ASYM_KEY_AREA_ENC;
    rsa_key.area = area;
    rsa_key.index = index;
    rsa_key.type = SDFE_ASYM_KEY_TYPE_RSA;
    rsa_key.use_ex = use_ex;
    rsa_key.bits = use_ex ? pub_ex.bits : pub.bits;

    if (use_ex) {
        memcpy(rsa_key.pub_ex, &pub_ex, sizeof(pub_ex));
        memcpy(rsa_key.pri_ex, &pri_ex, sizeof(pri_ex));
    } else {
        memcpy(rsa_key.pub, &pub, sizeof(pub));
        memcpy(rsa_key.pri, &pri, sizeof(pri));
    }

    {
        int sdf_ret = SDFE_ImportRSAKey(hSessionHandle, &rsa_key, NULL);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                           "TSAPI_ImportRSAKey: SDFE_ImportRSAKey failed: ret=0x%08x index=%d type=%s user=%s bits=%d use_ex=%d",
                           sdf_ret, index, tsapi_key_area_name(sign),
                           user != NULL ? user : "(null)", rsa_key.bits,
                           use_ex);
            goto end;
        }
    }

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}
# endif /* OPENSSL_NO_RSA */

int TSAPI_ImportSM2KeyWithEvlp(int index, int sign, const char *user,
                               const char *password, unsigned char *key,
                               size_t keylen, unsigned char *dek, size_t deklen)
{
    int ok = 0;
#ifdef SDF_LIB
    int area;
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_asym_key_ecc_t sm2_key;
    sdfe_sym_key_evlp_t sym_key_evlp;
    sdfe_login_arg_t login_arg;

    memset(&login_arg, 0, sizeof(login_arg));
    memset(&sm2_key, 0, sizeof(sm2_key));
    memset(&sym_key_evlp, 0, sizeof(sym_key_evlp));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_ImportSM2KeyWithEvlp", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2KeyWithEvlp: SDF_OpenDevice failed");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2KeyWithEvlp: SDF_OpenSession failed");
        goto end;
    }

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2KeyWithEvlp: SDFE_LoginUsr failed");
        goto end;
    }

    sym_key_evlp.flags = SDFE_SYM_KEY_EVLP_F_IMPORT_KEY_INDEX_VALID;
    sym_key_evlp.asym_key_type = SDFE_ASYM_KEY_TYPE_SM2;
    sym_key_evlp.sym_key_type = SDFE_SYM_KEY_TYPE_SM4;
    sym_key_evlp.sym_key_len = 16;
    sym_key_evlp.asym_key_index = 0;

    if (deklen > sizeof(sym_key_evlp.data)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2KeyWithEvlp: envelope too large: deklen=%zu max=%zu index=%d type=%s",
                       deklen, sizeof(sym_key_evlp.data), index,
                       tsapi_key_area_name(sign));
        goto end;
    }
    sym_key_evlp.data_len = deklen;
    memcpy(sym_key_evlp.data, dek, deklen);

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    sm2_key.area = area;
    sm2_key.index = index;
    sm2_key.type = SDFE_ASYM_KEY_TYPE_SM2;
    sm2_key.privkey_bits = 256;
    sm2_key.privkey_len = sm2_key.privkey_bits >> 3;
    sm2_key.pubkey_bits = 256;
    sm2_key.pubkey_len = (sm2_key.pubkey_bits >> 3) << 1;

    if (keylen != sizeof(sm2_key.privkey) + sizeof(sm2_key.pubkey)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ImportSM2KeyWithEvlp: invalid SM2 key blob length: keylen=%zu expected=%zu index=%d type=%s",
                       keylen, sizeof(sm2_key.privkey) + sizeof(sm2_key.pubkey),
                       index, tsapi_key_area_name(sign));
        goto end;
    }

    memcpy(sm2_key.pubkey, key, sizeof(sm2_key.pubkey));
    memcpy(sm2_key.privkey, key + sizeof(sm2_key.pubkey),
                sizeof(sm2_key.privkey));

    {
        int sdf_ret = SDFE_ImportECCKeyWithEvlp(hSessionHandle, &sm2_key,
                                                &sym_key_evlp, NULL);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ImportSM2KeyWithEvlp: SDFE_ImportECCKeyWithEvlp failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

int TSAPI_ExportSM2KeyWithEvlp(int index, int sign, const char *user,
                               const char *password, EVP_PKEY *sm2_pkey,
                               unsigned char **priv, size_t *privlen,
                               unsigned char **pub, size_t *publen,
                               unsigned char **outevlp, size_t *outevlplen)

{
    int ok = 0;
#ifdef SDF_LIB
    int area;
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCrefPublicKey *pubkey = NULL;
    sdfe_asym_key_ecc_t sm2_key;
    sdfe_sym_key_evlp_t sym_key_evlp;
    sdfe_login_arg_t login_arg;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));
    memset(&sm2_key, 0, sizeof(sm2_key));
    memset(&sym_key_evlp, 0, sizeof(sym_key_evlp));

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_ExportSM2KeyWithEvlp", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2KeyWithEvlp: SDF_OpenDevice failed");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2KeyWithEvlp: SDF_OpenSession failed");
        goto end;
    }

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2KeyWithEvlp: SDFE_LoginUsr failed");
        goto end;
    }

    sm2_key.area = area;
    sm2_key.index = index;
    sm2_key.type = SDFE_ASYM_KEY_TYPE_SM2;

    sym_key_evlp.asym_key_type = SDFE_ASYM_KEY_TYPE_SM2;
    sym_key_evlp.sym_key_type = SDFE_SYM_KEY_TYPE_SM4;
    sym_key_evlp.sym_key_len = 16;

    pubkey = TSAPI_EVP_PKEY_get_ECCrefPublicKey(sm2_pkey);
    if (pubkey == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2KeyWithEvlp: failed to convert peer public key: index=%d type=%s",
                       index, tsapi_key_area_name(sign));
        goto end;
    }

    {
        int sdf_ret = SDFE_ExportECCKeyWithEvlp(hSessionHandle, &sm2_key,
                                                &sym_key_evlp, (void *)pubkey);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ExportSM2KeyWithEvlp: SDFE_ExportECCKeyWithEvlp failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    *outevlp = OPENSSL_malloc(sym_key_evlp.data_len);
    if (*outevlp == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2KeyWithEvlp: outevlp alloc failed");
        goto end;
    }

    memcpy(*outevlp, sym_key_evlp.data, sym_key_evlp.data_len);
    *outevlplen = sym_key_evlp.data_len;

    *priv = OPENSSL_malloc(sizeof(sm2_key.privkey));
    if (*priv == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2KeyWithEvlp: priv alloc failed");
        goto end;
    }

    memcpy(*priv, sm2_key.privkey, sizeof(sm2_key.privkey));
    *privlen = sizeof(sm2_key.privkey);

    *pub = OPENSSL_malloc(sizeof(sm2_key.pubkey));
    if (*pub == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2KeyWithEvlp: pub alloc failed");
        goto end;
    }

    memcpy(*pub, sm2_key.pubkey, sizeof(sm2_key.pubkey));
    *publen = sizeof(sm2_key.pubkey);

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(*priv);
        OPENSSL_free(*pub);
        OPENSSL_free(*outevlp);
        *priv = NULL;
        *pub = NULL;
        *outevlp = NULL;
        *privlen = 0;
        *publen = 0;
        *outevlplen = 0;
    }

    OPENSSL_free(pubkey);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

EVP_PKEY *TSAPI_ExportSM2KeyWithIndex(int index, int sign, const char *user,
                                      const char *password)
{
    EVP_PKEY *pkey = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;
    OSSL_ECCrefPrivateKey privkey;
    OSSL_ECCrefPublicKey pubkey;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_ExportSM2KeyWithIndex", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2KeyWithIndex: SDF_OpenDevice failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2KeyWithIndex: SDF_OpenSession failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2KeyWithIndex: SDFE_LoginUsr failed: index=%d type=%s user=%s",
                       index, tsapi_key_area_name(sign),
                       user != NULL ? user : "(null)");
        goto end;
    }

    {
        int sdf_ret = SDFE_ExportECCPrivKey(hSessionHandle, area, index, 0, NULL,
                                            (ECCrefPrivateKey *)&privkey);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ExportSM2KeyWithIndex: SDFE_ExportECCPrivKey failed: ret=0x%08x index=%d type=%s user=%s",
                           sdf_ret, index, tsapi_key_area_name(sign),
                           user != NULL ? user : "(null)");
            goto end;
        }
    }

    if (sign) {
        int sdf_ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSessionHandle, index, &pubkey);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ExportSM2KeyWithIndex: ExportSignPublicKey failed: ret=0x%08x index=%d type=sign",
                           sdf_ret, index);
            goto end;
        }
    } else {
        int sdf_ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSessionHandle, index, &pubkey);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ExportSM2KeyWithIndex: ExportEncPublicKey failed: ret=0x%08x index=%d type=enc",
                           sdf_ret, index);
            goto end;
        }
    }

    pkey = TSAPI_EVP_PKEY_new_from_ECCrefKey(&pubkey, &privkey);
    if (pkey == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2KeyWithIndex: pkey conversion failed: index=%d type=%s",
                       index, tsapi_key_area_name(sign));
        goto end;
    }
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return pkey;
}

EVP_PKEY *TSAPI_ExportRSAPubKeyWithIndex(int index, int sign)
{
    EVP_PKEY *pkey = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_RSArefPublicKeyEx pub_ex;   /* Ex 版可容纳 ≤4096，统一用 Ex 接收 */
    OSSL_RSArefPublicKey pub;
    BIGNUM *n = NULL, *e = NULL;
    RSA *rsa = NULL;
    int nbytes, ret;

    memset(&pub_ex, 0, sizeof(pub_ex));

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportRSAPubKeyWithIndex: SDF_OpenDevice failed");
        goto end;
    }
    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportRSAPubKeyWithIndex: SDF_OpenSession failed");
        goto end;
    }

    /*
     * 直接使用 Ex 版接口（RSArefPublicKeyEx 可容纳 ≤4096，兼容所有位长）。
     * 部分厂商库的普通版 ExportSignPublicKey_RSA 只支持 ≤2048，
     * 对 3072/4096 会截断或报错；Ex 版统一处理所有位长。
     * 若 Ex 版未绑定（厂商库不提供），回退到普通版（仅 ≤2048）。
     */
    /*
     * 使用 Ex 版结构体（RSArefPublicKeyEx，可容纳 ≤4096）接收数据。
     * 先试 Ex 版接口（厂商库若有则覆盖所有位长），失败回退普通版（≤2048）。
     * 注意：部分厂商库 Ex 版与普通版索引语义不同，普通版更可靠。
     */
    //先使用Ex获取长度，然后根据长度具体使用哪套接口
    if (sign)
        ret = TSAPI_SDF_ExportSignPublicKey_RSAEx(hSessionHandle, index, &pub_ex);
    else
        ret = TSAPI_SDF_ExportEncPublicKey_RSAEx(hSessionHandle, index, &pub_ex);
    if (ret != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportRSAPubKeyWithIndex: ExportSignPublicKey failed: 0x%08x", ret);
        goto end;
    }

    if (pub_ex.bits <= 2048)
    {
        if (sign)
            ret = TSAPI_SDF_ExportSignPublicKey_RSA(hSessionHandle, index,
                (OSSL_RSArefPublicKey*)&pub);
        else
            ret = TSAPI_SDF_ExportEncPublicKey_RSA(hSessionHandle, index,
                (OSSL_RSArefPublicKey*)&pub);

        if (!ret)
        {
            //switch Ex
            memset(&pub_ex, 0, sizeof(pub_ex));
            pub_ex.bits = pub.bits;
            memcpy(&pub_ex.m[256], pub.m, sizeof(pub.m));
            memcpy(&pub_ex.e[256], pub.e, sizeof(pub.e));
        }
    }
    else
    {//3072 4096
        memset(&pub_ex, 0, sizeof(pub_ex));
        if (sign)
            ret = TSAPI_SDF_ExportSignPublicKey_RSAEx(hSessionHandle, index, &pub_ex);
        else
            ret = TSAPI_SDF_ExportEncPublicKey_RSAEx(hSessionHandle, index, &pub_ex);
        if (ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ExportRSAPubKeyWithIndex: ExportSignPublicKey failed: 0x%08x", ret);
            goto end;
        }
    }


    nbytes = (pub_ex.bits + 7) / 8;
    if (nbytes <= 0 || nbytes > (int)sizeof(pub_ex.m)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "TSAPI_ExportRSAPubKeyWithIndex: invalid RSA key bits");
        goto end;
    }

    n = BN_bin2bn(pub_ex.m, nbytes, NULL);
    e = BN_bin2bn(pub_ex.e, nbytes, NULL);
    if (n == NULL || e == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportRSAPubKeyWithIndex: BN alloc failed");
        goto end;
    }

    rsa = RSA_new();
    if (rsa == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportRSAPubKeyWithIndex: RSA alloc failed");
        goto end;
    }
    if (!RSA_set0_key(rsa, n, e, NULL)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "TSAPI_ExportRSAPubKeyWithIndex: RSA_set0_key failed");
        goto end;
    }
    n = e = NULL;  /* 所有权转移 */

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportRSAPubKeyWithIndex: EVP_PKEY alloc failed");
        goto end;
    }
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "TSAPI_ExportRSAPubKeyWithIndex: EVP_PKEY_assign_RSA failed");
        goto end;
    }
    rsa = NULL;  /* 所有权转移 */

end:
    BN_free(n);
    BN_free(e);
    RSA_free(rsa);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return pkey;
}

EVP_PKEY *TSAPI_ExportSM2PubKeyWithIndex(int index, int sign)
{
    EVP_PKEY *pkey = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCrefPublicKey pubkey;
    EC_GROUP *group = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int nbytes;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2PubKeyWithIndex: SDF_OpenDevice failed");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_ExportSM2PubKeyWithIndex: SDF_OpenSession failed");
        goto end;
    }

    if (sign) {
        int sdf_ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSessionHandle, index, &pubkey);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ExportSM2PubKeyWithIndex: ExportSignPublicKey failed: 0x%08x", sdf_ret);
            goto end;
        }
    } else {
        int sdf_ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSessionHandle, index, &pubkey);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_ExportSM2PubKeyWithIndex: ExportEncPublicKey failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2PubKeyWithIndex: EC_GROUP alloc failed");
        goto end;
    }

    eckey = EC_KEY_new();
    if (eckey == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2PubKeyWithIndex: EC_KEY alloc failed");
        goto end;
    }

    EC_KEY_set_group(eckey, group);

    nbytes = (pubkey.bits + 7) / 8;

    x = BN_bin2bn(pubkey.x + sizeof(pubkey.x) - nbytes, nbytes, NULL);
    if (x == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2PubKeyWithIndex: BN x alloc failed");
        goto end;
    }

    y = BN_bin2bn(pubkey.y + sizeof(pubkey.y) - nbytes, nbytes, NULL);
    if (y == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2PubKeyWithIndex: BN y alloc failed");
        goto end;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(eckey, x, y)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "TSAPI_ExportSM2PubKeyWithIndex: EC_KEY_set_public_key_affine_coordinates failed");
        goto end;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ExportSM2PubKeyWithIndex: EVP_PKEY alloc failed");
        goto end;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "TSAPI_ExportSM2PubKeyWithIndex: EVP_PKEY_assign_EC_KEY failed");
        EVP_PKEY_free(pkey);
        goto end;
    }
    eckey = NULL;

end:
    EC_KEY_free(eckey);
    EC_GROUP_free(group);
    BN_free(x);
    BN_free(y);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return pkey;
}

int TSAPI_UpdateSm2KeyWithIndex(int index, int sign, const char *user, const char *password)
{
    int ok = 0;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    sdfe_login_arg_t login_arg;
    int area;

    if (sign)
        area = SDFE_ASYM_KEY_AREA_SIGN;
    else
        area = SDFE_ASYM_KEY_AREA_ENC;

    memset(&login_arg, 0, sizeof(login_arg));

    if (user) {
        if (strlen(user) >= sizeof(login_arg.name)) {
            tsapi_raise_user_too_long("TSAPI_UpdateSm2KeyWithIndex", user);
            return 0;
        }

        strcpy((char *)login_arg.name, user);
    }

    login_arg.passwd = (uint8_t *)password;
    if (password)
        login_arg.passwd_len = strlen(password);
    else
        login_arg.passwd_len = 0;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_UpdateSm2KeyWithIndex: SDF_OpenDevice failed");
        goto end;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_UpdateSm2KeyWithIndex: SDF_OpenSession failed");
        goto end;
    }

    if (SDFE_LoginUsr(hSessionHandle, &login_arg) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_UpdateSm2KeyWithIndex: SDFE_LoginUsr failed");
        goto end;
    }

    {
        int sdf_ret = SDFE_DelECCKey(hSessionHandle, area, index);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_UpdateSm2KeyWithIndex: SDFE_DelECCKey failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    {
        int sdf_ret = SDFE_GenECCKey(hSessionHandle, area, index, 0, NULL);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_UpdateSm2KeyWithIndex: SDFE_GenECCKey failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    ok = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return ok;
}

EVP_PKEY *TSAPI_SM2Keygen(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
}

# ifndef OPENSSL_NO_SM3
int TSAPI_SM2Verify(EVP_PKEY *key, const unsigned char *tbs, size_t tbslen,
                    const unsigned char *sig, size_t siglen)
{
    int ok = 0;
    EVP_MD_CTX *ctx = NULL;

    if (key == NULL || tbs == NULL || sig == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2Verify: EVP_MD_CTX_new failed: tbslen=%zu siglen=%zu",
                       tbslen, siglen);
        return 0;
    }

    if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, key)
        || EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen) <= 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    ok = 1;
end:
    EVP_MD_CTX_free(ctx);
    return ok;
}

unsigned char *TSAPI_SM2Sign(EVP_PKEY *key, const unsigned char *tbs,
                             size_t tbslen, size_t *siglen)
{
    unsigned char *sig = NULL;
    size_t len;
    EVP_MD_CTX *ctx = NULL;

    if (key == NULL || tbs == NULL || siglen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2Sign: EVP_MD_CTX_new failed: tbslen=%zu",
                       tbslen);
        return NULL;
    }

    if (!EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, key)
        || !EVP_DigestSign(ctx, NULL, &len, tbs, tbslen)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    sig = OPENSSL_malloc(len);
    if (sig == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2Sign: signature alloc failed: siglen=%zu",
                       len);
        goto end;
    }

    if (!EVP_DigestSign(ctx, sig, &len, tbs, tbslen)) {
        OPENSSL_free(sig);
        *siglen = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    *siglen = len;
end:
    EVP_MD_CTX_free(ctx);
    return sig;
}
# endif

static unsigned char *do_SM2Crypt(int enc, EVP_PKEY *key,
                                  const unsigned char *in, size_t inlen,
                                  size_t *outlen)
{
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = 0;
    unsigned char *out = NULL;

    if (key == NULL || in == NULL || outlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (enc) {
        ctx = EVP_PKEY_CTX_new_from_pkey_provided(NULL, key, NULL);
    } else {
        ctx = EVP_PKEY_CTX_new(key, NULL);
    }

    if (ctx == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_EVP_LIB,
                       "do_SM2Crypt: EVP_PKEY_CTX_new failed: op=%s inlen=%zu",
                       enc ? "encrypt" : "decrypt", inlen);
        return NULL;
    }

    if (enc) {
        if (EVP_PKEY_encrypt_init(ctx) <= 0
            || EVP_PKEY_encrypt(ctx, NULL, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            goto end;
        }
    } else {
        if (EVP_PKEY_decrypt_init(ctx) <= 0
            || EVP_PKEY_decrypt(ctx, NULL, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            goto end;
        }
    }

    out = OPENSSL_malloc(len);
    if (out == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "do_SM2Crypt: output alloc failed: op=%s outlen=%zu",
                       enc ? "encrypt" : "decrypt", len);
        goto end;
    }

    if (enc) {
        if (EVP_PKEY_encrypt(ctx, out, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            OPENSSL_free(out);
            out = NULL;
            len = 0;
        }
    } else {
        if (EVP_PKEY_decrypt(ctx, out, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            OPENSSL_free(out);
            out = NULL;
            len = 0;
        }
    }

    *outlen = len;
end:
    EVP_PKEY_CTX_free(ctx);
    return out;
}

unsigned char *TSAPI_SM2DecryptWithISK(int isk, const unsigned char *in,
                                       size_t inlen, size_t *outlen)
{
    unsigned char *out = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCCipher *ecc = NULL;
    unsigned int len;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_SM2DecryptWithISK: SDF_OpenDevice failed");
        return NULL;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_SM2DecryptWithISK: SDF_OpenSession failed");
        goto end;
    }

    {
        int sdf_ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSessionHandle, isk,
                                                        NULL, 0);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_SM2DecryptWithISK: GetPrivateKeyAccessRight failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    ecc = TSAPI_SM2Ciphertext_to_ECCCipher(in, inlen);
    if (ecc == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2DecryptWithISK: ECCCipher alloc failed");
        goto end;
    }

    len = ecc->L;
    out = OPENSSL_malloc(len);
    if (out == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2DecryptWithISK: out alloc failed");
        goto end;
    }

    {
        int sdf_ret = TSAPI_SDF_InternalDecrypt_ECC(hSessionHandle, isk,
                                                   OSSL_SGD_SM2_3, ecc, out, &len);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_SM2DecryptWithISK: InternalDecrypt_ECC failed: 0x%08x", sdf_ret);
            OPENSSL_free(out);
            out = NULL;
            *outlen = 0;
            goto end;
        }
    }

    *outlen = len;
end:
    OPENSSL_free(ecc);
    TSAPI_SDF_ReleasePrivateKeyAccessRight(hSessionHandle, isk);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return out;
}

unsigned char *TSAPI_SM2EncryptWithISK(int isk, const unsigned char *in,
                                       size_t inlen, size_t *outlen)
{
    unsigned char *out = NULL;
#ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    OSSL_ECCCipher *ecc = NULL;

    if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_SM2EncryptWithISK: SDF_OpenDevice failed");
        return NULL;
    }

    if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "TSAPI_SM2EncryptWithISK: SDF_OpenSession failed");
        goto end;
    }

    ecc = OPENSSL_zalloc(sizeof(OSSL_ECCCipher) + inlen);
    if (ecc == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2EncryptWithISK: ECCCipher alloc failed");
        goto end;
    }

    {
        int sdf_ret = TSAPI_SDF_InternalEncrypt_ECC(hSessionHandle, isk,
                                                   OSSL_SGD_SM2_3,
                                                   (unsigned char *)in,
                                                   inlen, ecc);
        if (sdf_ret != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_SM2EncryptWithISK: InternalEncrypt_ECC failed: 0x%08x", sdf_ret);
            goto end;
        }
    }

    out = TSAPI_ECCCipher_to_SM2Ciphertext(ecc, outlen);

end:
    OPENSSL_free(ecc);
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
#endif
    return out;
}

unsigned char *TSAPI_SM2Encrypt(EVP_PKEY *key, const unsigned char *in,
                                size_t inlen, size_t *outlen)
{
    return do_SM2Crypt(1, key, in, inlen, outlen);
}

unsigned char *TSAPI_SM2Decrypt(EVP_PKEY *key, const unsigned char *in,
                                size_t inlen, size_t *outlen)
{
    return do_SM2Crypt(0, key, in, inlen, outlen);
}

unsigned char *TSAPI_ECCCipher_to_SM2Ciphertext(const OSSL_ECCCipher *ecc,
                                                size_t *ciphertext_len)
{
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *out = NULL;

    if (ecc == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((x = BN_bin2bn(ecc->x, sizeof(ecc->x), NULL)) == NULL
        || (y = BN_bin2bn(ecc->y, sizeof(ecc->y), NULL)) == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_ECCCipher_to_SM2Ciphertext: BN alloc failed: L=%u",
                       ecc->L);
        goto end;
    }

    out = ossl_sm2_ciphertext_encode(x, y, ecc->C, ecc->L, ecc->M,
                                     sizeof(ecc->M), ciphertext_len);
    if (out == NULL)
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                       "TSAPI_ECCCipher_to_SM2Ciphertext: SM2 ciphertext encode failed: L=%u",
                       ecc->L);
end:
    BN_free(x);
    BN_free(y);
    return out;

}

OSSL_ECCCipher *TSAPI_SM2Ciphertext_to_ECCCipher(const unsigned char *ciphertext,
                                                 size_t ciphertext_len)
{
    int ok = 0;
    EC_POINT *C1 = NULL;
    uint8_t *C2_data = NULL, *C3_data = NULL;
    size_t C2_len, C3_len;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *Cx = NULL, *Cy = NULL;
    OSSL_ECCCipher *ecc = NULL;

    if (ciphertext == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!ossl_sm2_ciphertext_decode(ciphertext, ciphertext_len, &C1, &C2_data,
                                    &C2_len, &C3_data, &C3_len)) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: SM2 ciphertext decode failed: ciphertext_len=%zu",
                       ciphertext_len);
        goto end;
    }

    ecc = OPENSSL_zalloc(sizeof(OSSL_ECCCipher) + C2_len);
    if (ecc == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: ECCCipher alloc failed: c2_len=%zu",
                       C2_len);
        goto end;
    }

    if (C3_len != sizeof(ecc->M)) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: invalid C3 length: c3_len=%zu expected=%zu",
                       C3_len, sizeof(ecc->M));
        goto end;
    }

    memcpy(ecc->M, C3_data, C3_len);
    ecc->L = C2_len;
    memcpy(ecc->C, C2_data, C2_len);

    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: EC_GROUP alloc failed");
        goto end;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: BN_CTX alloc failed");
        goto end;
    }

    BN_CTX_start(ctx);
    Cx = BN_CTX_get(ctx);
    Cy = BN_CTX_get(ctx);
    if (Cy == NULL) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: BN_CTX_get failed");
        goto end;
    }

    if (!EC_POINT_get_affine_coordinates(group, C1, Cx, Cy, NULL)) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: get affine coordinates failed");
        goto end;
    }

    if (BN_bn2bin(Cx, ecc->x + sizeof(ecc->x) - BN_num_bytes(Cx))
            != BN_num_bytes(Cx)
        || BN_bn2bin(Cy, ecc->y + sizeof(ecc->y) - BN_num_bytes(Cy))
            != BN_num_bytes(Cy)) {
        ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                       "TSAPI_SM2Ciphertext_to_ECCCipher: BN serialize failed");
        goto end;
    }

    ok = 1;
end:
    if (!ok) {
        OPENSSL_free(ecc);
        ecc = NULL;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(C1);
    OPENSSL_free(C2_data);
    OPENSSL_free(C3_data);
    return ecc;

}
#endif

#ifndef OPENSSL_NO_SM4
static unsigned char *do_SM4Crypt(int mode, int enc,
                                  const unsigned char *key,
                                  size_t keylen, int isk,
                                  const unsigned char *iv,
                                  const unsigned char *in, size_t inlen,
                                  size_t *outlen)
{
# ifdef SDF_LIB
    void *hDeviceHandle = NULL;
    void *hSessionHandle = NULL;
    void *hkeyHandle = NULL;
    OSSL_ECCCipher *ecc = NULL;
# endif
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *outbuf = NULL;
    unsigned int len = 0;
    int lenf = 0;
    size_t max_out_len;

    if (isk < 0) {
        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                           "TSAPI_SM4Crypt: EVP_CIPHER_CTX_new failed: op=%s mode=0x%x",
                           enc ? "encrypt" : "decrypt", mode);
            return 0;
        }

        if (mode == OSSL_SGD_MODE_ECB)
            cipher = EVP_sm4_ecb();
        else if (mode == OSSL_SGD_MODE_CBC)
            cipher = EVP_sm4_cbc();
        else if (mode == OSSL_SGD_MODE_CFB)
            cipher = EVP_sm4_cfb();
        else if (mode == OSSL_SGD_MODE_OFB)
            cipher = EVP_sm4_ofb();
        else if (mode == OSSL_SGD_MODE_CTR)
            cipher = EVP_sm4_ctr();
        else {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT,
                           "TSAPI_SM4Crypt: unknown SM4 mode: op=%s mode=0x%x",
                           enc ? "encrypt" : "decrypt", mode);
            goto end;
        }

        if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc)
            || !EVP_CIPHER_CTX_set_padding(ctx, 0)) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_EVP_LIB,
                           "TSAPI_SM4Crypt: EVP_CipherInit failed: op=%s mode=0x%x keylen=%zu inlen=%zu",
                           enc ? "encrypt" : "decrypt", mode, keylen, inlen);
            goto end;
        }

        max_out_len = inlen + EVP_CIPHER_CTX_get_block_size(ctx);

        outbuf = OPENSSL_malloc(max_out_len);
        if (outbuf == NULL) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE,
                           "TSAPI_SM4Crypt: output alloc failed: op=%s mode=0x%x max_out_len=%zu",
                           enc ? "encrypt" : "decrypt", mode, max_out_len);
            goto end;
        }

        if (!EVP_CipherUpdate(ctx, outbuf, (int *)&len, in, inlen)) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_EVP_LIB,
                           "TSAPI_SM4Crypt: EVP_CipherUpdate failed: op=%s mode=0x%x inlen=%zu",
                           enc ? "encrypt" : "decrypt", mode, inlen);
            OPENSSL_free(outbuf);
            outbuf = NULL;
            len = 0;
            goto end;
        }

        if (!EVP_CipherFinal_ex(ctx, outbuf + len, &lenf)) {
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_EVP_LIB,
                           "TSAPI_SM4Crypt: EVP_CipherFinal failed: op=%s mode=0x%x len=%u",
                           enc ? "encrypt" : "decrypt", mode, len);
            OPENSSL_free(outbuf);
            outbuf = NULL;
            len = 0;
            goto end;
        }

        len += lenf;
    }
# ifdef SDF_LIB
    else {

        if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_SM4Crypt: SDF_OpenDevice failed: op=%s mode=0x%x isk=%d keylen=%zu inlen=%zu",
                           enc ? "encrypt" : "decrypt", mode, isk, keylen,
                           inlen);
            goto end;
        }

        if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != OSSL_SDR_OK) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_SM4Crypt: SDF_OpenSession failed: op=%s mode=0x%x isk=%d keylen=%zu inlen=%zu",
                           enc ? "encrypt" : "decrypt", mode, isk, keylen,
                           inlen);
            goto end;
        }

        {
            int sdf_ret = TSAPI_SDF_GetPrivateKeyAccessRight(hSessionHandle, isk,
                                                           NULL, 0);
            if (sdf_ret != OSSL_SDR_OK) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                               "TSAPI_SM4Crypt: GetPrivateKeyAccessRight failed: ret=0x%08x op=%s mode=0x%x isk=%d",
                               sdf_ret, enc ? "encrypt" : "decrypt", mode,
                               isk);
                goto end;
            }
        }

        ecc = TSAPI_SM2Ciphertext_to_ECCCipher(key, keylen);
        if (ecc == NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "TSAPI_SM4Crypt: SM2 encrypted SM4 key decode failed: op=%s mode=0x%x isk=%d keylen=%zu",
                           enc ? "encrypt" : "decrypt", mode, isk, keylen);
            goto end;
        }

        {
            int sdf_ret = TSAPI_SDF_ImportKeyWithISK_ECC(hSessionHandle, isk,
                                                       ecc, &hkeyHandle);
            if (sdf_ret != OSSL_SDR_OK) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                               "TSAPI_SM4Crypt: ImportKeyWithISK_ECC failed: ret=0x%08x op=%s mode=0x%x isk=%d keylen=%zu",
                               sdf_ret, enc ? "encrypt" : "decrypt", mode,
                               isk, keylen);
                goto end;
            }
        }

        outbuf = (unsigned char *)OPENSSL_malloc(inlen + 128);
        if (outbuf == NULL) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE,
                           "TSAPI_SM4Crypt: outbuf alloc failed: op=%s mode=0x%x inlen=%zu",
                           enc ? "encrypt" : "decrypt", mode, inlen);
            goto end;
        }

        if (enc) {
            int sdf_ret = TSAPI_SDF_Encrypt(hSessionHandle, hkeyHandle,
                                          OSSL_SGD_SM4 | mode,
                                          (unsigned char *)iv, (unsigned char *)in,
                                          inlen, outbuf, &len);
            if (sdf_ret != OSSL_SDR_OK) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                               "TSAPI_SM4Encrypt: SDF_Encrypt failed: ret=0x%08x mode=0x%x isk=%d inlen=%zu",
                               sdf_ret, mode, isk, inlen);
                OPENSSL_free(outbuf);
                outbuf = NULL;
                goto end;
            }
        } else {
            int sdf_ret = TSAPI_SDF_Decrypt(hSessionHandle, hkeyHandle,
                                          OSSL_SGD_SM4 | mode,
                                          (unsigned char *)iv, (unsigned char *)in,
                                          inlen, outbuf, &len);
            if (sdf_ret != OSSL_SDR_OK) {
                ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                               "TSAPI_SM4Decrypt: SDF_Decrypt failed: ret=0x%08x mode=0x%x isk=%d inlen=%zu",
                               sdf_ret, mode, isk, inlen);
                OPENSSL_free(outbuf);
                outbuf = NULL;
                goto end;
            }
        }
    }
# endif
    *outlen = len;
end:
    EVP_CIPHER_CTX_free(ctx);
# ifdef SDF_LIB
    if (isk >= 0) {
        TSAPI_SDF_DestroyKey(hSessionHandle, hkeyHandle);
        TSAPI_SDF_ReleasePrivateKeyAccessRight(hSessionHandle, isk);
        OPENSSL_free(ecc);
        TSAPI_SDF_CloseSession(hSessionHandle);
        TSAPI_SDF_CloseDevice(hDeviceHandle);
    }
# endif
    return outbuf;
}

unsigned char *TSAPI_SM4Decrypt(int mode, const unsigned char *key,
                                size_t keylen, int isk,
                                const unsigned char *iv,
                                const unsigned char *in, size_t inlen,
                                size_t *outlen)
{
    return do_SM4Crypt(mode, 0, key, keylen, isk, iv, in, inlen, outlen);
}

unsigned char *TSAPI_SM4Encrypt(int mode, const unsigned char *key,
                                size_t keylen, int isk,
                                const unsigned char *iv,
                                const unsigned char *in, size_t inlen,
                                size_t *outlen)
{
    return do_SM4Crypt(mode, 1, key, keylen, isk, iv, in, inlen, outlen);
}
#endif

#ifndef OPENSSL_NO_SM3
unsigned char *TSAPI_SM3(const void *data, size_t datalen, size_t *outlen)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char *out = NULL;
    unsigned int len = 0;

    if (data == NULL || outlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return NULL;

    if (!EVP_DigestInit_ex(ctx, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(ctx, data, datalen)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        goto end;
    }

    out = OPENSSL_malloc(EVP_MD_CTX_get_size(ctx));
    if (out == NULL)
        goto end;

    if (!EVP_DigestFinal_ex(ctx, out, &len)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
        OPENSSL_free(out);
        out = NULL;
        len = 0;
    }

    *outlen = len;
end:
    EVP_MD_CTX_free(ctx);
    return out;
}
#endif
