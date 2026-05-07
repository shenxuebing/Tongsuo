/*
 * SDF Provider Utility Functions
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/tsapi.h>
#include "sdfprov_utils.h"
#include "crypto/sm2.h"

int sdfprov_eccrefpub_to_ec_key(const OSSL_ECCrefPublicKey *pub,
                                EC_KEY *ec_key)
{
    BIGNUM *x = NULL, *y = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group;
    int ret = 0;

    if (pub == NULL || ec_key == NULL)
        return 0;

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
        return 0;

    x = BN_bin2bn(pub->x, OSSL_ECCref_MAX_LEN, NULL);
    y = BN_bin2bn(pub->y, OSSL_ECCref_MAX_LEN, NULL);
    point = EC_POINT_new(group);
    if (x == NULL || y == NULL || point == NULL)
        goto end;

    if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        goto end;

    if (!EC_KEY_set_public_key(ec_key, point))
        goto end;

    ret = 1;
end:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    return ret;
}

int sdfprov_ec_key_to_eccrefpub(const EC_KEY *ec_key,
                                OSSL_ECCrefPublicKey *pub)
{
    const EC_POINT *point;
    const EC_GROUP *group;
    BIGNUM *x = NULL, *y = NULL;
    int ret = 0;

    if (ec_key == NULL || pub == NULL)
        return 0;

    group = EC_KEY_get0_group(ec_key);
    point = EC_KEY_get0_public_key(ec_key);
    if (group == NULL || point == NULL)
        return 0;

    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL)
        goto end;

    if (!EC_POINT_get_affine_coordinates(group, point, x, y, NULL))
        goto end;

    memset(pub, 0, sizeof(*pub));
    pub->bits = 256;
    BN_bn2binpad(x, pub->x, OSSL_ECCref_MAX_LEN);
    BN_bn2binpad(y, pub->y, OSSL_ECCref_MAX_LEN);

    ret = 1;
end:
    BN_free(x);
    BN_free(y);
    return ret;
}

int sdfprov_eccsig_to_der(const OSSL_ECCSignature *sig,
                          unsigned char **out, size_t *out_len)
{
    BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    unsigned char *der = NULL;
    int der_len;
    int ret = 0;

    if (sig == NULL || out == NULL || out_len == NULL)
        return 0;

    r = BN_bin2bn(sig->r, OSSL_ECCref_MAX_LEN, NULL);
    s = BN_bin2bn(sig->s, OSSL_ECCref_MAX_LEN, NULL);
    if (r == NULL || s == NULL)
        goto end;

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
        goto end;

    if (!ECDSA_SIG_set0(ecdsa_sig, r, s))
        goto end;
    r = NULL;
    s = NULL;

    der_len = i2d_ECDSA_SIG(ecdsa_sig, &der);
    if (der_len <= 0)
        goto end;

    *out = der;
    *out_len = (size_t)der_len;
    der = NULL;
    ret = 1;
end:
    OPENSSL_free(der);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ecdsa_sig);
    return ret;
}

int sdfprov_der_to_eccsig(const unsigned char *der, size_t der_len,
                          OSSL_ECCSignature *sig)
{
    ECDSA_SIG *ecdsa_sig = NULL;
    const BIGNUM *sig_r, *sig_s;
    const unsigned char *p = der;
    int ret = 0;

    if (der == NULL || sig == NULL)
        return 0;

    ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (ecdsa_sig == NULL)
        return 0;

    ECDSA_SIG_get0(ecdsa_sig, &sig_r, &sig_s);

    memset(sig, 0, sizeof(*sig));
    if (BN_bn2binpad(sig_r, sig->r, OSSL_ECCref_MAX_LEN) < 0
        || BN_bn2binpad(sig_s, sig->s, OSSL_ECCref_MAX_LEN) < 0)
        goto end;

    ret = 1;
end:
    ECDSA_SIG_free(ecdsa_sig);
    return ret;
}

/*
 * OSSL_ECCCipher 结构:
 *   x[64] + y[64]     = C1 (SM2 临时公钥点)
 *   M[32]              = C3 (SM3 摘要)
 *   L                  = 密文长度
 *   C[L]               = C2 (密文)
 *
 * 使用 ossl_sm2_ciphertext_encode 进行 DER 编码
 */
int sdfprov_ecccipher_to_sm2_der(const OSSL_ECCCipher *cipher,
                                 unsigned char **out, size_t *out_len,
                                 int encdata_format)
{
    unsigned char *der;

    if (cipher == NULL || out == NULL || out_len == NULL)
        return 0;

    der = TSAPI_ECCCipher_to_SM2Ciphertext(cipher, out_len);
    if (der == NULL)
        return 0;

    *out = der;
    return 1;
}

int sdfprov_sm2_der_to_ecccipher(const unsigned char *der, size_t der_len,
                                 OSSL_ECCCipher *cipher,
                                 int encdata_format)
{
    EC_POINT *C1 = NULL;
    uint8_t *C2 = NULL, *C3 = NULL;
    size_t C2_len = 0, C3_len = 0;
    EC_GROUP *group = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int ret = 0;

    if (der == NULL || cipher == NULL)
        return 0;

    /* 解码 DER 密文: 尝试 C1C3C2 格式 */
    if (!ossl_sm2_ciphertext_decode(der, der_len,
                                     &C1, &C2, &C2_len,
                                     &C3, &C3_len)) {
        fprintf(stderr, "  [SDFPROV] der_to_ecccipher: C1C3C2 decode FAILED\n");
        return 0;
    }

    fprintf(stderr, "  [SDFPROV] der_to_ecccipher: C1C3C2 decode C2_len=%zu C3_len=%zu\n",
            C2_len, C3_len);

    /*
     * 默认 Provider 的 SM2 加密使用 SM2_CiphertextEx (C1C2C3 格式),
     * 但 ossl_sm2_ciphertext_decode 按 SM2_Ciphertext (C1C3C2) 解码,
     * 导致 C2 和 C3 互换:
     *   - 如果实际格式是 C1C2C3, decode 返回 C2=实际C3(hash,32), C3=实际C2(密文)
     *   - 如果实际格式是 C1C3C2, decode 返回 C2=实际C2(密文), C3=实际C3(hash,32)
     * 判断依据: C3 应该是 32 字节的 SM3 hash
     */
    if (C3_len != 32 && C2_len == 32) {
        /* C1C2C3 格式: decode 的 C2 实际是 C3(hash), C3 实际是 C2(密文) */
        uint8_t *tmp_data = C2;
        size_t tmp_len = C2_len;
        C2 = C3;
        C2_len = C3_len;
        C3 = tmp_data;
        C3_len = tmp_len;
        fprintf(stderr, "  [SDFPROV] der_to_ecccipher: C1C2C3 format detected, swapped\n");
    }

    /* 创建 SM2 曲线组来提取坐标 */
    group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL)
        goto end;

    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL)
        goto end;

    if (!EC_POINT_get_affine_coordinates(group, C1, x, y, NULL))
        goto end;

    memset(cipher, 0, offsetof(OSSL_ECCCipher, C));
    BN_bn2binpad(x, cipher->x, OSSL_ECCref_MAX_LEN);
    BN_bn2binpad(y, cipher->y, OSSL_ECCref_MAX_LEN);

    /* C3(SM3 hash) -> M, C2(密文) -> C */
    if (C3_len <= 32)
        memcpy(cipher->M, C3, C3_len);

    cipher->L = (unsigned int)C2_len;
    if (C2_len > 0)
        memcpy(cipher->C, C2, C2_len);

    fprintf(stderr, "  [SDFPROV] der_to_ecccipher: final L=%u\n", cipher->L);
    ret = 1;

end:
    EC_GROUP_free(group);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(C1);
    OPENSSL_free(C2);
    OPENSSL_free(C3);
    return ret;
}
