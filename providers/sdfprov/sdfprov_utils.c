/*
 * SDF Provider Utility Functions
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/proverr.h>
#include <openssl/tsapi.h>
#include <openssl/crypto.h>
#include "sdfprov_utils.h"
#include "crypto/sm2.h"

static const unsigned char *sdfprov_rsa_select_modulus_window(const unsigned char *buf,
                                                              size_t field_len,
                                                              size_t nbytes);
static BIGNUM *sdfprov_rsa_make_bn_trimmed(const unsigned char *buf, size_t len);
extern SM2_CiphertextEx *SM2_Ciphertext_to_SM2_CiphertextEx(
    const SM2_Ciphertext *c1c3c2);

static char *sdfprov_next_token(char **cursor, const char *delim)
{
    char *start;
    char *end;

    if (cursor == NULL || *cursor == NULL)
        return NULL;

    start = *cursor;
    end = start + strcspn(start, delim);
    if (*end == '\0') {
        *cursor = NULL;
    } else {
        *end = '\0';
        *cursor = end + 1;
    }
    return start;
}

/*
 * 解析 session 地址字符串。
 * 支持：
 *   "12345678"
 *   "0x12345678"
 *   "session:12345678"
 */
static int sdfprov_parse_session_value(const char *value, void **session)
{
    unsigned long long raw;
    char *endp = NULL;

    if (value == NULL || session == NULL)
        return 0;

    if (strncmp(value, "session:", 8) == 0)
        value += 8;

    if (*value == '\0')
        return 0;

    raw = strtoull(value, &endp, 0);
    if (endp == NULL || *endp != '\0')
        return 0;

    *session = (void *)(uintptr_t)raw;
    return 1;
}

/*
 * 解析老格式 URI 末尾的可选参数。
 * 兼容：
 *   :<pwd>
 *   :session:<addr>
 *   :<pwd>:session:<addr>
 */
static int sdfprov_parse_old_uri_tail(const char *tail, char **key_password,
                                      void **session, int *external_session)
{
    char *tail_dup = NULL;
    char *cursor = NULL;
    char *token = NULL;
    int ok = 1;

    if (tail == NULL || *tail == '\0')
        return 1;

    tail_dup = OPENSSL_strdup(tail);
    if (tail_dup == NULL)
        return 0;

    cursor = tail_dup;
    while ((token = sdfprov_next_token(&cursor, ":")) != NULL) {
        if (*token == '\0')
            continue;
        if (strncmp(token, "session=", 8) == 0) {
            if (!sdfprov_parse_session_value(token + 8, session))
                ok = 0;
            else
                *external_session = 1;
            break;
        }
        if (strcmp(token, "session") == 0 && cursor != NULL) {
            if (!sdfprov_parse_session_value(cursor, session))
                ok = 0;
            else
                *external_session = 1;
            break;
        }
        if (*key_password == NULL) {
            *key_password = OPENSSL_strdup(token);
            if (*key_password == NULL)
                ok = 0;
        }
    }

    OPENSSL_free(tail_dup);
    return ok;
}

/* 解析老 Engine 风格 URI: sdf:<algo>:<index>:<type>[:<pwd>] */
static int sdfprov_parse_old_uri(const char *p, SDFPROV_KEY_URI *info)
{
    char *endp = NULL;
    const char *tail = NULL;

    if (strncmp(p, "sm2:", 4) == 0) {
        info->algo = SDF_ALGO_SM2;
        p += 4;
    } else if (strncmp(p, "rsa:", 4) == 0) {
        info->algo = SDF_ALGO_RSA;
        p += 4;
    } else {
        return 0;
    }

    info->key_index = (unsigned int)strtoul(p, &endp, 10);
    if (endp == NULL || *endp != ':')
        return 0;
    p = endp + 1;

    if (strncmp(p, "sign", 4) == 0 && (p[4] == '\0' || p[4] == ':')) {
        info->key_type = 0;
        tail = p + 4;
    } else if (strncmp(p, "enc", 3) == 0 && (p[3] == '\0' || p[3] == ':')) {
        info->key_type = 1;
        tail = p + 3;
    } else {
        return 0;
    }

    if (tail != NULL && *tail == ':')
        tail++;

    return sdfprov_parse_old_uri_tail(tail, &info->key_password,
                                      &info->session,
                                      &info->external_session);
}

/*
 * 解析 key=value 风格 URI：
 *   sdf:key=<index>;type=<sign|enc>[;algo=<sm2|rsa>][;pwd=<password>][;session=<addr>]
 */
static int sdfprov_parse_kv_uri(const char *p, SDFPROV_KEY_URI *info)
{
    char *uri_dup = NULL;
    char *cursor = NULL;
    char *item = NULL;
    int saw_key = 0;
    int saw_type = 0;
    int ok = 1;

    uri_dup = OPENSSL_strdup(p);
    if (uri_dup == NULL)
        return 0;

    info->algo = SDF_ALGO_SM2;
    cursor = uri_dup;

    while ((item = sdfprov_next_token(&cursor, ";&")) != NULL) {
        char *eq = NULL;
        if (*item == '\0')
            continue;
        eq = strchr(item, '=');
        if (eq == NULL)
            continue;
        *eq++ = '\0';

        if (strcmp(item, "key") == 0 || strcmp(item, "index") == 0) {
            char *endp = NULL;
            info->key_index = (unsigned int)strtoul(eq, &endp, 10);
            if (endp == NULL || *endp != '\0') {
                ok = 0;
                break;
            }
            saw_key = 1;
        } else if (strcmp(item, "type") == 0) {
            if (strcmp(eq, "sign") == 0 || strcmp(eq, "0") == 0) {
                info->key_type = 0;
            } else if (strcmp(eq, "enc") == 0 || strcmp(eq, "1") == 0) {
                info->key_type = 1;
            } else {
                ok = 0;
                break;
            }
            saw_type = 1;
        } else if (strcmp(item, "algo") == 0) {
            if (strcmp(eq, "sm2") == 0)
                info->algo = SDF_ALGO_SM2;
            else if (strcmp(eq, "rsa") == 0)
                info->algo = SDF_ALGO_RSA;
            else {
                ok = 0;
                break;
            }
        } else if (strcmp(item, "pwd") == 0) {
            OPENSSL_free(info->key_password);
            info->key_password = OPENSSL_strdup(eq);
            if (info->key_password == NULL) {
                ok = 0;
                break;
            }
        } else if (strcmp(item, "session") == 0) {
            if (!sdfprov_parse_session_value(eq, &info->session)) {
                ok = 0;
                break;
            }
            info->external_session = 1;
        }
    }

    OPENSSL_free(uri_dup);
    return ok && saw_key && saw_type;
}

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
    unsigned char *der = NULL;
    BIGNUM *x = NULL, *y = NULL;
    ASN1_OCTET_STRING *c2 = NULL, *c3 = NULL;
    SM2_Ciphertext *ct = NULL;
    SM2_CiphertextEx *ctex = NULL;
    int der_len;
    int ret = 0;

    if (cipher == NULL || out == NULL || out_len == NULL)
        return 0;

    /*
     * encdata_format 语义必须与 crypto/sm2 保持一致:
     *   0 = C1C2C3 (SM2_CiphertextEx，Tongsuo 默认)
     *   1 = C1C3C2 (SM2_Ciphertext，GM/T 0009 标准格式)
     */
    if (encdata_format == 1) {
        /*
         * TSAPI_ECCCipher_to_SM2Ciphertext() 固定生成 SM2_Ciphertext，
         * 字段顺序为 C1x, C1y, C3, C2，即 C1C3C2。
         */
        der = TSAPI_ECCCipher_to_SM2Ciphertext(cipher, out_len);
        if (der == NULL)
            return 0;

        *out = der;
        return 1;
    }

    /*
     * encdata_format=0 时需要输出 C1C2C3。这里先构造标准
     * SM2_Ciphertext(C1C3C2)，再复用 crypto/sm2 中已有转换函数
     * 转成 SM2_CiphertextEx(C1C2C3) 后 DER 编码。
     */
    x = BN_bin2bn(cipher->x, sizeof(cipher->x), NULL);
    y = BN_bin2bn(cipher->y, sizeof(cipher->y), NULL);
    c2 = ASN1_OCTET_STRING_new();
    c3 = ASN1_OCTET_STRING_new();
    ct = SM2_Ciphertext_new();

    if (x == NULL || y == NULL || c2 == NULL || c3 == NULL || ct == NULL)
        goto end;

    if (!ASN1_OCTET_STRING_set(c2, cipher->C, cipher->L)
        || !ASN1_OCTET_STRING_set(c3, cipher->M, sizeof(cipher->M)))
        goto end;

    if (!SM2_Ciphertext_set0(ct, x, y, c3, c2))
        goto end;
    x = y = NULL;
    c2 = c3 = NULL;

    ctex = SM2_Ciphertext_to_SM2_CiphertextEx(ct);
    if (ctex == NULL)
        goto end;

    der_len = i2d_SM2_CiphertextEx(ctex, NULL);
    if (der_len <= 0)
        goto end;

    der = OPENSSL_malloc(der_len);
    if (der == NULL)
        goto end;

    {
        unsigned char *p = der;
        if (i2d_SM2_CiphertextEx(ctex, &p) != der_len)
            goto end;
    }

    *out = der;
    *out_len = (size_t)der_len;
    der = NULL;
    ret = 1;

end:
    OPENSSL_free(der);
    BN_free(x);
    BN_free(y);
    ASN1_OCTET_STRING_free(c2);
    ASN1_OCTET_STRING_free(c3);
    SM2_Ciphertext_free(ct);
    SM2_CiphertextEx_free(ctex);
    return ret;
}

int sdfprov_sm2_der_to_ecccipher(const unsigned char *der, size_t der_len,
                                 OSSL_ECCCipher *cipher,
                                 int encdata_format,
                                 size_t cipher_buf_size)
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
        return 0;
    }

    /*
     * encdata_format 语义必须与 crypto/sm2 保持一致:
     *   0 = C1C2C3 (SM2_CiphertextEx，Tongsuo 默认)
     *   1 = C1C3C2 (SM2_Ciphertext，GM/T 0009 标准格式)
     *
     * 当前解码函数 ossl_sm2_ciphertext_decode() 按 SM2_Ciphertext
     * 结构解析，也就是按 C1x, C1y, C3, C2 读取。
     *
     * 因此:
     *   - 输入实际为 C1C3C2 时，C2/C3 已经在正确位置，不需要交换。
     *   - 输入实际为 C1C2C3 时，按 C1C3C2 解码后 C2/C3 会反，需要交换回来。
     */
    if (encdata_format == 0) {
        /* C1C2C3 格式: decode 的 C2 实际是 C3(hash), C3 实际是 C2(密文), 需要交换 */
        uint8_t *tmp_data = C2;
        size_t tmp_len = C2_len;
        C2 = C3;
        C2_len = C3_len;
        C3 = tmp_data;
        C3_len = tmp_len;
    }

    /* 验证 C2_len 不超过分配的缓冲区大小 */
    if (C2_len > cipher_buf_size) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_DECRYPT,
                       "C2_len (%zu) exceeds buffer (%zu)", C2_len, cipher_buf_size);
        goto end;
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

int sdfprov_parse_key_uri(const char *uri, SDFPROV_KEY_URI *info)
{
    if (uri == NULL || info == NULL || strncmp(uri, "sdf:", 4) != 0)
        return 0;

    memset(info, 0, sizeof(*info));

    if (strncmp(uri + 4, "key=", 4) == 0 || strncmp(uri + 4, "index=", 6) == 0)
        return sdfprov_parse_kv_uri(uri + 4, info);

    return sdfprov_parse_old_uri(uri + 4, info);
}

/* 释放 URI 解析结果中动态分配的字段。 */
void sdfprov_key_uri_cleanup(SDFPROV_KEY_URI *info)
{
    if (info == NULL)
        return;
    OPENSSL_free(info->key_password);
    memset(info, 0, sizeof(*info));
}

/* 统一把解析结果格式化为 KEYMGMT load 使用的 reference。 */
int sdfprov_format_key_reference(char *buf, size_t buf_size,
                                 const SDFPROV_KEY_URI *info)
{
    const char *algo_name;
    int len;

    if (buf == NULL || info == NULL)
        return 0;

    algo_name = info->algo == SDF_ALGO_RSA ? "rsa" : "sm2";

    len = snprintf(buf, buf_size, "sdf:key=%u;type=%s;algo=%s",
                   info->key_index,
                   info->key_type == 0 ? "sign" : "enc",
                   algo_name);
    if (len <= 0 || (size_t)len >= buf_size)
        return 0;

    if (info->key_password != NULL) {
        len += snprintf(buf + len, buf_size - (size_t)len,
                        ";pwd=%s", info->key_password);
        if ((size_t)len >= buf_size)
            return 0;
    }

    if (info->external_session) {
        len += snprintf(buf + len, buf_size - (size_t)len,
                        ";session=0x%llx",
                        (unsigned long long)(uintptr_t)info->session);
        if ((size_t)len >= buf_size)
            return 0;
    }

    return 1;
}

/* 把 2048 位 RSA 公钥结构转换成 OpenSSL RSA 对象。 */
int sdfprov_rsa_pubkey_to_rsa(const OSSL_RSArefPublicKey *pub, RSA **rsa)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    RSA *tmp = NULL;
    int nbytes;
    int ret = 0;
    const unsigned char *m_ptr;

    if (pub == NULL || rsa == NULL || pub->bits == 0)
        return 0;

    nbytes = (int)((pub->bits + 7) / 8);
    if (nbytes <= 0 || nbytes > OSSL_RSAref_MAX_LEN)
        return 0;

    m_ptr = sdfprov_rsa_select_modulus_window(pub->m, OSSL_RSAref_MAX_LEN,
                                              (size_t)nbytes);
    n = BN_bin2bn(m_ptr, nbytes, NULL);
    e = sdfprov_rsa_make_bn_trimmed(pub->e, OSSL_RSAref_MAX_LEN);
    tmp = RSA_new();
    if (n == NULL || e == NULL || tmp == NULL)
        goto end;

    if (!RSA_set0_key(tmp, n, e, NULL))
        goto end;
    n = e = NULL;

    *rsa = tmp;
    tmp = NULL;
    ret = 1;
end:
    BN_free(n);
    BN_free(e);
    RSA_free(tmp);
    return ret;
}

/* 把 4096 位扩展 RSA 公钥结构转换成 OpenSSL RSA 对象。 */
int sdfprov_rsa_pubkeyex_to_rsa(const OSSL_RSArefPublicKeyEx *pub, RSA **rsa)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    RSA *tmp = NULL;
    int nbytes;
    int ret = 0;
    const unsigned char *m_ptr;

    if (pub == NULL || rsa == NULL || pub->bits == 0)
        return 0;

    nbytes = (int)((pub->bits + 7) / 8);
    if (nbytes <= 0 || nbytes > OSSL_RSAref_MAX_LEN_EX)
        return 0;

    m_ptr = sdfprov_rsa_select_modulus_window(pub->m, OSSL_RSAref_MAX_LEN_EX,
                                              (size_t)nbytes);
    n = BN_bin2bn(m_ptr, nbytes, NULL);
    e = sdfprov_rsa_make_bn_trimmed(pub->e, OSSL_RSAref_MAX_LEN_EX);
    tmp = RSA_new();
    if (n == NULL || e == NULL || tmp == NULL)
        goto end;

    if (!RSA_set0_key(tmp, n, e, NULL))
        goto end;
    n = e = NULL;

    *rsa = tmp;
    tmp = NULL;
    ret = 1;
end:
    BN_free(n);
    BN_free(e);
    RSA_free(tmp);
    return ret;
}

int sdfprov_rsa_to_pubkey(const RSA *rsa, OSSL_RSArefPublicKey *pub)
{
    const BIGNUM *n = NULL, *e = NULL;
    int nbytes;

    if (rsa == NULL || pub == NULL)
        return 0;

    RSA_get0_key(rsa, &n, &e, NULL);
    if (n == NULL || e == NULL)
        return 0;

    nbytes = BN_num_bytes(n);
    if (nbytes <= 0 || nbytes > OSSL_RSAref_MAX_LEN)
        return 0;

    memset(pub, 0, sizeof(*pub));
    pub->bits = (unsigned int)RSA_bits(rsa);
    if (BN_bn2binpad(n, pub->m + (OSSL_RSAref_MAX_LEN - nbytes), nbytes) != nbytes)
        return 0;
    if (BN_bn2binpad(e, pub->e, OSSL_RSAref_MAX_LEN) < 0)
        return 0;
    return 1;
}

static const unsigned char *sdfprov_rsa_select_modulus_window(const unsigned char *buf,
                                                              size_t field_len,
                                                              size_t nbytes)
{
    const unsigned char *tail = buf + (field_len - nbytes);
    size_t i;

    for (i = 0; i < nbytes; i++) {
        if (tail[i] != 0)
            return tail;
    }
    return buf;
}

static BIGNUM *sdfprov_rsa_make_bn_trimmed(const unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len && buf[off] == 0)
        off++;
    if (off == len)
        return NULL;
    return BN_bin2bn(buf + off, (int)(len - off), NULL);
}

int sdfprov_rsa_to_pubkeyex(const RSA *rsa, OSSL_RSArefPublicKeyEx *pub)
{
    const BIGNUM *n = NULL, *e = NULL;
    int nbytes;

    if (rsa == NULL || pub == NULL)
        return 0;

    RSA_get0_key(rsa, &n, &e, NULL);
    if (n == NULL || e == NULL)
        return 0;

    nbytes = BN_num_bytes(n);
    if (nbytes <= 0 || nbytes > OSSL_RSAref_MAX_LEN_EX)
        return 0;

    memset(pub, 0, sizeof(*pub));
    pub->bits = (unsigned int)RSA_bits(rsa);
    if (BN_bn2binpad(n, pub->m + (OSSL_RSAref_MAX_LEN_EX - nbytes), nbytes) != nbytes)
        return 0;
    if (BN_bn2binpad(e, pub->e, OSSL_RSAref_MAX_LEN_EX) < 0)
        return 0;
    return 1;
}
