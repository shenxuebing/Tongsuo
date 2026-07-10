/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROVIDERS_SDFPROV_UTILS_H
# define OSSL_PROVIDERS_SDFPROV_UTILS_H

# include <stdint.h>
# include <openssl/ec.h>
# include <openssl/rsa.h>
# include <openssl/sdf.h>
# include "crypto/sdf/sdf_local.h"
# include "sdfprov_internal.h"

typedef struct {
    unsigned int key_index;
    int key_type;
    int algo;
    char *key_password;
    void *session;
    int external_session;
} SDFPROV_KEY_URI;

/* ECCrefPublicKey -> EC_KEY 公钥点 */
int sdfprov_eccrefpub_to_ec_key(const OSSL_ECCrefPublicKey *pub,
                                EC_KEY *ec_key);

/* EC_KEY 公钥点 -> ECCrefPublicKey */
int sdfprov_ec_key_to_eccrefpub(const EC_KEY *ec_key,
                                OSSL_ECCrefPublicKey *pub);

/* OSSL_ECCSignature (r[64]||s[64]) -> DER 编码签名 */
int sdfprov_eccsig_to_der(const OSSL_ECCSignature *sig,
                          unsigned char **out, size_t *out_len);

/* DER 编码签名 -> OSSL_ECCSignature */
int sdfprov_der_to_eccsig(const unsigned char *der, size_t der_len,
                          OSSL_ECCSignature *sig);

/* OSSL_ECCCipher -> SM2 密文 DER (C1C3C2 或 C1C2C3) */
int sdfprov_ecccipher_to_sm2_der(const OSSL_ECCCipher *cipher,
                                 unsigned char **out, size_t *out_len,
                                 int encdata_format);

/* SM2 密文 DER -> OSSL_ECCCipher
 * cipher_buf_size: cipher->C 缓冲区可用字节数，用于边界检查
 */
int sdfprov_sm2_der_to_ecccipher(const unsigned char *der, size_t der_len,
                                 OSSL_ECCCipher *cipher,
                                 int encdata_format,
                                 size_t cipher_buf_size);

int sdfprov_parse_key_uri(const char *uri, SDFPROV_KEY_URI *info);
void sdfprov_key_uri_cleanup(SDFPROV_KEY_URI *info);
int sdfprov_format_key_reference(char *buf, size_t buf_size,
                                 const SDFPROV_KEY_URI *info);
int sdfprov_rsa_pubkey_to_rsa(const OSSL_RSArefPublicKey *pub, RSA **rsa);
int sdfprov_rsa_pubkeyex_to_rsa(const OSSL_RSArefPublicKeyEx *pub, RSA **rsa);
int sdfprov_rsa_to_pubkey(const RSA *rsa, OSSL_RSArefPublicKey *pub);
int sdfprov_rsa_to_pubkeyex(const RSA *rsa, OSSL_RSArefPublicKeyEx *pub);

#endif
