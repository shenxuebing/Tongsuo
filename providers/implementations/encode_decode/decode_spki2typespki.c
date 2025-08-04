/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/asn1t.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include "internal/sizes.h"
#include "crypto/x509.h"
#include "crypto/ec.h"
#include "crypto/evp.h"
#include "prov/bio.h"
#include "prov/implementations.h"
#include "endecoder_local.h"

static OSSL_FUNC_decoder_newctx_fn spki2typespki_newctx;
static OSSL_FUNC_decoder_freectx_fn spki2typespki_freectx;
static OSSL_FUNC_decoder_decode_fn spki2typespki_decode;

/*
 * Context used for SubjectPublicKeyInfo to Type specific SubjectPublicKeyInfo
 * decoding.
 */
struct spki2typespki_ctx_st {
    PROV_CTX *provctx;
};

static void *spki2typespki_newctx(void *provctx)
{
    struct spki2typespki_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void spki2typespki_freectx(void *vctx)
{
    struct spki2typespki_ctx_st *ctx = vctx;

    OPENSSL_free(ctx);
}

static int spki2typespki_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                                OSSL_CALLBACK *data_cb, void *data_cbarg,
                                OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct spki2typespki_ctx_st *ctx = vctx;
    unsigned char *der, *derp;
    long len;
    int ok = 0;
    int objtype = OSSL_OBJECT_PKEY;
    X509_PUBKEY *xpub = NULL;
    X509_ALGOR *algor = NULL;
    const ASN1_OBJECT *oid = NULL;
    char dataname[OSSL_MAX_NAME_SIZE];
    OSSL_PARAM params[5], *p = params;

    if (!ossl_read_der(ctx->provctx, cin, &der, &len))
        return 1;
    derp = der;
    xpub = ossl_d2i_X509_PUBKEY_INTERNAL((const unsigned char **)&derp, len,
                                         PROV_LIBCTX_OF(ctx->provctx));


    if (xpub == NULL) {
        //int ret = 0;
        //const unsigned char *p8_data = der;
        //const unsigned char *ec_data = der;
        //PKCS8_PRIV_KEY_INFO* p8inf = NULL;
        //EC_KEY* eckey = NULL;
        //EVP_PKEY* pkey = NULL;
        //
        ///* First try to parse as PKCS8 private key info */
        //p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p8_data, len);
        //if (p8inf != NULL) {
        //    /* Clear any previous errors before attempting parsing */
        //    ERR_clear_error();
        //    
        //    /* Directly extract the private key data from PKCS8 */
        //    const ASN1_OBJECT *algoid = NULL;
        //    const void *algp = NULL;
        //    int algptype;
        //    const unsigned char *pk = NULL;
        //    int pklen = 0;
        //    
        //    if (PKCS8_pkey_get0(&algoid, &pk, &pklen, &algp, p8inf)) {
        //        int pkey_id = OBJ_obj2nid(algoid);
        //        
        //        /* Handle EC/SM2 keys */
        //        if (pkey_id == NID_X9_62_id_ecPublicKey) {
        //            /* Parse the EC private key directly */
        //            const unsigned char *p = pk;
        //            eckey = d2i_ECPrivateKey(NULL, &p, pklen);
        //            if (eckey != NULL) {
        //                /* Check if this is SM2 by looking at the algorithm parameters */
        //                if (algp != NULL) {
        //                    const unsigned char *palg = algp;
        //                    ASN1_OBJECT *poid = d2i_ASN1_OBJECT(NULL, &palg, -1);
        //                    if (poid != NULL) {
        //                        if (OBJ_obj2nid(poid) == NID_sm2) {
        //                            EC_KEY_set_flags(eckey, EC_FLAG_SM2_RANGE);
        //                        }
        //                        ASN1_OBJECT_free(poid);
        //                    }
        //                }
        //                
        //                /* Create EVP_PKEY from EC_KEY */
        //                pkey = EVP_PKEY_new();
        //                if (pkey != NULL && EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
        //                    /* Successfully converted EC_KEY to EVP_PKEY, now create X509_PUBKEY */
        //                    if (X509_PUBKEY_set(&xpub, pkey)) {
        //                        ret = 1;
        //                    }
        //                    EVP_PKEY_free(pkey); /* This will also free eckey */
        //                    eckey = NULL;
        //                }
        //                if (eckey != NULL) {
        //                    EC_KEY_free(eckey);
        //                }
        //            }
        //        }
        //        /* Handle RSA keys */
        //        //else if (pkey_id == NID_rsaEncryption) {
        //        //    const unsigned char *p = pk;
        //        //    RSA *rsa = d2i_RSAPrivateKey(NULL, &p, pklen);
        //        //    if (rsa != NULL) {
        //        //        pkey = EVP_PKEY_new();
        //        //        if (pkey != NULL && EVP_PKEY_assign_RSA(pkey, rsa)) {
        //        //            if (X509_PUBKEY_set(&xpub, pkey)) {
        //        //                ret = 1;
        //        //            }
        //        //            EVP_PKEY_free(pkey); /* This will also free rsa */
        //        //        } else {
        //        //            RSA_free(rsa);
        //        //        }
        //        //    }
        //        //}
        //        ///* Handle DSA keys */
        //        //else if (pkey_id == NID_dsa) {
        //        //    const unsigned char *p = pk;
        //        //    DSA *dsa = d2i_DSAPrivateKey(NULL, &p, pklen);
        //        //    if (dsa != NULL) {
        //        //        pkey = EVP_PKEY_new();
        //        //        if (pkey != NULL && EVP_PKEY_assign_DSA(pkey, dsa)) {
        //        //            if (X509_PUBKEY_set(&xpub, pkey)) {
        //        //                ret = 1;
        //        //            }
        //        //            EVP_PKEY_free(pkey); /* This will also free dsa */
        //        //        } else {
        //        //            DSA_free(dsa);
        //        //        }
        //        //    }
        //        //}
        //    }
        //    PKCS8_PRIV_KEY_INFO_free(p8inf);
        //}
        //
        ///* If PKCS8 parsing failed, try to parse as EC_PRIVATEKEY directly */
        //if (!ret) {
        //    eckey = d2i_ECPrivateKey(NULL, &ec_data, len);
        //    if (eckey != NULL) {
        //        /* Create EVP_PKEY from EC_KEY */
        //        pkey = EVP_PKEY_new();
        //        if (pkey != NULL && EVP_PKEY_assign_EC_KEY(pkey, eckey)) {
        //            /* Successfully converted EC_KEY to EVP_PKEY, now create X509_PUBKEY */
        //            if (X509_PUBKEY_set(&xpub, pkey)) {
        //                ret = 1;
        //            }
        //            EVP_PKEY_free(pkey); /* This will also free eckey */
        //        } else {
        //            EC_KEY_free(eckey);
        //            EVP_PKEY_free(pkey);
        //        }
        //    }
        //}
        //
        //if (!ret) {
            /* We return "empty handed".  This is not an error. */
            ok = 1;
            goto end;
        }
    //}

    if (!X509_PUBKEY_get0_param(NULL, NULL, NULL, &algor, xpub))
        goto end;
    X509_ALGOR_get0(&oid, NULL, NULL, algor);

#ifndef OPENSSL_NO_EC
    /* SM2 abuses the EC oid, so this could actually be SM2 */
    if (OBJ_obj2nid(oid) == NID_X9_62_id_ecPublicKey
            && ossl_x509_algor_is_sm2(algor))
        strcpy(dataname, "SM2");
    else
#endif
    if (OBJ_obj2txt(dataname, sizeof(dataname), oid, 0) <= 0)
        goto end;

    ossl_X509_PUBKEY_INTERNAL_free(xpub);
    xpub = NULL;

    *p++ =
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                            dataname, 0);

    *p++ =
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                            "SubjectPublicKeyInfo",
                                            0);
    *p++ =
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der, len);
    *p++ =
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);

    *p = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);

 end:
    ossl_X509_PUBKEY_INTERNAL_free(xpub);
    OPENSSL_free(der);
    return ok;
}

const OSSL_DISPATCH ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))spki2typespki_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))spki2typespki_freectx },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))spki2typespki_decode },
    { 0, NULL }
};

