/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated low-level EC APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <crypto/sm2.h>

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_NOOUT,
    OPT_TEXT, OPT_PRINT, OPT_PRINT_CERTS, OPT_QUIET,
    OPT_ENGINE, OPT_PROV_ENUM,
#ifndef OPENSSL_NO_SM2
    OPT_IN_SIGN_KEY_FORM, OPT_IN_SIGN_KEY,
    OPT_GMT0009, OPT_GMT0010, OPT_ENC_KEY_PRINT,
#endif
} OPTION_CHOICE;

const OPTIONS pkcs7_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif

    OPT_SECTION("Input"),
    {"in", OPT_IN, '<', "Input file"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},

    OPT_SECTION("Output"),
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"noout", OPT_NOOUT, '-', "Don't output encoded data"},
    {"text", OPT_TEXT, '-', "Print full details of certificates"},
    {"print", OPT_PRINT, '-', "Print out all fields of the PKCS7 structure"},
    {"print_certs", OPT_PRINT_CERTS, '-',
     "Print_certs  print any certs or crl in the input"},
    {"quiet", OPT_QUIET, '-',
     "When used with -print_certs, it produces a cleaner output"},

    OPT_PROV_OPTIONS,
#ifndef OPENSSL_NO_SM2
    {"in_sign_key_format", OPT_IN_SIGN_KEY_FORM, 'f',
     "GMT0009/0010 input sign key format - DER or PEM or ENGINE"},
    {"in_sign_key", OPT_IN_SIGN_KEY, '<',
     "GMT0009/0010 input the sign key"},
    {"GMT0009", OPT_GMT0009, '-', "Decode GMT 0009 enveloped key"},
    {"GMT0010", OPT_GMT0010, '-', "Decode GMT 0010 PKCS7 enveloped key"},
    {"enc_key_print", OPT_ENC_KEY_PRINT, '-',
     "Print the decrypted GMT0009/0010 key"},
#endif
    {NULL}
};

#ifndef OPENSSL_NO_SM2
static EVP_PKEY *pkcs7_gmt_decode_sm2_pkey(const unsigned char *key_text,
                                           size_t key_text_len)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *priv_key = NULL;
    EC_POINT *pub_key = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto err;

    eckey = EC_KEY_new_by_curve_name(NID_sm2);
    if (eckey == NULL)
        goto err;

    priv_key = BN_bin2bn(key_text, (int)key_text_len, NULL);
    if (priv_key == NULL)
        goto err;

    if (EC_KEY_set_private_key(eckey, priv_key) <= 0)
        goto err;

    pub_key = EC_POINT_new(EC_KEY_get0_group(eckey));
    if (pub_key == NULL)
        goto err;

    if (EC_POINT_mul(EC_KEY_get0_group(eckey), pub_key,
                     EC_KEY_get0_private_key(eckey), NULL, NULL, NULL) <= 0)
        goto err;

    if (EC_KEY_set_public_key(eckey, pub_key) <= 0)
        goto err;

    if (EVP_PKEY_set1_EC_KEY(pkey, eckey) <= 0)
        goto err;

    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2))
        goto err;

    EC_POINT_free(pub_key);
    BN_free(priv_key);
    EC_KEY_free(eckey);
    return pkey;

 err:
    EVP_PKEY_free(pkey);
    EC_POINT_free(pub_key);
    BN_free(priv_key);
    EC_KEY_free(eckey);
    return NULL;
}
#endif

int pkcs7_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    PKCS7 *p7 = NULL, *p7i;
    BIO *in = NULL, *out = NULL;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM;
#ifndef OPENSSL_NO_SM2
    int in_sign_key_format = FORMAT_PEM;
    char *in_sign_key = NULL;
    int gmt0009 = 0, gmt0010 = 0;
    int enc_key_print = 0;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    SM2_Enveloped_Key *sm2evpkey = NULL;
    EVP_PKEY *sign_pkey = NULL, *enc_pkey = NULL;
    BIO *bio_key = NULL;
    size_t key_text_len = 0;
    unsigned char key_text[128];
#endif
    char *infile = NULL, *outfile = NULL, *prog;
    int i, print_certs = 0, text = 0, noout = 0, p7_print = 0, quiet = 0, ret = 1;
    OPTION_CHOICE o;
    OSSL_LIB_CTX *libctx = app_get0_libctx();

    prog = opt_init(argc, argv, pkcs7_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkcs7_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
#ifndef OPENSSL_NO_SM2
        case OPT_IN_SIGN_KEY_FORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER | OPT_FMT_ENGINE,
                            &in_sign_key_format))
                goto opthelp;
            break;
        case OPT_IN_SIGN_KEY:
            in_sign_key = opt_arg();
            break;
        case OPT_GMT0009:
            gmt0009 = 1;
            break;
        case OPT_GMT0010:
            gmt0010 = 1;
            break;
        case OPT_ENC_KEY_PRINT:
            enc_key_print = 1;
            break;
#endif
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PRINT:
            p7_print = 1;
            break;
        case OPT_PRINT_CERTS:
            print_certs = 1;
            break;
        case OPT_QUIET:
            quiet = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        }
    }

    /* No extra arguments. */
    if (!opt_check_rest_arg(NULL))
        goto opthelp;

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;

#ifndef OPENSSL_NO_SM2
    if (gmt0009 && gmt0010) {
        BIO_printf(bio_err, "GMT0009 and GMT0010 cannot be used together\n");
        goto end;
    }

    if ((gmt0009 || gmt0010) && in_sign_key == NULL) {
        BIO_printf(bio_err, "missing -in_sign_key for GMT0009/0010 decode\n");
        goto end;
    }
#endif

    p7 = PKCS7_new_ex(libctx, app_get0_propq());
    if (p7 == NULL) {
        BIO_printf(bio_err, "unable to allocate PKCS7 object\n");
        ERR_print_errors(bio_err);
        goto end;
    }

#ifndef OPENSSL_NO_SM2
    if (gmt0009 || gmt0010) {
        sign_pkey = load_key(in_sign_key, in_sign_key_format, 1, NULL, e,
                             "Private Key");
        if (sign_pkey == NULL) {
            BIO_printf(bio_err, "unable to load Key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (gmt0009) {
        if (informat != FORMAT_ASN1) {
            BIO_printf(bio_err, "GMT0009 input format must be DER\n");
            goto end;
        }

        sm2evpkey = ASN1_item_d2i_bio(ASN1_ITEM_rptr(SM2_Enveloped_Key),
                                      in, NULL);
        if (sm2evpkey == NULL) {
            BIO_printf(bio_err, "unable to load sm2evpkey object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        bio_key = SM2_Enveloped_Key_dataDecode(sm2evpkey, sign_pkey);
        if (bio_key == NULL) {
            BIO_printf(bio_err, "unable to decode sm2evpkey object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (BIO_read_ex(bio_key, key_text, sizeof(key_text), &key_text_len) <= 0) {
            BIO_printf(bio_err, "sm2evpkey data error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (key_text_len != 32) {
            BIO_printf(bio_err, "key length error\n");
            goto end;
        }

        if (BIO_get_cipher_status(bio_key) <= 0) {
            BIO_printf(bio_err, "sm2evpkey cipher decrypt error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif

#ifndef OPENSSL_NO_SM2
    if (!gmt0009) {
#else
    {
#endif
        if (informat == FORMAT_ASN1)
            p7i = d2i_PKCS7_bio(in, &p7);
        else
            p7i = PEM_read_bio_PKCS7(in, &p7, NULL, NULL);
        if (p7i == NULL) {
            BIO_printf(bio_err, "unable to load PKCS7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

#ifndef OPENSSL_NO_SM2
    if (gmt0010) {
        bio_key = PKCS7_dataDecode(p7, sign_pkey, NULL, NULL);
        if (bio_key == NULL) {
            BIO_printf(bio_err, "unable to decode p7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (BIO_get_cipher_ctx(bio_key, &cipher_ctx) <= 0) {
            BIO_printf(bio_err, "unable to get cipher ctx\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (EVP_CIPHER_CTX_set_padding(cipher_ctx, 0) <= 0) {
            BIO_printf(bio_err, "unable to set padding\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (BIO_read_ex(bio_key, key_text, sizeof(key_text), &key_text_len) <= 0) {
            BIO_printf(bio_err, "pkcs7 read BIO error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (BIO_get_cipher_status(bio_key) <= 0) {
            BIO_printf(bio_err, "pkcs7 cipher decrypt error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (key_text_len >= 32) {
            memmove(key_text, key_text + key_text_len - 32, 32);
            key_text_len = 32;
        } else {
            BIO_printf(bio_err, "pkcs7 data error\n");
            goto end;
        }
    }
#endif

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

#ifndef OPENSSL_NO_SM2
    if (gmt0009 || gmt0010) {
        enc_pkey = pkcs7_gmt_decode_sm2_pkey(key_text, key_text_len);
        if (enc_pkey == NULL) {
            BIO_printf(bio_err, "unable to build SM2 key from decrypted data\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (!noout) {
            if (outformat == FORMAT_ASN1) {
                if (!i2d_PrivateKey_bio(out, enc_pkey))
                    goto end;
            } else {
                if (!PEM_write_bio_PrivateKey(out, enc_pkey, NULL, NULL, 0,
                                              NULL, NULL))
                    goto end;
            }
        }

        if (enc_key_print && EVP_PKEY_print_private(out, enc_pkey, 0, NULL) <= 0) {
            BIO_printf(bio_err, "enc pkey print error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (gmt0009) {
            ret = 0;
            goto end;
        }
    }
#endif

    if (p7_print)
        PKCS7_print_ctx(out, p7, 0, NULL);

    if (print_certs) {
        STACK_OF(X509) *certs = NULL;
        STACK_OF(X509_CRL) *crls = NULL;

        i = OBJ_obj2nid(p7->type);
        switch (i) {
        case NID_pkcs7_signed:
        case NID_pkcs7_sm2_signed:
            if (p7->d.sign != NULL) {
                certs = p7->d.sign->cert;
                crls = p7->d.sign->crl;
            }
            break;
        case NID_pkcs7_signedAndEnveloped:
        case NID_pkcs7_sm2_signedAndEnveloped:
            if (p7->d.signed_and_enveloped != NULL) {
                certs = p7->d.signed_and_enveloped->cert;
                crls = p7->d.signed_and_enveloped->crl;
            }
            break;
        default:
            break;
        }

        if (certs != NULL) {
            X509 *x;

            for (i = 0; i < sk_X509_num(certs); i++) {
                x = sk_X509_value(certs, i);
                if (text)
                    X509_print(out, x);
                else if (!quiet)
                    dump_cert_text(out, x);

                if (!noout)
                    PEM_write_bio_X509(out, x);
                BIO_puts(out, "\n");
            }
        }
        if (crls != NULL) {
            X509_CRL *crl;

            for (i = 0; i < sk_X509_CRL_num(crls); i++) {
                crl = sk_X509_CRL_value(crls, i);

                X509_CRL_print_ex(out, crl, get_nameopt());

                if (!noout)
                    PEM_write_bio_X509_CRL(out, crl);
                BIO_puts(out, "\n");
            }
        }

        ret = 0;
        goto end;
    }

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_PKCS7_bio(out, p7);
        else
            i = PEM_write_bio_PKCS7(out, p7);

        if (!i) {
            BIO_printf(bio_err, "unable to write pkcs7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    ret = 0;
 end:
    PKCS7_free(p7);
    release_engine(e);
#ifndef OPENSSL_NO_SM2
    BIO_free_all(bio_key);
    SM2_Enveloped_Key_free(sm2evpkey);
    EVP_PKEY_free(sign_pkey);
    EVP_PKEY_free(enc_pkey);
#endif
    BIO_free(in);
    BIO_free_all(out);
    return ret;
}
