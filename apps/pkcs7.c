/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated low-level EC APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <crypto/sm2.h>

/*============================================================
 * PKCS7 操作模式（参考 apps/smime.c 与 apps/cms.c 的实现）
 *
 * SMIME_OP     : 输出类操作（签名、加密）
 * SMIME_IP     : 输入类操作（验签、解密）
 * SMIME_SIGNERS: 涉及签名者密钥的操作
 *============================================================*/
#define SMIME_OP        0x10
#define SMIME_IP        0x20
#define SMIME_SIGNERS   0x40
#define SMIME_ENCRYPT   (1 | SMIME_OP)
#define SMIME_DECRYPT   (2 | SMIME_IP)
#define SMIME_SIGN      (3 | SMIME_OP | SMIME_SIGNERS)
#define SMIME_VERIFY    (4 | SMIME_IP)
#define SMIME_RESIGN    (6 | SMIME_IP | SMIME_OP | SMIME_SIGNERS)
#define SMIME_PK7OUT    (5 | SMIME_IP | SMIME_OP)

static int save_certs(char *signerfile, STACK_OF(X509) *signers);
static int pkcs7_cb(int ok, X509_STORE_CTX *ctx);

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_NOOUT,
    OPT_TEXT, OPT_PRINT, OPT_PRINT_CERTS, OPT_QUIET,

    /* P7 操作（参考 smime/cms） */
    OPT_SIGN, OPT_VERIFY, OPT_ENCRYPT, OPT_DECRYPT, OPT_RESIGN,
    OPT_SIGNER, OPT_RECIP, OPT_INKEY, OPT_KEYFORM, OPT_PASSIN,
    OPT_MD, OPT_CIPHER,
    OPT_DETACHED, OPT_NODETACH, OPT_NOCERTS, OPT_NOATTR, OPT_NOSMIMECAP,
    OPT_BINARY, OPT_NOSIGS, OPT_NOINTERN, OPT_NOVERIFY, OPT_NOCHAIN,
    OPT_CRLFEOL, OPT_STREAM, OPT_INDEF, OPT_NOINDEF,
    OPT_CERTFILE, OPT_CONTENT,
    OPT_TO, OPT_FROM, OPT_SUBJECT,
    OPT_CAFILE, OPT_CAPATH, OPT_CASTORE,
    OPT_NOCAFILE, OPT_NOCAPATH, OPT_NOCASTORE,
    OPT_GMT0010_SIGN, OPT_SM2_HASH, OPT_SM2_ADDHASH_Z,

    OPT_ENGINE, OPT_R_ENUM, OPT_PROV_ENUM, OPT_V_ENUM, OPT_CONFIG,

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
    OPT_CONFIG_OPTION,

    OPT_SECTION("Input"),
    {"in", OPT_IN, '<', "Input file"},
    {"inform", OPT_INFORM, 'F',
     "Input format - DER or PEM (default) or SMIME"},
    {"inkey", OPT_INKEY, 's',
     "Input private key (if not signer or recipient). "
     "Supports file/ENGINE/Provider URI (e.g. sdf:sm2:0:sign:11111111)"},
    {"keyform", OPT_KEYFORM, 'f',
     "Input private key format (PEM, DER, ENGINE; URI auto-detected)"},

    OPT_SECTION("Output"),
    {"outform", OPT_OUTFORM, 'F',
     "Output format - DER or PEM (default) or SMIME"},
    {"out", OPT_OUT, '>', "Output file"},
    {"noout", OPT_NOOUT, '-', "Don't output encoded data"},
    {"text", OPT_TEXT, '-', "Include or delete text MIME headers"},
    {"print", OPT_PRINT, '-', "Print out all fields of the PKCS7 structure"},
    {"print_certs", OPT_PRINT_CERTS, '-',
     "Print_certs  print any certs or crl in the input"},
    {"quiet", OPT_QUIET, '-',
     "When used with -print_certs, it produces a cleaner output"},

    OPT_SECTION("Action"),
    {"sign", OPT_SIGN, '-', "Sign message"},
    {"verify", OPT_VERIFY, '-', "Verify signed message"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt message (digital envelope)"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt encrypted message"},
    {"resign", OPT_RESIGN, '-', "Resign a signed message"},

    OPT_SECTION("Signing/Encryption"),
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"md", OPT_MD, 's', "Digest algorithm to use when signing (default sm3 for SM2)"},
    {"", OPT_CIPHER, '-', "Any supported cipher (default sm4-ecb for SM2 envelope)"},
    {"signer", OPT_SIGNER, 's', "Signer certificate file (local file)"},
    {"recip", OPT_RECIP, '<', "Recipient certificate file (local file)"},
    {"content", OPT_CONTENT, '<',
     "Supply or override content for detached signature"},
    {"certfile", OPT_CERTFILE, '<',
     "Extra signer and intermediate CA certificates to include when signing"},
    {"nodetach", OPT_NODETACH, '-', "Use opaque signing (default: detached)"},
    {"detached", OPT_DETACHED, '-', "Use detached signing"},
    {"nocerts", OPT_NOCERTS, '-', "Don't include signers certificate when signing"},
    {"noattr", OPT_NOATTR, '-', "Don't include any signed attributes"},
    {"binary", OPT_BINARY, '-', "Don't translate message to text"},
    {"nosmimecap", OPT_NOSMIMECAP, '-',
     "Omit the SMIMECapabilities attribute (default for sign)"},
    {"gmt0010", OPT_GMT0010_SIGN, '-',
     "Use GMT0010 SM2 PKCS7 OID (sm2-signedData/sm2-data). "
     "Required for SM2 hardware/software keys"},
    {"sm2_hash", OPT_SM2_HASH, '-',
     "SM2 external hash mode: message is already a hash value"},
    {"sm2_addhash_z", OPT_SM2_ADDHASH_Z, '-',
     "SM2 mode: compute Z value and prepend to digest in PKCS7 structure"},
    {"nointern", OPT_NOINTERN, '-',
     "Don't search certificates in message for signer"},

    OPT_SECTION("Verification/Decryption"),
    {"nosigs", OPT_NOSIGS, '-', "Don't verify message signature"},
    {"noverify", OPT_NOVERIFY, '-', "Don't verify signers certificate"},
    {"nochain", OPT_NOCHAIN, '-',
     "Don't use certs in message as untrusted CAs"},
    {"stream", OPT_STREAM, '-', "Enable streaming"},
    {"indef", OPT_INDEF, '-', "Same as -stream"},
    {"noindef", OPT_NOINDEF, '-', "Disable streaming"},
    {"crlfeol", OPT_CRLFEOL, '-', "Use CRLF as EOL instead of LF only"},

    OPT_SECTION("Email (SMIME output only)"),
    {"to", OPT_TO, 's', "To address"},
    {"from", OPT_FROM, 's', "From address"},
    {"subject", OPT_SUBJECT, 's', "Subject"},

    OPT_SECTION("Certificate chain (verification)"),
    {"CApath", OPT_CAPATH, '/', "Trusted certificates directory"},
    {"CAfile", OPT_CAFILE, '<', "Trusted certificates file"},
    {"CAstore", OPT_CASTORE, ':', "Trusted certificates store URI"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"no-CAstore", OPT_NOCASTORE, '-',
     "Do not load certificates from the default certificates store"},

    OPT_R_OPTIONS,
    OPT_V_OPTIONS,
    OPT_PROV_OPTIONS,

#ifndef OPENSSL_NO_SM2
    OPT_SECTION("GMT0009/0010 (SM2 Enveloped Key decode)"),
    {"in_sign_key_format", OPT_IN_SIGN_KEY_FORM, 'f',
     "GMT0009/0010 input sign key format - DER or PEM or ENGINE"},
    {"in_sign_key", OPT_IN_SIGN_KEY, '<',
     "GMT0009/0010 input the sign key (file/ENGINE/Provider URI)"},
    {"GMT0009", OPT_GMT0009, '-', "Decode GMT 0009 enveloped key"},
    {"GMT0010", OPT_GMT0010, '-', "Decode GMT 0010 PKCS7 enveloped key"},
    {"enc_key_print", OPT_ENC_KEY_PRINT, '-',
     "Print the decrypted GMT0009/0010 key"},
#endif

    OPT_PARAMETERS(),
    {"cert", 0, 0, "Recipient certs, used when encrypting"},
    {NULL}
};

#ifndef OPENSSL_NO_SM2
/*
 * 检测 URI 是否是 STORE 格式（包含 scheme，如 "sdf:", "pkcs11:" 等）
 * 简单的启发式检测：包含 ":" 且不是 Windows 绝对路径（如 "C:\"）
 */
static int is_store_uri(const char *uri)
{
    if (uri == NULL)
        return 0;

    const char *colon = strchr(uri, ':');
    if (colon == NULL)
        return 0;

    /* 检查是否是 Windows 盘符路径 (C:\, D:\ 等) */
    if (colon == uri + 1 &&
        ((uri[0] >= 'A' && uri[0] <= 'Z') || (uri[0] >= 'a' && uri[0] <= 'z')) &&
        (colon[1] == '\\' || colon[1] == '/'))
        return 0;

    /* 包含 ":" 且不是盘符路径，认为是 STORE URI */
    return 1;
}

/*
 * 为 GMT0009/0010 加载签名密钥
 * 支持 STORE URI（如 "sdf:sm2:0:sign:11111111"）和普通文件路径
 */
static EVP_PKEY *load_gmt_sign_key(const char *uri, int format, const char *pass)
{
    /*
     * 如果是 STORE URI，使用 format=0 让 STORE 自动检测格式
     * load_key 内部的 load_key_certs_crls 会调用 OSSL_STORE_open_ex，
     * STORE loader 会根据 URI scheme 路由到正确的 provider
     */
    if (is_store_uri(uri)) {
        return load_key(uri, 0, 1, pass, NULL, "GMT sign key");
    }
    return load_key(uri, format, 1, pass, NULL, "GMT sign key");
}

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

static const char *operation_name(int operation)
{
    switch (operation) {
    case SMIME_ENCRYPT:
        return "encrypt";
    case SMIME_DECRYPT:
        return "decrypt";
    case SMIME_SIGN:
        return "sign";
    case SMIME_RESIGN:
        return "resign";
    case SMIME_VERIFY:
        return "verify";
    case SMIME_PK7OUT:
        return "pk7out";
    default:
        return "(invalid operation)";
    }
}

static void pkcs7_err_at(const char *file, int line, const char *fmt, ...)
{
    va_list args;

    BIO_printf(bio_err, "pkcs7: %s:%d: ", file, line);
    va_start(args, fmt);
    BIO_vprintf(bio_err, fmt, args);
    va_end(args);
    BIO_printf(bio_err, "\n");
}

#define pkcs7_err(...) pkcs7_err_at(__FILE__, __LINE__, __VA_ARGS__)

#define SET_OPERATION(op) \
    ((operation != 0 && (operation != (op))) \
     ? 0 * BIO_printf(bio_err, "%s: Cannot use -%s together with -%s\n", \
                      prog, operation_name(op), operation_name(operation)) \
     : (operation = (op)))

int pkcs7_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    CONF *conf = NULL;
    BIO *in = NULL, *out = NULL, *indata = NULL;
    PKCS7 *p7 = NULL, *p7i;
    STACK_OF(X509) *encerts = NULL, *other = NULL, *signers = NULL;
    STACK_OF(OPENSSL_STRING) *sksigners = NULL, *skkeys = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL, *recip = NULL, *signer = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_MD *sign_md = NULL;
    const char *CAfile = NULL, *CApath = NULL, *CAstore = NULL, *prog = NULL;
    char *certfile = NULL, *keyfile = NULL, *contfile = NULL;
    char *infile = NULL, *outfile = NULL, *signerfile = NULL, *recipfile = NULL;
    char *passinarg = NULL, *passin = NULL, *to = NULL, *from = NULL;
    char *subject = NULL, *digestname = NULL, *ciphername = NULL;
    int noCApath = 0, noCAfile = 0, noCAstore = 0;
    int flags = 0, operation = 0, ret = 1, indef = 0;
    int vpmtouched = 0, rv = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyform = FORMAT_UNDEF;
    const char *mime_eol = "\n";
    OSSL_LIB_CTX *libctx = app_get0_libctx();

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

    int i, print_certs = 0, text = 0, noout = 0, p7_print = 0, quiet = 0;
    OPTION_CHOICE o;

    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        return 1;

    opt_set_unknown_name("cipher");
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

        /*------- 基础 IO 选项 -------*/
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDS, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDS, &outformat))
                goto opthelp;
            break;
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
            flags |= PKCS7_TEXT;
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

        /*------- P7 操作 -------*/
        case OPT_SIGN:
            if (!SET_OPERATION(SMIME_SIGN))
                goto end;
            break;
        case OPT_VERIFY:
            if (!SET_OPERATION(SMIME_VERIFY))
                goto end;
            break;
        case OPT_ENCRYPT:
            if (!SET_OPERATION(SMIME_ENCRYPT))
                goto end;
            break;
        case OPT_DECRYPT:
            if (!SET_OPERATION(SMIME_DECRYPT))
                goto end;
            break;
        case OPT_RESIGN:
            if (!SET_OPERATION(SMIME_RESIGN))
                goto end;
            break;

        /*------- 签名/加密参数 -------*/
        case OPT_SIGNER:
            /* 支持多签名者，参考 smime.c 的实现 */
            if (signerfile != NULL) {
                if (sksigners == NULL
                    && (sksigners = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                if (sk_OPENSSL_STRING_push(sksigners, signerfile) <= 0)
                    goto end;
                if (keyfile == NULL)
                    keyfile = signerfile;
                if (skkeys == NULL
                    && (skkeys = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                if (sk_OPENSSL_STRING_push(skkeys, keyfile) <= 0)
                    goto end;
                keyfile = NULL;
            }
            signerfile = opt_arg();
            break;
        case OPT_RECIP:
            recipfile = opt_arg();
            break;
        case OPT_INKEY:
            if (keyfile != NULL) {
                if (signerfile == NULL) {
                    BIO_printf(bio_err,
                               "Illegal -inkey without -signer\n");
                    goto end;
                }
                if (sksigners == NULL
                    && (sksigners = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                if (sk_OPENSSL_STRING_push(sksigners, signerfile) <= 0)
                    goto end;
                if (skkeys == NULL
                    && (skkeys = sk_OPENSSL_STRING_new_null()) == NULL)
                    goto end;
                if (sk_OPENSSL_STRING_push(skkeys, keyfile) <= 0)
                    goto end;
                signerfile = NULL;
            }
            keyfile = opt_arg();
            break;
        case OPT_KEYFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PDE, &keyform))
                goto opthelp;
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_MD:
            digestname = opt_arg();
            break;
        case OPT_CIPHER:
            ciphername = opt_unknown();
            break;
        case OPT_CERTFILE:
            certfile = opt_arg();
            break;
        case OPT_CONTENT:
            contfile = opt_arg();
            break;
        case OPT_DETACHED:
            flags |= PKCS7_DETACHED;
            break;
        case OPT_NODETACH:
            flags &= ~PKCS7_DETACHED;
            break;
        case OPT_NOCERTS:
            flags |= PKCS7_NOCERTS;
            break;
        case OPT_NOATTR:
            flags |= PKCS7_NOATTR;
            break;
        case OPT_NOSMIMECAP:
            flags |= PKCS7_NOSMIMECAP;
            break;
        case OPT_GMT0010_SIGN:
            flags |= PKCS7_SM2_GMT0010;
            break;
        case OPT_SM2_HASH:
            flags |= PKCS7_SM2_HASH;
            break;
        case OPT_SM2_ADDHASH_Z:
            flags |= PKCS7_SM2_ADDHASH_Z;
            break;
        case OPT_BINARY:
            flags |= PKCS7_BINARY;
            break;
        case OPT_NOSIGS:
            flags |= PKCS7_NOSIGS;
            break;
        case OPT_NOINTERN:
            flags |= PKCS7_NOINTERN;
            break;
        case OPT_NOVERIFY:
            flags |= PKCS7_NOVERIFY;
            break;
        case OPT_NOCHAIN:
            flags |= PKCS7_NOCHAIN;
            break;
        case OPT_CRLFEOL:
            flags |= PKCS7_CRLFEOL;
            mime_eol = "\r\n";
            break;
        case OPT_STREAM:
        case OPT_INDEF:
            indef = 1;
            break;
        case OPT_NOINDEF:
            indef = 0;
            break;
        case OPT_TO:
            to = opt_arg();
            break;
        case OPT_FROM:
            from = opt_arg();
            break;
        case OPT_SUBJECT:
            subject = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_CASTORE:
            CAstore = opt_arg();
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_NOCASTORE:
            noCAstore = 1;
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        case OPT_CONFIG:
            conf = app_load_config_modules(opt_arg());
            if (conf == NULL)
                goto end;
            break;
        case OPT_V_CASES:
            if (!opt_verify(o, vpm))
                goto opthelp;
            vpmtouched = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
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
        default:
            goto opthelp;
        }
    }

    /* No extra arguments unless encrypting (recipient certs as positional args) */
    argc = opt_num_rest();
    argv = opt_rest();
    if (operation != SMIME_ENCRYPT && !opt_check_rest_arg(NULL))
        goto opthelp;

    /*------- 参数解析：摘要与对称算法 -------*/
    if (digestname != NULL) {
        if (!opt_md(digestname, &sign_md))
            goto opthelp;
    }
    if (!opt_cipher_any(ciphername, &cipher))
        goto opthelp;

    /*------- 参数合法性检查 -------*/
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

    /*------- GMT0009/0010 解封流程：完全保留原有逻辑 -------*/
#ifndef OPENSSL_NO_SM2
    if (gmt0009 || gmt0010) {
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;

        sign_pkey = load_gmt_sign_key(in_sign_key, in_sign_key_format, NULL);
        if (sign_pkey == NULL) {
            BIO_printf(bio_err, "unable to load Key\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        p7 = PKCS7_new_ex(libctx, app_get0_propq());
        if (p7 == NULL) {
            BIO_printf(bio_err, "unable to allocate PKCS7 object\n");
            ERR_print_errors(bio_err);
            goto end;
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
        } else {
            /* GMT0010 */
            if (informat == FORMAT_ASN1)
                p7i = d2i_PKCS7_bio(in, &p7);
            else
                p7i = PEM_read_bio_PKCS7(in, &p7, NULL, NULL);
            if (p7i == NULL) {
                BIO_printf(bio_err, "unable to load PKCS7 object\n");
                ERR_print_errors(bio_err);
                goto end;
            }

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

        out = bio_open_default(outfile, 'w', outformat);
        if (out == NULL)
            goto end;

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

        if (enc_key_print
            && EVP_PKEY_print_private(out, enc_pkey, 0, NULL) <= 0) {
            BIO_printf(bio_err, "enc pkey print error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        ret = 0;
        goto end;
    }
#endif /* OPENSSL_NO_SM2 */

    /*============================================================
     * 以下为 P7 签名/验签/加密/解密 流程（参考 smime.c 实现）
     *============================================================*/

    /* 默认 detached 签名（与 smime 一致） */
    if (operation == SMIME_SIGN)
        flags |= PKCS7_DETACHED;

    if (operation == 0) {
        /* 无操作模式：走原有的解析/打印流程 */
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;

        p7 = PKCS7_new_ex(libctx, app_get0_propq());
        if (p7 == NULL) {
            BIO_printf(bio_err, "unable to allocate PKCS7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if (informat == FORMAT_SMIME) {
            p7i = SMIME_read_PKCS7(in, &indata);
        } else if (informat == FORMAT_ASN1) {
            p7i = d2i_PKCS7_bio(in, &p7);
        } else {
            p7i = PEM_read_bio_PKCS7(in, &p7, NULL, NULL);
        }
        if (p7i == NULL) {
            BIO_printf(bio_err, "unable to load PKCS7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        out = bio_open_default(outfile, 'w', outformat);
        if (out == NULL)
            goto end;

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
            else if (outformat == FORMAT_SMIME)
                i = SMIME_write_PKCS7(out, p7, indata, flags);
            else
                i = PEM_write_bio_PKCS7(out, p7);

            if (!i) {
                BIO_printf(bio_err, "unable to write pkcs7 object\n");
                ERR_print_errors(bio_err);
                goto end;
            }
        }
        ret = 0;
        goto end;
    }

    /*------- 有操作模式时的流程 -------*/

    if (!(operation & SMIME_SIGNERS) && (skkeys != NULL || sksigners != NULL)) {
        BIO_puts(bio_err, "Multiple signers or keys not allowed\n");
        goto opthelp;
    }

    if (operation & SMIME_SIGNERS) {
        /* Check to see if any final signer needs to be appended */
        if (keyfile && !signerfile) {
            BIO_puts(bio_err, "Illegal -inkey without -signer\n");
            goto opthelp;
        }
        if (signerfile != NULL) {
            if (sksigners == NULL
                && (sksigners = sk_OPENSSL_STRING_new_null()) == NULL)
                goto end;
            if (sk_OPENSSL_STRING_push(sksigners, signerfile) <= 0)
                goto end;
            if (!skkeys && (skkeys = sk_OPENSSL_STRING_new_null()) == NULL)
                goto end;
            if (!keyfile)
                keyfile = signerfile;
            if (sk_OPENSSL_STRING_push(skkeys, keyfile) <= 0)
                goto end;
        }
        if (sksigners == NULL) {
            BIO_printf(bio_err, "No signer certificate specified\n");
            goto opthelp;
        }
        signerfile = NULL;
        keyfile = NULL;
    } else if (operation == SMIME_DECRYPT) {
        if (recipfile == NULL && keyfile == NULL) {
            BIO_printf(bio_err,
                       "No recipient certificate or key specified\n");
            goto opthelp;
        }
    } else if (operation == SMIME_ENCRYPT) {
        if (argc == 0) {
            BIO_printf(bio_err, "No recipient(s) certificate(s) specified\n");
            goto opthelp;
        }
    }

    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    ret = 2;

    if (!(operation & SMIME_SIGNERS))
        flags &= ~PKCS7_DETACHED;

    if (!(operation & SMIME_OP)) {
        if (flags & PKCS7_BINARY)
            outformat = FORMAT_BINARY;
    }

    if (!(operation & SMIME_IP)) {
        if (flags & PKCS7_BINARY)
            informat = FORMAT_BINARY;
    }

    /*------- 加密：收集接收方证书 -------*/
    if (operation == SMIME_ENCRYPT) {
        encerts = sk_X509_new_null();
        if (encerts == NULL)
            goto end;
        while (*argv != NULL) {
            cert = load_cert(*argv, FORMAT_UNDEF,
                             "recipient certificate file");
            if (cert == NULL)
                goto end;
            if (!sk_X509_push(encerts, cert))
                goto end;
            cert = NULL;
            argv++;
        }
    }

    /*------- 附加证书链 -------*/
    if (certfile != NULL) {
        if (!load_certs(certfile, 0, &other, NULL, "certificate file")) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    /*------- 接收方证书（解密） -------*/
    if (recipfile != NULL && (operation == SMIME_DECRYPT)) {
        if ((recip = load_cert(recipfile, FORMAT_UNDEF,
                               "recipient certificate file")) == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    /*------- 私钥加载 -------*/
    if (operation == SMIME_DECRYPT) {
        if (keyfile == NULL)
            keyfile = recipfile;
    } else if (operation == SMIME_SIGN) {
        if (keyfile == NULL)
            keyfile = signerfile;
    } else {
        keyfile = NULL;
    }

    if (keyfile != NULL) {
        /*
         * 统一通过 load_key 加载私钥：
         * - 普通文件 → PEM/DER
         * - FORMAT_ENGINE → 走引擎
         * - STORE URI（如 sdf:sm2:0:sign:11111111）→ 走 OSSL_STORE → Provider
         */
        if (is_store_uri(keyfile)) {
            key = load_key(keyfile, 0, 0, passin, e, "signing/decryption key");
        } else {
            key = load_key(keyfile, keyform, 0, passin, e, "signing/decryption key");
        }
        if (key == NULL) {
            pkcs7_err("Failed to load %s key: key=%s keyform=%d operation=%s",
                      operation == SMIME_SIGN ? "signing" : "decryption",
                      keyfile, keyform, operation_name(operation));
            goto end;
        }
    }

    /*------- 打开输入 -------*/
    in = bio_open_default(infile, 'r', informat);
    if (in == NULL) {
        pkcs7_err("Failed to open input: in=%s inform=%d operation=%s",
                  infile != NULL ? infile : "stdin", informat,
                  operation_name(operation));
        goto end;
    }

    /*------- 输入类操作：读入已有 P7 结构 -------*/
    if (operation & SMIME_IP) {
        p7 = PKCS7_new_ex(libctx, app_get0_propq());
        if (p7 == NULL) {
            pkcs7_err("Failed to allocate PKCS7 object: operation=%s",
                      operation_name(operation));
            goto end;
        }
        if (informat == FORMAT_SMIME) {
            p7i = SMIME_read_PKCS7_ex(in, &indata, &p7);
        } else if (informat == FORMAT_PEM) {
            p7i = PEM_read_bio_PKCS7(in, &p7, NULL, NULL);
        } else if (informat == FORMAT_ASN1) {
            p7i = d2i_PKCS7_bio(in, &p7);
        } else {
            pkcs7_err("Bad input format for PKCS#7 file: in=%s inform=%d operation=%s",
                      infile != NULL ? infile : "stdin", informat,
                      operation_name(operation));
            goto end;
        }

        if (p7i == NULL) {
            pkcs7_err("Failed to read PKCS#7/S/MIME input: in=%s inform=%d operation=%s",
                      infile != NULL ? infile : "stdin", informat,
                      operation_name(operation));
            goto end;
        }
        if (contfile != NULL) {
            BIO_free(indata);
            if ((indata = BIO_new_file(contfile, "rb")) == NULL) {
                pkcs7_err("Failed to read detached content file: content=%s operation=%s",
                          contfile, operation_name(operation));
                goto end;
            }
        }
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL) {
        pkcs7_err("Failed to open output: out=%s outform=%d operation=%s",
                  outfile != NULL ? outfile : "stdout", outformat,
                  operation_name(operation));
        goto end;
    }

    /*------- 验签：准备 CA 信任库 -------*/
    if (operation == SMIME_VERIFY) {
        if ((store = setup_verify(CAfile, noCAfile, CApath, noCApath,
                                  CAstore, noCAstore)) == NULL)
            goto end;
        X509_STORE_set_verify_cb(store, pkcs7_cb);
        if (vpmtouched)
            X509_STORE_set1_param(store, vpm);
    }

    ret = 3;

    /*============================================================
     * 执行操作
     *============================================================*/

    if (operation == SMIME_ENCRYPT) {
        /*
         * 国密信封默认对称算法：
         * - 接收方证书为 SM2/EC → 默认 sm4-ecb（可用 -cipher 覆盖，硬件可选 sm1 等）
         * - 否则 → aes-256-cbc（兼容 RSA 场景，参考 smime/cms）
         */
        if (cipher == NULL) {
            if (encerts != NULL && sk_X509_num(encerts) > 0) {
                X509 *rc = sk_X509_value(encerts, 0);
                EVP_PKEY *rpk = X509_get0_pubkey(rc);
                if (rpk != NULL
                    && (EVP_PKEY_is_a(rpk, "SM2")
                        || EVP_PKEY_is_a(rpk, "EC"))) {
                    cipher = (EVP_CIPHER *)EVP_sm4_ecb();
                }
            }
            if (cipher == NULL)
                cipher = (EVP_CIPHER *)EVP_aes_256_cbc();
        }
        if (indef)
            flags |= PKCS7_STREAM;
        p7 = PKCS7_encrypt_ex(encerts, in, cipher, flags, libctx,
                              app_get0_propq());
        if (p7 == NULL) {
            pkcs7_err("Failed to create PKCS#7 envelope: in=%s out=%s recipients=%d cipher=%s flags=0x%x",
                      infile != NULL ? infile : "stdin",
                      outfile != NULL ? outfile : "stdout",
                      encerts != NULL ? sk_X509_num(encerts) : 0,
                      cipher != NULL ? EVP_CIPHER_get0_name(cipher) : "(null)",
                      flags);
            goto end;
        }
    } else if (operation & SMIME_SIGNERS) {
        /*
         * 签名流程（参考 apps/smime.c）。
         *
         * 摘要算法确定顺序（与软件层 PKCS7_sign 行为一致）：
         *   1. 用户显式指定 -md → 用之
         *   2. 否则 PKCS7_sign_add_signer 传 NULL md，由内部
         *      EVP_PKEY_get_default_digest_nid 自动解析：
         *        - SM2 keymgmt 通过 OSSL_PKEY_PARAM_DEFAULT_DIGEST 返回 SM3
         *        - RSA keymgmt 返回 sha256 等
         *      （要求 provider 的 keymgmt 实现了 DEFAULT_DIGEST 参数，
         *       SDF Provider 已在 sdfprov_sm2/rsa_keymgmt 中支持。）
         *
         * 采用 PKCS7_sign_ex(NULL,NULL,...,PARTIAL) 建空壳 +
         * PKCS7_sign_add_signer + PKCS7_final 的拆分式（与 smime.c 一致），
         * 以支持多签名者、-md、流式等场景。
         */
        if (operation == SMIME_SIGN) {
            if (flags & PKCS7_DETACHED) {
                if (outformat == FORMAT_SMIME)
                    flags |= PKCS7_STREAM;
            } else if (indef) {
                flags |= PKCS7_STREAM;
            }
        } else {
            /* SMIME_RESIGN：从已有 P7 中复用摘要 */
            flags |= PKCS7_REUSE_DIGEST;
        }

        /*
         * 签名默认不附加 SMIMECapabilities 属性（国密 P7 场景不需要）。
         * 用户可通过 -smimecap 显式取消此默认行为（未来扩展）。
         * PKCS7_SM2_GMT0010 由用户通过 -gmt0010 显式指定，控制 PKCS7 OID：
         *   有 -gmt0010 → NID_pkcs7_sm2_signed / NID_pkcs7_sm2_data
         *   无 -gmt0010 → NID_pkcs7_signed / NID_pkcs7_data（RSA/通用）
         */
        if (operation == SMIME_SIGN || operation == SMIME_RESIGN)
            flags |= PKCS7_NOSMIMECAP;

        flags |= PKCS7_PARTIAL;
        p7 = PKCS7_sign_ex(NULL, NULL, other, in, flags, libctx,
                           app_get0_propq());
        if (p7 == NULL) {
            pkcs7_err("Failed to create PKCS#7 signed structure: in=%s out=%s flags=0x%x operation=%s",
                      infile != NULL ? infile : "stdin",
                      outfile != NULL ? outfile : "stdout", flags,
                      operation_name(operation));
            goto end;
        }
        if (flags & PKCS7_NOCERTS) {
            for (i = 0; i < sk_X509_num(other); i++) {
                X509 *x = sk_X509_value(other, i);
                PKCS7_add_certificate(p7, x);
            }
        }

        for (i = 0; i < sk_OPENSSL_STRING_num(sksigners); i++) {
            signerfile = sk_OPENSSL_STRING_value(sksigners, i);
            keyfile = sk_OPENSSL_STRING_value(skkeys, i);
            signer = load_cert(signerfile, FORMAT_UNDEF,
                               "signer certificate");
            if (signer == NULL) {
                pkcs7_err("Failed to load signer certificate: signer=%s operation=%s",
                          signerfile, operation_name(operation));
                goto end;
            }

            if (is_store_uri(keyfile))
                key = load_key(keyfile, 0, 0, passin, e, "signing key");
            else
                key = load_key(keyfile, keyform, 0, passin, e, "signing key");
            if (key == NULL) {
                pkcs7_err("Failed to load signing key: key=%s signer=%s keyform=%d",
                          keyfile, signerfile, keyform);
                goto end;
            }

            /*
             * sign_md 为 NULL 时，PKCS7_sign_add_signer 内部会按 pkey 类型
             * 自动选择默认摘要（SM2→SM3，RSA→sha256 等）。
             */
            if (!PKCS7_sign_add_signer(p7, signer, key, sign_md, flags)) {
                pkcs7_err("Failed to add signer to PKCS#7: signer=%s key=%s md=%s flags=0x%x",
                          signerfile, keyfile,
                          sign_md != NULL ? EVP_MD_get0_name(sign_md) : "(default)",
                          flags);
                goto end;
            }
            X509_free(signer);
            signer = NULL;
            EVP_PKEY_free(key);
            key = NULL;
        }

        /*
         * finalize。
         * SM2 签名的 Z 值预处理由 PKCS7 内部 + Provider 的 digest_sign 路径
         * 协同完成，应用层不需要显式叠加 PKCS7_SM2_ADDHASH_Z flag。
         * 用户可通过 -sm2_hash（外送hash）或 -sm2_addhash_z（Z值写入P7）改变行为。
         */
        if (operation == SMIME_SIGN && !(flags & PKCS7_STREAM)) {
            if (!PKCS7_final(p7, in, flags)) {
                pkcs7_err("Failed to finalize PKCS#7 signed data: in=%s out=%s flags=0x%x",
                          infile != NULL ? infile : "stdin",
                          outfile != NULL ? outfile : "stdout", flags);
                goto end;
            }
        }
    }

    if (p7 == NULL) {
        pkcs7_err("Failed to create PKCS#7 structure: operation=%s in=%s out=%s",
                  operation_name(operation),
                  infile != NULL ? infile : "stdin",
                  outfile != NULL ? outfile : "stdout");
        goto end;
    }

    ret = 4;
    if (operation == SMIME_DECRYPT) {
        if (!PKCS7_decrypt(p7, key, recip, out, flags)) {
            pkcs7_err("Failed to decrypt PKCS#7 envelope: in=%s out=%s recip=%s key=%s flags=0x%x",
                      infile != NULL ? infile : "stdin",
                      outfile != NULL ? outfile : "stdout",
                      recipfile != NULL ? recipfile : "(null)",
                      keyfile != NULL ? keyfile : "(null)", flags);
            goto end;
        }
    } else if (operation == SMIME_VERIFY) {
        if (PKCS7_verify(p7, other, store, indata, out, flags))
            BIO_printf(bio_err, "Verification successful\n");
        else {
            pkcs7_err("PKCS#7 verification failed: in=%s content=%s out=%s CAfile=%s CApath=%s CAstore=%s flags=0x%x",
                      infile != NULL ? infile : "stdin",
                      contfile != NULL ? contfile : "(embedded)",
                      outfile != NULL ? outfile : "stdout",
                      CAfile != NULL ? CAfile : "(default)",
                      CApath != NULL ? CApath : "(default)",
                      CAstore != NULL ? CAstore : "(default)", flags);
            goto end;
        }
        signers = PKCS7_get0_signers(p7, other, flags);
        if (signers == NULL) {
            pkcs7_err("Failed to get signers from verified PKCS#7: in=%s flags=0x%x",
                      infile != NULL ? infile : "stdin", flags);
            ret = 5;
            goto end;
        }
        if (!save_certs(signerfile, signers)) {
            pkcs7_err("Failed to write signers: signerout=%s",
                      signerfile != NULL ? signerfile : "(null)");
            ret = 5;
            goto end;
        }
        sk_X509_free(signers);
        signers = NULL;
    } else {
        if (operation == SMIME_ENCRYPT && flags & PKCS7_STREAM)
            BIO_flush(in);   /* ensure content is read for streaming */
        if (to)
            BIO_printf(out, "To: %s%s", to, mime_eol);
        if (from)
            BIO_printf(out, "From: %s%s", from, mime_eol);
        if (subject)
            BIO_printf(out, "Subject: %s%s", subject, mime_eol);
        if (outformat == FORMAT_SMIME) {
            if (operation == SMIME_RESIGN)
                rv = SMIME_write_PKCS7(out, p7, indata, flags);
            else
                rv = SMIME_write_PKCS7(out, p7, in, flags);
        } else if (outformat == FORMAT_PEM) {
            rv = PEM_write_bio_PKCS7_stream(out, p7, in, flags);
        } else if (outformat == FORMAT_ASN1) {
            rv = i2d_PKCS7_bio_stream(out, p7, in, flags);
        } else {
            pkcs7_err("Bad output format for PKCS#7 file: out=%s outform=%d operation=%s",
                      outfile != NULL ? outfile : "stdout", outformat,
                      operation_name(operation));
            goto end;
        }
        if (rv == 0) {
            pkcs7_err("Failed to write PKCS#7 output: out=%s outform=%d operation=%s flags=0x%x",
                      outfile != NULL ? outfile : "stdout", outformat,
                      operation_name(operation), flags);
            ret = 3;
            goto end;
        }
    }
    ret = 0;

 end:
    if (ret)
        ERR_print_errors(bio_err);
    OSSL_STACK_OF_X509_free(encerts);
    OSSL_STACK_OF_X509_free(other);
    OSSL_STACK_OF_X509_free(signers);
    sk_OPENSSL_STRING_free(sksigners);
    sk_OPENSSL_STRING_free(skkeys);
    X509_VERIFY_PARAM_free(vpm);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(recip);
    X509_free(signer);
    EVP_PKEY_free(key);
    EVP_MD_free(sign_md);
    EVP_CIPHER_free(cipher);
    PKCS7_free(p7);
    release_engine(e);
    BIO_free(in);
    BIO_free(indata);
    BIO_free_all(out);
    OPENSSL_free(passin);
    NCONF_free(conf);
#ifndef OPENSSL_NO_SM2
    BIO_free_all(bio_key);
    SM2_Enveloped_Key_free(sm2evpkey);
    EVP_PKEY_free(sign_pkey);
    EVP_PKEY_free(enc_pkey);
#endif
    return ret;
}

/* 把验签得到的签名者证书写出为 PEM（参考 smime.c） */
static int save_certs(char *signerfile, STACK_OF(X509) *signers)
{
    int i;
    BIO *tmp;

    if (signerfile == NULL)
        return 1;
    tmp = BIO_new_file(signerfile, "w");
    if (tmp == NULL)
        return 0;
    for (i = 0; i < sk_X509_num(signers); i++)
        PEM_write_bio_X509(tmp, sk_X509_value(signers, i));
    BIO_free(tmp);
    return 1;
}

/* 验签回调：输出策略信息（参考 smime.c） */
static int pkcs7_cb(int ok, X509_STORE_CTX *ctx)
{
    int error;

    error = X509_STORE_CTX_get_error(ctx);

    if ((error != X509_V_ERR_NO_EXPLICIT_POLICY)
        && ((error != X509_V_OK) || (ok != 2)))
        return ok;

    policies_print(ctx);

    return ok;
}
