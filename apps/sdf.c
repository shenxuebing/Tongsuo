/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include "internal/deprecated.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <openssl/sdf.h>
#include <openssl/bio.h>
#include <openssl/tsapi.h>
#include <openssl/ec.h>
#include <openssl/sgd.h>
#include "internal/sdf.h"
#include "apps.h"
#include "progs.h"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_IN,
    OPT_INKEY,
    OPT_INDEX,
    OPT_GENSM2KEY,
    OPT_DELSM2KEY,
    OPT_UPDATESM2KEY,
    OPT_EXPORTSM2PUBKEY,
    OPT_EXPORTRSAPUBKEY,
    OPT_EXPORTSM2KEY,
    OPT_EXPORTSM2KEYWITHEVLP,
    OPT_IMPORTSM2KEY,
    OPT_IMPORTSM2KEYWITHEVLP,
    OPT_IMPORTRSAKEY,
    OPT_DELRSAKEY,
    OPT_LOGIN,
    OPT_ENCRYPT,
    OPT_DECRYPT,
    OPT_PEERKEY,
    OPT_TYPE,
    OPT_OUT,
    OPT_KEYOUT,
    OPT_DEKOUT,
    OPT_INDEK,
    OPT_IV,
    OPT_ISK,
    OPT_ISKTYPE,
    OPT_ALGORITHM,
    OPT_PROV_ENUM,
    OPT_CONFIG,
} OPTION_CHOICE;

/*
 * Usage notes:
 *
 * Provider/config loading:
 *   openssl sdf -config apps/openssl.cnf ...
 *   or set OPENSSL_CONF to the config file before running openssl.
 *
 * The sdfprov section in openssl.cnf provides sdf_lib_path,
 * sdf_module_password, sdf_use_loadmodule and indexstart.
 * Environment variables SDF_LIB_PATH, SDF_MODULE_PASSWORD,
 * SDF_USE_LOADMODULE and SDF_INDEX_START are fallback values only.
 *
 * SM2 key management:
 *   openssl sdf -gensm2key -index N [-type sign|enc] [-login user:pass]
 *   openssl sdf -delsm2key -index N [-type sign|enc] [-login user:pass]
 *   openssl sdf -updatesm2key -index N [-type sign|enc] [-login user:pass]
 *   openssl sdf -importsm2key -index N -type sign -inkey sm2_sign.key
 *   openssl sdf -importsm2key -index N -type enc  -inkey sm2_enc.key
 *   openssl sdf -exportsm2key -index N -type sign -keyout sm2_sign.key
 *   openssl sdf -exportsm2pubkey -index N -type enc -keyout sm2_enc.pub
 *
 * RSA key import:
 *   openssl sdf -delrsakey -index N [-type sign|enc] [-login user:pass]
 *   openssl sdf -importrsakey -index N -type sign -inkey rsa_sign.key
 *   openssl sdf -importrsakey -index N -type enc  -inkey rsa_enc.key
 *
 * SM2 key import/export with digital envelope:
 *   openssl sdf -importsm2keywithevlp -index N -type enc \
 *       -inkey sm2.keyenc -indek sm4.keyenc
 *   openssl sdf -exportsm2keywithevlp -index N -type sign \
 *       -peerkey peer.pem -keyout sm2.bin -dekout dek.bin
 *
 * Encryption/decryption:
 *   openssl sdf -encrypt -algorithm sm2 -index N -in data.txt -out data.enc
 *   openssl sdf -decrypt -algorithm sm2 -index N -in data.enc -out data.txt
 *   openssl sdf -encrypt -algorithm sm4-cbc -inkey sm4key.enc -isk N \
 *       -isktype sm2 -iv HEX -in data.txt -out data.enc
 *   openssl sdf -decrypt -algorithm sm4-cbc -inkey sm4key.enc -isk N \
 *       -isktype sm2 -iv HEX -in data.enc -out data.txt
 *
 * Asymmetric import/delete index mapping:
 *   indexstart=1: -index N maps to sign=2*N-1, enc=2*N.
 *   indexstart=0: -index N maps to sign=2*N+1, enc=2*N+2.
 *   The mapping is applied only to asymmetric import/delete commands.
 *
 * byzk0018/BYCSM SM2 import index note:
 *   BYCSM_ImportECCKeyPair receives the command index, but the vendor library
 *   stores sign/enc key pairs under a container index.  In local tests,
 *   importing sign index 81 and enc index 82 stored the pair under export
 *   index 40; 83/84 stored under 41; 85/86 stored under 42.
 *   Verify imported public keys with the container index used by the vendor
 *   library, for example:
 *     openssl sdf -exportsm2pubkey -index 40 -type sign -keyout sm2_sign.pub
 *     openssl sdf -exportsm2pubkey -index 40 -type enc  -keyout sm2_enc.pub
 */

const OPTIONS sdf_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt file"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt file"},
    {"importsm2key", OPT_IMPORTSM2KEY, '-', "Import SM2 key with the index"},
    {"importsm2keywithevlp", OPT_IMPORTSM2KEYWITHEVLP, '-', "Import SM2 key with digital envelope"},
    {"importrsakey", OPT_IMPORTRSAKEY, '-', "Import RSA key with the index (auto 1024-4096)"},
    {"delrsakey", OPT_DELRSAKEY, '-', "Delete RSA key pair with the index"},
    {"gensm2key", OPT_GENSM2KEY, '-', "Generate SM2 key pair with the index"},
    {"delsm2key", OPT_DELSM2KEY, '-', "Delete SM2 key pair with the index"},
    {"updatesm2key", OPT_UPDATESM2KEY, '-', "Update SM2 key pair with the index"},
    {"exportsm2key", OPT_EXPORTSM2KEY, '-', "Export SM2 key with the index"},
    {"exportsm2pubkey", OPT_EXPORTSM2PUBKEY, '-', "Export SM2 public key with the index"},
    {"exportrsapubkey", OPT_EXPORTRSAPUBKEY, '-', "Export RSA public key with the index"},
    {"exportsm2keywithevlp", OPT_EXPORTSM2KEYWITHEVLP, '-', "Export SM2 key with digital envelope"},
    {"login", OPT_LOGIN, 's', "Login with username:password"},
    OPT_CONFIG_OPTION,
    OPT_PROV_OPTIONS,

    OPT_SECTION("Input"),
    {"inkey", OPT_INKEY, 's', "Input key file"},
    {"index", OPT_INDEX, 's', "Specify the index of key"},
    {"peerkey", OPT_PEERKEY, 's', "Peer public key file used in exporting SM2 key with digital envelope"},
    {"type", OPT_TYPE, 's', "sign: signature key (default), enc: encryption key"},
    {"indek", OPT_INDEK, '>', "Input digital envelope key"},
    {"isk", OPT_ISK, 's', "Index of ISK key"},
    {"isktype", OPT_ISKTYPE, 's', "ISK type, sm2: SM2 key, rsa: RSA key"},
    {"iv", OPT_IV, 's', "IV in hex format"},
    {"algorithm", OPT_ALGORITHM, 's', "Algorithm to use"},
    {"in", OPT_IN, '>', "Input file"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"keyout", OPT_KEYOUT, '>', "Output key file"},
    {"dekout", OPT_DEKOUT, '>', "Output digital envelope key"},

    {NULL}
};

static void sdf_print_usage(void)
{
    BIO_printf(bio_err, "\nCommand usage examples:\n");
    BIO_printf(bio_err, "  Load provider config:\n");
    BIO_printf(bio_err, "    set OPENSSL_CONF=C:\\path\\to\\openssl.cnf\n");
    BIO_printf(bio_err, "    openssl sdf [command options]\n");
    BIO_printf(bio_err, "    # Prefer OPENSSL_CONF for provider options such as sdf_use_loadmodule.\n");
    BIO_printf(bio_err, "    # -config can load app config, but may be too late for auto-loaded providers.\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Generate SM2 key on device:\n");
    BIO_printf(bio_err, "    openssl sdf -gensm2key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Delete SM2 key on device:\n");
    BIO_printf(bio_err, "    openssl sdf -delsm2key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Update SM2 key on device:\n");
    BIO_printf(bio_err, "    openssl sdf -updatesm2key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Import SM2 private key to device:\n");
    BIO_printf(bio_err, "    openssl sdf -importsm2key -inkey sm2.key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -importsm2key -index 81 -type sign -inkey ..\\test\\certs\\sm2\\server_sign.key\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -importsm2key -index 82 -type enc -inkey ..\\test\\certs\\sm2\\server_enc.key\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Import RSA private key to device:\n");
    BIO_printf(bio_err, "    openssl sdf -delrsakey -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "    openssl sdf -importrsakey -inkey rsa.key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Import SM2 key with digital envelope:\n");
    BIO_printf(bio_err, "    openssl sdf -importsm2keywithevlp -inkey sm2.keyenc -indek sm4.keyenc -index N [-type sign|enc]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Export SM2 private key from device:\n");
    BIO_printf(bio_err, "    openssl sdf -exportsm2key -index N -keyout sm2.key [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Export SM2 public key from device:\n");
    BIO_printf(bio_err, "    openssl sdf -exportsm2pubkey -index N -keyout sm2.pub [-type sign|enc]\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -exportsm2pubkey -index 40 -type sign -keyout sm2_sign.pub\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -exportsm2pubkey -index 40 -type enc -keyout sm2_enc.pub\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Export SM2 key with digital envelope:\n");
    BIO_printf(bio_err, "    openssl sdf -exportsm2keywithevlp -index N -peerkey peer.pem -keyout sm2.bin -dekout dek.bin [-type sign|enc]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Encrypt/decrypt with SM2 key index:\n");
    BIO_printf(bio_err, "    openssl sdf -encrypt -algorithm sm2 -index N -in plain.bin -out cipher.bin\n");
    BIO_printf(bio_err, "    openssl sdf -decrypt -algorithm sm2 -index N -in cipher.bin -out plain.bin\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Encrypt/decrypt with SM4 key encrypted by ISK:\n");
    BIO_printf(bio_err, "    openssl sdf -encrypt -algorithm sm4-cbc -inkey sm4.keyenc -isk N -isktype sm2 -iv HEX -in plain.bin -out cipher.bin\n");
    BIO_printf(bio_err, "    openssl sdf -decrypt -algorithm sm4-cbc -inkey sm4.keyenc -isk N -isktype sm2 -iv HEX -in cipher.bin -out plain.bin\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "Notes:\n");
    BIO_printf(bio_err, "  -type defaults to sign. Use -type enc for encryption-key slots.\n");
    BIO_printf(bio_err, "  -login defaults to admin:123123 if omitted.\n");
    BIO_printf(bio_err, "  Supported -algorithm values are sm2, sm4-ecb, sm4-cbc, sm4-cfb, sm4-ofb.\n");
    BIO_printf(bio_err, "  sdf_lib_path, sdf_module_password, sdf_use_loadmodule and indexstart are read from openssl.cnf.\n");
    BIO_printf(bio_err, "  indexstart controls logical asymmetric import/delete index mapping.\n");
    BIO_printf(bio_err, "  indexstart=1: logical N maps to sign=2*N-1 and enc=2*N.\n");
    BIO_printf(bio_err, "  indexstart=0: logical N maps to sign=2*N+1 and enc=2*N+2.\n");
    BIO_printf(bio_err, "  Use OPENSSL_CONF when changing provider options; -config is best for app-time config.\n");
    BIO_printf(bio_err, "  SDF_LIB_PATH, SDF_MODULE_PASSWORD, SDF_USE_LOADMODULE and SDF_INDEX_START are only fallbacks.\n");
    BIO_printf(bio_err, "  Set sdf_use_loadmodule=0 for vendors that do not provide BYCSM_LoadModule.\n");
    BIO_printf(bio_err, "  Some BYCSM libraries store SM2 sign/enc pairs under a container index.\n");
    BIO_printf(bio_err, "  For byzk0018 tests, import indexes 81/82 export as container index 40.\n");
    BIO_printf(bio_err, "\n");
}

static int sdf_missing_arg(const char *cmd, const char *arg)
{
    BIO_printf(bio_err, "%s requires %s\n", cmd, arg);
    return 0;
}

static int sdf_require_index(const char *cmd, int index)
{
    if (index >= 0)
        return 1;

    BIO_printf(bio_err, "%s requires -index N\n", cmd);
    return 0;
}

static const char *sdf_key_type_name(int sign)
{
    return sign ? "sign" : "enc";
}

static int sdf_pkey_bits(EVP_PKEY *pkey)
{
    int bits = EVP_PKEY_get_bits(pkey);

    return bits > 0 ? bits : 0;
}

/*
 * 统一的失败输出：打印用户可读的错误消息 + OpenSSL 错误栈详情。
 * TSAPI/SDFE 层通过 ERR_raise 设置的错误会在此一并输出，
 * 帮助使用者定位底层原因（如设备未连接、密钥已存在、索引超限等）。
 */
static void sdf_fail_at(const char *file, int line, const char *fmt, ...)
{
    va_list args;

    BIO_printf(bio_err, "sdf: %s:%d: ", file, line);
    va_start(args, fmt);
    BIO_vprintf(bio_err, fmt, args);
    va_end(args);
    BIO_printf(bio_err, "\n");
    ERR_print_errors(bio_err);
    ERR_clear_error();
}

#define sdf_fail(...) sdf_fail_at(__FILE__, __LINE__, __VA_ARGS__)
#define sdf_msg(...) sdf_fail_at(__FILE__, __LINE__, __VA_ARGS__)

static int sdf_map_asym_index(int relative_index, int sign)
{
    int index_start = ossl_sdf_lib_get_index_start();

    if (index_start == 0)
        return relative_index * 2 + (sign ? 1 : 2);

    return relative_index * 2 - (sign ? 1 : 0);
}

int sdf_main(int argc, char **argv)
{
    char *prog;
    OPTION_CHOICE o;
    BIO *outkey = NULL, *outdek = NULL, *key_bio = NULL;
    BIO *in = NULL, *out = NULL;
    int ret = 1, index = -1, sign = 1, mode = 0;
    int isk = -1;
    int gensm2 = 0, delsm2 = 0, updatesm2 = 0;
    int exportsm2pubkey = 0, exportsm2keywithevlp = 0, importsm2keywithevlp = 0;
    int exportrsapubkey = 0;
    int exportsm2key = 0, importsm2key = 0, encrypt = 0, decrypt = 0;
    int importrsakey = 0, delrsakey = 0;
    unsigned char *inkey = NULL, *indek = NULL, *inbuf = NULL, *outbuf = NULL;
    char *p = NULL;
    char *login = NULL;
    char *outkeyfile = NULL, *peerkey_file = NULL, *indekfile = NULL;
    char *outdekfile = NULL, *inkeyfile = NULL;
    char *infile = NULL, *outfile = NULL;
    const char *user = "admin", *password = "123123", *hexiv = NULL, *algo = NULL;
    const char *isktype = "sm2";
    unsigned char *iv = NULL;
    long ivlen = 0;
    EVP_PKEY *pkey = NULL, *peer = NULL;
    unsigned char *priv = NULL, *pub = NULL, *outevlp = NULL;
    size_t privlen = 0, publen = 0, outevlplen = 0, keylen = 0, deklen = 0, inbuflen = 0;
    size_t outbuflen = 0;
    CONF *conf = NULL;
    int logical_index = -1, map_asym_index = 0;

    prog = opt_init(argc, argv, sdf_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(sdf_options);
            sdf_print_usage();
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_INKEY:
            inkeyfile = opt_arg();
            break;
        case OPT_GENSM2KEY:
            gensm2 = 1;
            break;
        case OPT_DELSM2KEY:
            delsm2 = 1;
            break;
        case OPT_UPDATESM2KEY:
            updatesm2 = 1;
            break;
        case OPT_INDEX:
            if (!opt_int(opt_arg(), &index))
                goto end;
            break;
        case OPT_LOGIN:
            login = opt_arg();
            break;
        case OPT_EXPORTSM2KEY:
            exportsm2key = 1;
            break;
        case OPT_EXPORTSM2PUBKEY:
            exportsm2pubkey = 1;
            break;
        case OPT_EXPORTRSAPUBKEY:
            exportrsapubkey = 1;
            break;
        case OPT_EXPORTSM2KEYWITHEVLP:
            exportsm2keywithevlp = 1;
            break;
        case OPT_IMPORTSM2KEY:
            importsm2key = 1;
            break;
        case OPT_IMPORTSM2KEYWITHEVLP:
            importsm2keywithevlp = 1;
            break;
        case OPT_IMPORTRSAKEY:
            importrsakey = 1;
            break;
        case OPT_DELRSAKEY:
            delrsakey = 1;
            break;
        case OPT_PEERKEY:
            peerkey_file = opt_arg();
            break;
        case OPT_TYPE:
            if (strcmp(opt_arg(), "sign") == 0)
                sign = 1;
            else if (strcmp(opt_arg(), "enc") == 0)
                sign = 0;
            else
                goto opthelp;
            break;
        case OPT_KEYOUT:
            outkeyfile = opt_arg();
            break;
        case OPT_INDEK:
            indekfile = opt_arg();
            break;
        case OPT_DEKOUT:
            outdekfile = opt_arg();
            break;
        case OPT_ENCRYPT:
            encrypt = 1;
            break;
        case OPT_DECRYPT:
            decrypt = 1;
            break;
        case OPT_IV:
            hexiv = opt_arg();
            break;
        case OPT_ALGORITHM:
            algo = opt_arg();
            break;
        case OPT_ISK:
            if (!opt_int(opt_arg(), &isk))
                goto end;
            break;
        case OPT_ISKTYPE:
            isktype = opt_arg();
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
        }
    }

    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    argc = gensm2 + delsm2 + delrsakey + updatesm2 + exportsm2pubkey + exportrsapubkey
           + exportsm2key + exportsm2keywithevlp + importsm2key
           + importsm2keywithevlp + importrsakey + encrypt + decrypt;
    if (argc == 0) {
        BIO_printf(bio_err, "No sdf command specified\n");
        goto opthelp;
    }
    if (argc > 1) {
        BIO_printf(bio_err, "Only one sdf command can be specified\n");
        goto opthelp;
    }

    if ((gensm2 && !sdf_require_index("-gensm2key", index))
        || (delsm2 && !sdf_require_index("-delsm2key", index))
        || (delrsakey && !sdf_require_index("-delrsakey", index))
        || (updatesm2 && !sdf_require_index("-updatesm2key", index))
        || (exportsm2key && (!sdf_require_index("-exportsm2key", index)
                             || (outkeyfile == NULL
                                 && !sdf_missing_arg("-exportsm2key", "-keyout file"))))
        || (exportsm2pubkey && !sdf_require_index("-exportsm2pubkey", index))
        || (exportrsapubkey && !sdf_require_index("-exportrsapubkey", index))
        || (exportsm2keywithevlp
            && (!sdf_require_index("-exportsm2keywithevlp", index)
                || (peerkey_file == NULL
                    && !sdf_missing_arg("-exportsm2keywithevlp", "-peerkey file"))
                || (outkeyfile == NULL
                    && !sdf_missing_arg("-exportsm2keywithevlp", "-keyout file"))
                || (outdekfile == NULL
                    && !sdf_missing_arg("-exportsm2keywithevlp", "-dekout file"))))
        || (importsm2key && (!sdf_require_index("-importsm2key", index)
                             || (inkeyfile == NULL
                                 && !sdf_missing_arg("-importsm2key", "-inkey file"))))
        || (importrsakey && (!sdf_require_index("-importrsakey", index)
                             || (inkeyfile == NULL
                                 && !sdf_missing_arg("-importrsakey", "-inkey file"))))
        || (importsm2keywithevlp
            && (!sdf_require_index("-importsm2keywithevlp", index)
                || (inkeyfile == NULL
                    && !sdf_missing_arg("-importsm2keywithevlp", "-inkey file"))
                || (indekfile == NULL
                    && !sdf_missing_arg("-importsm2keywithevlp", "-indek file")))))
        goto end;

    if (encrypt || decrypt) {
        if (algo == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                             "-algorithm name"))
            goto end;
        if (infile == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                               "-in file"))
            goto end;
        if (outfile == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                                "-out file"))
            goto end;

        if (OPENSSL_strcasecmp(algo, "sm2") == 0) {
            if (!sdf_require_index(encrypt ? "-encrypt" : "-decrypt", index))
                goto end;
        } else if (OPENSSL_strcasecmp(algo, "sm4-ecb") == 0
                   || OPENSSL_strcasecmp(algo, "sm4-cbc") == 0
                   || OPENSSL_strcasecmp(algo, "sm4-cfb") == 0
                   || OPENSSL_strcasecmp(algo, "sm4-ofb") == 0) {
            if (inkeyfile == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                                      "-inkey file"))
                goto end;
            if (isk < 0 && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                            "-isk N"))
                goto end;
            if (OPENSSL_strcasecmp(isktype, "sm2") != 0) {
                BIO_printf(bio_err, "Unsupported -isktype %s\n", isktype);
                goto end;
            }
            if (OPENSSL_strcasecmp(algo, "sm4-ecb") != 0 && hexiv == NULL
                && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt", "-iv HEX"))
                goto end;
        }
    }

    if (login) {
        user = login;
        p = strchr(login, ':');
        if (p == NULL) {
            BIO_printf(bio_err, "No password found");
            goto end;
        }

        password = p + 1;
        *p = '\0';
    }

    map_asym_index = gensm2 || delsm2 || delrsakey || updatesm2 || importsm2key
                     || importsm2keywithevlp || importrsakey;
    if (map_asym_index) {
        logical_index = index;
        index = sdf_map_asym_index(logical_index, sign);
        BIO_printf(bio_err, "Using %s key index: logical=%d, device=%d, indexstart=%d\n",
                   sdf_key_type_name(sign), logical_index, index,
                   ossl_sdf_lib_get_index_start());
    }

    /*
     * 厂商库通常由 sdfprov 从 openssl.cnf 读取配置后预加载。
     * 如果 provider/config 没有先完成预加载，TSAPI 层仍会在首次调用时尝试
     * 用 SDF_LIB_PATH / SDF_MODULE_PASSWORD / SDF_USE_LOADMODULE 作为 fallback。
     */

    if (gensm2) {
        if (!TSAPI_GenerateSM2KeyWithIndex(index, sign, user, password)) {
            sdf_fail("Failed to generate SM2 %s key: logical_index=%d device_index=%d user=%s",
                     sdf_key_type_name(sign), logical_index, index, user);
            goto end;
        }

        BIO_printf(bio_err, "Generated SM2 %s key at index %d\n",
                   sdf_key_type_name(sign), index);
        ret = 0;
        goto end;
    }

    if (delsm2) {
        if (!TSAPI_DelSm2KeyWithIndex(index, sign, user, password)) {
            sdf_fail("Failed to delete SM2 %s key: logical_index=%d device_index=%d user=%s",
                     sdf_key_type_name(sign), logical_index, index, user);
            goto end;
        }

        BIO_printf(bio_err, "Deleted SM2 %s key at logical index %d (device index %d)\n",
                   sdf_key_type_name(sign), logical_index, index);
        ret = 0;
        goto end;
    }

    if (delrsakey) {
        if (!TSAPI_DelRSAKeyWithIndex(index, sign, user, password)) {
            sdf_fail("Failed to delete RSA %s key: logical_index=%d device_index=%d user=%s",
                     sdf_key_type_name(sign), logical_index, index, user);
            goto end;
        }

        BIO_printf(bio_err, "Deleted RSA %s key at logical index %d (device index %d)\n",
                   sdf_key_type_name(sign), logical_index, index);
        ret = 0;
        goto end;
    }

    if (updatesm2) {
        if (!TSAPI_UpdateSm2KeyWithIndex(index, sign, user, password)) {
            sdf_fail("Failed to update SM2 %s key: logical_index=%d device_index=%d user=%s",
                     sdf_key_type_name(sign), logical_index, index, user);
            goto end;
        }

        BIO_printf(bio_err, "Updated SM2 %s key at index %d\n",
                   sdf_key_type_name(sign), index);
        ret = 0;
        goto end;
    }

    /*
     * 公钥导出（SM2/RSA）：
     * - 指定 -keyout 时输出 PEM 到文件
     * - 未指定 -keyout 时打印 PEM 到 stdout
     */
    if (exportsm2pubkey || exportrsapubkey) {
        if (outkeyfile != NULL) {
            outkey = bio_open_default(outkeyfile, 'w', FORMAT_PEM);
            if (outkey == NULL) {
                sdf_msg("Failed to open public key output: keyout=%s", outkeyfile);
                goto end;
            }
        } else {
            outkey = BIO_new_fp(stdout, BIO_NOCLOSE);
            if (outkey == NULL) {
                sdf_msg("Failed to create stdout BIO for public key output");
                goto end;
            }
        }

        if (exportsm2pubkey)
            pkey = TSAPI_ExportSM2PubKeyWithIndex(index, sign);
        else
            pkey = TSAPI_ExportRSAPubKeyWithIndex(index, sign);

        if (pkey == NULL) {
            sdf_fail("Failed to export %s %s public key: index=%d keyout=%s",
                     exportsm2pubkey ? "SM2" : "RSA", sdf_key_type_name(sign),
                     index, outkeyfile != NULL ? outkeyfile : "stdout");
            goto end;
        }

        if (!PEM_write_bio_PUBKEY(outkey, pkey)) {
            sdf_msg("Failed to write %s %s public key: index=%d keyout=%s",
                    exportsm2pubkey ? "SM2" : "RSA", sdf_key_type_name(sign),
                    index, outkeyfile != NULL ? outkeyfile : "stdout");
            goto end;
        }

        BIO_printf(bio_err, "Exported %s %s public key at index %d%s%s\n",
                   exportsm2pubkey ? "SM2" : "RSA", sdf_key_type_name(sign),
                   index, outkeyfile != NULL ? " to " : "",
                   outkeyfile != NULL ? outkeyfile : "");
        ret = 0;
        goto end;
    }

    /* exportsm2key (export private key, requires -keyout) */
    if (outkeyfile) {
        outkey = bio_open_default(outkeyfile, 'w', FORMAT_BINARY);
        if (outkey == NULL) {
            sdf_msg("Failed to open key output file: keyout=%s", outkeyfile);
            goto end;
        }
    }

    if (exportsm2key) {
        pkey = TSAPI_ExportSM2KeyWithIndex(index, sign, user, password);
        if (pkey == NULL) {
            sdf_fail("Failed to export SM2 %s private key: index=%d keyout=%s",
                     sdf_key_type_name(sign), index,
                     outkeyfile != NULL ? outkeyfile : "(null)");
            goto end;
        }

        if (!PEM_write_bio_PrivateKey(outkey, pkey, NULL, NULL, 0, NULL, NULL)) {
            sdf_msg("Failed to write SM2 %s private key: index=%d keyout=%s",
                    sdf_key_type_name(sign), index, outkeyfile);
            goto end;
        }

        BIO_printf(bio_err, "Exported SM2 %s private key at index %d to %s\n",
                   sdf_key_type_name(sign), index, outkeyfile);
        ret = 0;
        goto end;
    }

    if (exportsm2keywithevlp) {
        peer = load_pubkey(peerkey_file, FORMAT_PEM, 0, NULL, NULL, "peer key");
        if (peer == NULL) {
            sdf_msg("Failed to read peer public key: peerkey=%s", peerkey_file);
            goto end;
        }

        if (!TSAPI_ExportSM2KeyWithEvlp(index, sign, user, password, peer, &priv,
                                        &privlen, &pub, &publen, &outevlp,
                                        &outevlplen)) {
            sdf_fail("Failed to export SM2 %s key with digital envelope: index=%d peerkey=%s keyout=%s dekout=%s",
                     sdf_key_type_name(sign), index, peerkey_file,
                     outkeyfile, outdekfile);
            goto end;
        }

        if (BIO_write(outkey, pub, publen) != (int)publen
            || BIO_write(outkey, priv, privlen) != (int)privlen) {
            sdf_msg("Failed to write SM2 envelope key data: keyout=%s public=%zu private=%zu",
                    outkeyfile, publen, privlen);
            goto end;
        }

        outdek = bio_open_default(outdekfile, 'w', FORMAT_BINARY);
        if (outdek == NULL) {
            sdf_msg("Failed to open digital envelope output: dekout=%s", outdekfile);
            goto end;
        }

        if (BIO_write(outdek, outevlp, outevlplen) != (int)outevlplen) {
            sdf_msg("Failed to write digital envelope: dekout=%s bytes=%zu",
                    outdekfile, outevlplen);
            goto end;
        }

        BIO_printf(bio_err,
                   "Exported SM2 %s key with envelope at index %d: public=%zu bytes, private=%zu bytes, envelope=%zu bytes\n",
                   sdf_key_type_name(sign), index, publen, privlen, outevlplen);
        ret = 0;
        goto end;
    }

    if (importsm2key) {
        pkey = load_key(inkeyfile, FORMAT_PEM, 0, NULL, NULL, "key");

        if (pkey == NULL) {
            sdf_msg("Failed to read SM2 private key: inkey=%s", inkeyfile);
            goto end;
        }

        if (!TSAPI_ImportSM2Key(index, sign, user, password, pkey)) {
            sdf_fail("Failed to import SM2 %s key: inkey=%s logical_index=%d device_index=%d user=%s",
                     sdf_key_type_name(sign), inkeyfile, logical_index, index, user);
            goto end;
        }

        BIO_printf(bio_err, "Imported SM2 %s key to logical index %d (device index %d), bits=%d\n",
                   sdf_key_type_name(sign), logical_index, index, sdf_pkey_bits(pkey));
        ret = 0;
        goto end;
    }

    if (importrsakey) {
        pkey = load_key(inkeyfile, FORMAT_PEM, 0, NULL, NULL, "key");

        if (pkey == NULL) {
            sdf_msg("Failed to read RSA private key: inkey=%s", inkeyfile);
            goto end;
        }

        if (!TSAPI_ImportRSAKey(index, sign, user, password, pkey)) {
            sdf_fail("Failed to import RSA %s key: inkey=%s logical_index=%d device_index=%d bits=%d user=%s",
                     sdf_key_type_name(sign), inkeyfile, logical_index, index,
                     sdf_pkey_bits(pkey), user);
            goto end;
        }

        BIO_printf(bio_err, "Imported RSA %s key to logical index %d (device index %d), bits=%d\n",
                   sdf_key_type_name(sign), logical_index, index, sdf_pkey_bits(pkey));
        ret = 0;
        goto end;
    }

    if (inkeyfile) {
        key_bio = BIO_new(BIO_s_file());
        if (key_bio == NULL) {
            sdf_msg("Failed to create key input BIO: inkey=%s", inkeyfile);
            goto end;
        }

        if (BIO_read_filename(key_bio, inkeyfile) <= 0) {
            sdf_msg("Failed to open key input file: inkey=%s", inkeyfile);
            goto end;
        }

        if (!bio_to_mem(&inkey, &keylen, 4096, key_bio)) {
            BIO_free(key_bio);
            BIO_printf(bio_err, "Error reading key\n");
            goto end;
        }
        BIO_free(key_bio);
        key_bio = NULL;
    }

    if (indekfile) {
        key_bio = BIO_new(BIO_s_file());
        if (key_bio == NULL) {
            sdf_msg("Failed to create envelope input BIO: indek=%s", indekfile);
            goto end;
        }

        if (BIO_read_filename(key_bio, indekfile) <= 0) {
            sdf_msg("Failed to open envelope input file: indek=%s", indekfile);
            goto end;
        }

        if (!bio_to_mem(&indek, &deklen, 4096, key_bio)){
            BIO_free(key_bio);
            BIO_printf(bio_err, "Error reading key\n");
            goto end;
        }
        BIO_free(key_bio);
        key_bio = NULL;
    }

    if (importsm2keywithevlp) {
        if (inkey == NULL || indek == NULL) {
            sdf_msg("Missing key or digital envelope for import: inkey=%s indek=%s",
                    inkeyfile != NULL ? inkeyfile : "(null)",
                    indekfile != NULL ? indekfile : "(null)");
            goto end;
        }

        if (!TSAPI_ImportSM2KeyWithEvlp(index, sign, user, password, inkey,
                                        keylen, indek, deklen)) {
            sdf_fail("Failed to import SM2 %s key with digital envelope: key=%s(%d bytes) envelope=%s(%d bytes) logical_index=%d device_index=%d",
                     sdf_key_type_name(sign), inkeyfile, keylen, indekfile,
                     deklen, logical_index, index);
            goto end;
        }

        BIO_printf(bio_err,
                   "Imported SM2 %s key with envelope to logical index %d (device index %d): key=%d bytes, envelope=%d bytes\n",
                   sdf_key_type_name(sign), logical_index, index, keylen, deklen);
        ret = 0;
        goto end;
    }

    if (infile) {
        in = bio_open_default(infile, 'r', FORMAT_BINARY);
        if (in == NULL) {
            sdf_msg("Failed to open input file: in=%s", infile);
            goto end;
        }

        /* Note: Only supports files less than 1GB */
        if (!bio_to_mem(&inbuf, &inbuflen, 1024 * 1024 * 1024, in)) {
            BIO_free(in);
            BIO_printf(bio_err, "Error reading input\n");
            goto end;
        }
    }

    if (outfile) {
        out = bio_open_default(outfile, 'w', FORMAT_BINARY);
        if (out == NULL) {
            sdf_msg("Failed to open output file: out=%s", outfile);
            goto end;
        }
    }

    if (encrypt || decrypt) {
        if (inbuf == NULL || out == NULL || algo == NULL) {
            BIO_printf(bio_err, "No input, output or algorithm specified\n");
            goto end;
        }

        if (OPENSSL_strcasecmp(algo, "sm2") == 0) {
            if (index < 0) {
                sdf_msg("Missing SM2 key index for %s: algorithm=%s",
                        encrypt ? "encrypt" : "decrypt", algo);
                goto end;
            }

            if (encrypt)
                outbuf = TSAPI_SM2EncryptWithISK(index, inbuf, inbuflen,
                                                 &outbuflen);
            else
                outbuf = TSAPI_SM2DecryptWithISK(index, inbuf, inbuflen,
                                                 &outbuflen);
        } else {
            if (OPENSSL_strcasecmp(algo, "sm4-ecb") == 0)
                mode = OSSL_SGD_SM4_ECB;
            else if (OPENSSL_strcasecmp(algo, "sm4-cbc") == 0)
                mode = OSSL_SGD_SM4_CBC;
            else if (OPENSSL_strcasecmp(algo, "sm4-cfb") == 0)
                mode = OSSL_SGD_SM4_CFB;
            else if (OPENSSL_strcasecmp(algo, "sm4-ofb") == 0)
                mode = OSSL_SGD_SM4_OFB;
            else {
                sdf_msg("Unknown algorithm for %s: algorithm=%s",
                        encrypt ? "encrypt" : "decrypt", algo);
                goto end;
            }

            if (hexiv) {
                iv = OPENSSL_hexstr2buf(hexiv, &ivlen);
                if (iv == NULL) {
                    sdf_msg("Failed to parse IV hex string: algorithm=%s iv=%s",
                            algo, hexiv);
                    goto end;
                }
                if (ivlen != 16) {
                    sdf_msg("Invalid SM4 IV length: algorithm=%s ivlen=%ld expected=16",
                            algo, ivlen);
                    goto end;
                }
            }

            if (OPENSSL_strcasecmp(isktype, "sm2") == 0) {
                if (encrypt) {
                    if ((outbuf = TSAPI_SM4Encrypt(mode, inkey, keylen, isk, iv,
                                                   inbuf, inbuflen, &outbuflen))
                                        == NULL) {
                        sdf_msg("Failed to encrypt data: algorithm=%s in=%s bytes=%d key=%s keylen=%d isk=%d isktype=%s",
                                algo, infile, inbuflen, inkeyfile, keylen, isk,
                                isktype);
                        goto end;
                    }
                } else {
                    if ((outbuf = TSAPI_SM4Decrypt(mode, inkey, keylen, isk, iv,
                                                   inbuf, inbuflen, &outbuflen))
                                        == NULL) {
                        sdf_msg("Failed to decrypt data: algorithm=%s in=%s bytes=%d key=%s keylen=%d isk=%d isktype=%s",
                                algo, infile, inbuflen, inkeyfile, keylen, isk,
                                isktype);
                        goto end;
                    }
                }
            } else {
                sdf_msg("Unknown ISK type: algorithm=%s isktype=%s", algo, isktype);
                goto end;
            }
        }

        if (BIO_write(out, outbuf, outbuflen) != (int)outbuflen) {
            sdf_msg("Failed to write %s output: out=%s bytes=%zu algorithm=%s",
                    encrypt ? "encrypt" : "decrypt", outfile, outbuflen, algo);
            goto end;
        }

        BIO_printf(bio_err, "%s %zu bytes with %s, wrote %zu bytes to %s\n",
                   encrypt ? "Encrypted" : "Decrypted", (size_t)inbuflen,
                   algo, outbuflen, outfile);
        ret = 0;
        goto end;
    }

    ret = 0;
end:
    OPENSSL_free(iv);
    OPENSSL_free(inbuf);
    OPENSSL_free(outbuf);
    BIO_free(in);
    BIO_free(out);
    OPENSSL_free(inkey);
    BIO_free(outdek);
    BIO_free(key_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer);
    BIO_free(outkey);
    OPENSSL_free(priv);
    OPENSSL_free(pub);
    OPENSSL_free(outevlp);
    NCONF_free(conf);
    return ret;
}
